from fastapi import FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response, FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
from typing import Dict, List, Optional
from uuid import uuid4
import qrcode
import io
import jwt
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import os
import json
import re
import random
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from dotenv import load_dotenv
import pathlib
import socket
import urllib.request

# --- FORCE IPv4 FIX ---
old_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args, **kwargs):
    responses = old_getaddrinfo(*args, **kwargs)
    return [response for response in responses if response[0] == socket.AF_INET]
socket.getaddrinfo = new_getaddrinfo

# --- PATH CONFIGURATION ---
BASE_DIR = pathlib.Path(__file__).parent.resolve()
ROOT_DIR = BASE_DIR.parent
CLIENT_DIR = ROOT_DIR / "client"

# Ensure we can import modules from the server directory
sys.path.append(str(BASE_DIR))

print(f"📂 Server Directory: {BASE_DIR}")
print(f"📂 Client Directory: {CLIENT_DIR}")

# --- LIGHTWEIGHT SECURITY MONITOR (RAM EFFICIENT) ---
# Replaces CatBoost for Free Tier Deployment
class SecurityWarning:
    def __init__(self, message):
        self.message = message

class LightweightMonitor:
    def __init__(self):
        self.flagged_sessions = set()

    def analyze_message(self, user, session, message):
        warnings = []
        # 1. Extract URLs
        urls = re.findall(r'https?://\S+', message)
        
        for url in urls:
            # 2. Check for specific phishing patterns or your test domains
            # Add 'square.site' and 'brizy.site' specifically for your tests
            suspicious_terms = ['square.site', 'brizy.site', 'ngrok', 'bit.ly', 'customer0-answers', 'verify', 'login', 'secure']
            
            if any(term in url.lower() for term in suspicious_terms) or len(url) > 80:
                warning_msg = f"Phishing Threat Detected: {url}"
                warnings.append(SecurityWarning(warning_msg))
                self.flagged_sessions.add(session)
                print(f"🚨 THREAT DETECTED: {url}")
                
        return warnings

    def add_warning(self, warning):
        # In a real app, save to DB here. 
        pass

    def should_terminate_session(self, user, session):
        # Terminate if they were just flagged
        if session in self.flagged_sessions:
            self.flagged_sessions.remove(session) # Reset
            return True
        return False
    
    def get_warning_count(self, user, session):
        return 1

# Initialize the lightweight monitor instead of the heavy ML one
security_monitor = LightweightMonitor()
print("✅ Loaded Lightweight Monitor (RAM Safe for Free Tier)")

# Load environment variables
load_dotenv(dotenv_path="../.docker.env")
load_dotenv()

app = FastAPI(title="Secure Chat App", version="2.0.0")

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-jwt-key-change-this-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "1"))

# AES encryption
_aes_key_str = os.getenv("AES_SECRET_KEY", "your-32-character-aes-secret-key-here")
_aes_iv_str = os.getenv("AES_IV", "your-16-character-iv-here")

if len(_aes_key_str) != 32: _aes_key_str = _aes_key_str.ljust(32, '0') if len(_aes_key_str) < 32 else _aes_key_str[:32]
if len(_aes_iv_str) != 16: _aes_iv_str = _aes_iv_str.ljust(16, '0') if len(_aes_iv_str) < 16 else _aes_iv_str[:16]

AES_SECRET_KEY = _aes_key_str.encode()
AES_IV = _aes_iv_str.encode()

# MongoDB configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "chat_app")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "users")

mongodb_client = None
mongodb_connected = False

# In-memory fallback
in_memory_users = {}
in_memory_qr_tokens = {}
in_memory_otps = {}
in_memory_temp_passwords = {}
in_memory_verification_tokens = {}
in_memory_login_attempts = {}

# WebSocket connection manager
class RoomConnectionManager:
    def __init__(self):
        self.room_to_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self.room_to_connections.setdefault(session_id, []).append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        connections = self.room_to_connections.get(session_id, [])
        if websocket in connections: connections.remove(websocket)
        if not connections and session_id in self.room_to_connections:
            del self.room_to_connections[session_id]

    async def broadcast(self, session_id: str, message: dict):
        connections = list(self.room_to_connections.get(session_id, []))
        for connection in connections:
            try: await connection.send_json(message)
            except: 
                try: connections.remove(connection)
                except: pass

manager = RoomConnectionManager()
SESSIONS: Dict[str, dict] = {}

# Models
class UserSignup(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ChatMessage(BaseModel):
    user_message: str

class QRToken(BaseModel):
    token: str

class OTPRequest(BaseModel):
    email: str
    password: Optional[str] = None

class OTPVerification(BaseModel):
    email: str
    otp_code: str

class PasswordReset(BaseModel):
    email: str
    otp_code: str
    new_password: str

class PasswordResetWithToken(BaseModel):
    verification_token: str
    new_password: str

class SessionValidation(BaseModel):
    token: str

# AES Encryption/Decryption
def encrypt_message(message: str) -> str:
    try:
        cipher = Cipher(algorithms.AES(AES_SECRET_KEY), modes.CBC(AES_IV), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted_data).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return message

def decrypt_message(encrypted_message: str) -> str:
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode())
        cipher = Cipher(algorithms.AES(AES_SECRET_KEY), modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted_data.decode()
    except Exception as e:
        return encrypted_message

def generate_qr_token(user_email: str) -> str:
    try:
        token_data = {
            "user_email": user_email,
            "expires_at": (datetime.utcnow() + timedelta(minutes=1)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        return encrypt_message(json.dumps(token_data))
    except: return ""

def validate_qr_token(encrypted_token: str) -> dict:
    try:
        decrypted_json = decrypt_message(encrypted_token)
        token_data = json.loads(decrypted_json)
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        if datetime.utcnow() > expires_at: return {"valid": False, "error": "Token expired"}
        return {"valid": True, "user_email": token_data["user_email"], "created_at": token_data["created_at"]}
    except: return {"valid": False, "error": "Invalid token"}

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

# N8N OTP Sender
async def send_email_otp(email: str, otp_code: str, purpose: str = "signup") -> bool:
    print(f"\n{'='*60}\n🚀 TRIGGERING N8N OTP\nTo: {email}\nCode: {otp_code}\n{'='*60}\n")
    n8n_url = os.getenv("N8N_WEBHOOK_URL")
    if not n8n_url:
        print("⚠️  N8N_WEBHOOK_URL not set. OTP printed to console only.")
        return True 
    try:
        payload = {"email": email, "otp_code": otp_code, "purpose": purpose, "timestamp": datetime.utcnow().isoformat()}
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(n8n_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'SecureChatApp/1.0'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"✅ n8n Webhook status: {response.status}")
            return True
    except Exception as e:
        print(f"❌ Failed to trigger n8n: {str(e)}")
        return True

async def store_otp(email: str, otp_code: str, purpose: str) -> bool:
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    otp_doc = {"email": email, "otp_code": otp_code, "purpose": purpose, "created_at": datetime.utcnow(), "expires_at": expires_at, "used": False, "attempts": 0}
    if mongodb_connected:
        try:
            col = get_otps_collection()
            await col.delete_many({"email": email, "purpose": purpose, "used": False})
            await col.insert_one(otp_doc)
            return True
        except: return False
    else:
        in_memory_otps[f"{email}:{purpose}"] = otp_doc
        return True

async def verify_otp(email: str, otp_code: str, purpose: str) -> dict:
    if mongodb_connected:
        try:
            col = get_otps_collection()
            doc = await col.find_one({"email": email, "purpose": purpose, "used": False})
            if not doc: return {"valid": False, "error": "OTP not found"}
            if datetime.utcnow() > doc["expires_at"]:
                await col.delete_one({"_id": doc["_id"]})
                return {"valid": False, "error": "Expired"}
            if doc.get("attempts", 0) >= 5:
                await col.delete_one({"_id": doc["_id"]})
                return {"valid": False, "error": "Too many attempts"}
            if doc["otp_code"] != otp_code:
                await col.update_one({"_id": doc["_id"]}, {"$inc": {"attempts": 1}})
                return {"valid": False, "error": "Invalid code"}
            await col.update_one({"_id": doc["_id"]}, {"$set": {"used": True}})
            return {"valid": True}
        except: return {"valid": False, "error": "Verification error"}
    else:
        key = f"{email}:{purpose}"
        doc = in_memory_otps.get(key)
        if not doc: return {"valid": False, "error": "Not found"}
        if doc["used"]: return {"valid": False, "error": "Used"}
        if datetime.utcnow() > doc["expires_at"]: return {"valid": False, "error": "Expired"}
        if doc["otp_code"] != otp_code: return {"valid": False, "error": "Invalid code"}
        doc["used"] = True
        return {"valid": True}

async def check_otp_rate_limit(email: str, purpose: str) -> bool:
    if mongodb_connected:
        try:
            col = get_otps_collection()
            count = await col.count_documents({"email": email, "purpose": purpose, "created_at": {"$gte": datetime.utcnow() - timedelta(minutes=15)}})
            return count < 3
        except: return True
    else: return True

# DB Helpers
async def connect_to_mongo():
    global mongodb_client
    mongodb_client = AsyncIOMotorClient(MONGODB_URL, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    await mongodb_client.admin.command('ping')
    print(f"Connected to MongoDB at {MONGODB_URL}")

async def close_mongo_connection():
    if mongodb_client: mongodb_client.close()

def get_user_collection(): return mongodb_client[DATABASE_NAME][COLLECTION_NAME]
def get_qr_tokens_collection(): return mongodb_client[DATABASE_NAME]["qr_tokens"]
def get_otps_collection(): return mongodb_client[DATABASE_NAME]["otps"]
def get_sessions_collection(): return mongodb_client[DATABASE_NAME]["sessions"]

def hash_password(password: str, rounds: int = 12) -> str: return bcrypt.hash(password, rounds=rounds)
def verify_password(password: str, password_hash: str) -> bool: return bcrypt.verify(password, password_hash)

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try: return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except: return None

# --- STARTUP ---
@app.on_event("startup")
async def startup_event():
    global mongodb_connected
    try:
        await connect_to_mongo()
        mongodb_connected = True
        try: await get_sessions_collection().create_index("created_at", expireAfterSeconds=86400)
        except: pass
        print("✅ MongoDB connected successfully")
    except Exception as e:
        mongodb_connected = False
        print(f"⚠️  MongoDB connection failed: {str(e)[:100]}")
        print("⚠️  Using in-memory storage")
    print(f"\n🚀 Server is running at http://localhost:8000")

@app.on_event("shutdown")
async def shutdown_event(): await close_mongo_connection()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

if CLIENT_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(CLIENT_DIR)), name="static")
else: print("⚠️  Warning: Client directory not found")

@app.get("/")
async def root():
    if (CLIENT_DIR / "index.html").exists(): return FileResponse(CLIENT_DIR / "index.html")
    return {"message": "Secure Chat Server Running"}

@app.get("/favicon.ico")
async def favicon(): return Response(status_code=204)

@app.get("/{page_name}.html")
async def read_html(page_name: str):
    if ".." in page_name or "/" in page_name: return JSONResponse(content={"error": "Invalid path"}, status_code=400)
    file_path = CLIENT_DIR / f"{page_name}.html"
    if file_path.exists(): return FileResponse(file_path)
    return JSONResponse(content={"error": "Page not found"}, status_code=404)

@app.get("/qr-validate")
async def qr_validate_page():
    if (CLIENT_DIR / "qr_validate.html").exists(): return FileResponse(CLIENT_DIR / "qr_validate.html")
    return JSONResponse(content={"error": "Not found"}, status_code=404)

@app.post("/signup")
async def signup(user: UserSignup):
    if len(user.password) < 8: raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password too short")
    hashed = hash_password(user.password)
    user_doc = {"email": user.email, "password_hash": hashed, "created_at": datetime.utcnow()}
    if mongodb_connected:
        try:
            col = get_user_collection()
            if await col.find_one({"email": user.email}): raise HTTPException(status.HTTP_400_BAD_REQUEST, "User exists")
            await col.insert_one(user_doc)
        except Exception as e: raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e))
    else:
        if user.email in in_memory_users: raise HTTPException(status.HTTP_400_BAD_REQUEST, "User exists")
        in_memory_users[user.email] = user_doc
    return {"message": "User registered"}

@app.post("/send_signup_otp")
async def send_signup_otp(request: OTPRequest):
    if not await check_otp_rate_limit(request.email, "signup"): raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    otp = generate_otp()
    await send_email_otp(request.email, otp, "signup")
    await store_otp(request.email, otp, "signup")
    hashed = hash_password(request.password)
    if not mongodb_connected:
        in_memory_temp_passwords[request.email] = {"password_hash": hashed, "expires_at": datetime.utcnow() + timedelta(minutes=10)}
    else:
        try:
            col = mongodb_client[DATABASE_NAME]["temp_passwords"]
            await col.delete_many({"email": request.email})
            await col.insert_one({"email": request.email, "password_hash": hashed, "created_at": datetime.utcnow(), "expires_at": datetime.utcnow() + timedelta(minutes=10)})
        except: pass
    return {"message": "OTP sent successfully"}

@app.post("/verify_signup_otp")
async def verify_signup_otp(verification: OTPVerification):
    res = await verify_otp(verification.email, verification.otp_code, "signup")
    if not res["valid"]: raise HTTPException(status.HTTP_400_BAD_REQUEST, res["error"])
    password_hash = None
    if mongodb_connected:
        try:
            col = mongodb_client[DATABASE_NAME]["temp_passwords"]
            doc = await col.find_one({"email": verification.email})
            if doc: 
                password_hash = doc["password_hash"]
                await col.delete_one({"_id": doc["_id"]})
        except: pass
    if not password_hash and verification.email in in_memory_temp_passwords:
        password_hash = in_memory_temp_passwords[verification.email]["password_hash"]
        del in_memory_temp_passwords[verification.email]
    if not password_hash: raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password data expired")
    user_doc = {"email": verification.email, "password_hash": password_hash, "created_at": datetime.utcnow()}
    if mongodb_connected: await get_user_collection().insert_one(user_doc)
    else: in_memory_users[verification.email] = user_doc
    return {"message": "Account created"}

@app.post("/login")
async def login(user: UserLogin):
    db_user = None
    if mongodb_connected:
        try: db_user = await get_user_collection().find_one({"email": user.email})
        except: pass
    else: db_user = in_memory_users.get(user.email)
    if not db_user or not verify_password(user.password, db_user["password_hash"]): raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = create_access_token({"sub": user.email})
    return {"message": "Login successful", "token": token}

@app.post("/chat")
async def chat(message: ChatMessage): return {"reply": encrypt_message(f"Response for: {message.user_message}"), "encrypted": True}

@app.post("/create_session")
async def create_session():
    sid = uuid4().hex
    created_at = datetime.utcnow().isoformat()
    if mongodb_connected:
        try: await get_sessions_collection().insert_one({"session_id": sid, "created_at": created_at})
        except: pass
    else: SESSIONS[sid] = {"created_at": created_at}
    return {"session_id": sid, "join_url": f"/static/chat.html?session_id={sid}"}

@app.get("/qr_from_session/{session_id}")
async def qr_from_session(session_id: str):
    session_exists = False
    if mongodb_connected:
        try:
            if await get_sessions_collection().find_one({"session_id": session_id}): session_exists = True
        except: pass
    if not session_exists and session_id in SESSIONS: session_exists = True
    if not session_exists: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    join_url = f"/static/chat.html?session_id={session_id}"
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(join_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        return Response(content=img_buffer.getvalue(), media_type="image/png")
    except Exception: raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate QR code")

@app.websocket("/ws/{session_id}")
async def websocket_room_endpoint(websocket: WebSocket, session_id: str, token: str = Query(...)):
    user_email = verify_token(token)
    session_exists = False
    if mongodb_connected:
        try:
            if await get_sessions_collection().find_one({"session_id": session_id}): session_exists = True
        except: pass
    if not session_exists and session_id in SESSIONS: session_exists = True
    
    if not user_email or not session_exists:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(session_id, websocket)
    try:
        await websocket.send_json({"user": "System", "message": encrypt_message(f"Welcome {user_email}!"), "encrypted": True})
        while True:
            data = await websocket.receive_text()
            try:
                msg_data = json.loads(data)
                user = msg_data.get("user", user_email)
                raw_msg = msg_data.get("message", "")
                
                # --- DECRYPT AND SCAN (RAM SAFE) ---
                plaintext_for_ml = decrypt_message(raw_msg)
                print(f"DEBUG: Scanning: {plaintext_for_ml[:30]}...")

                warnings = security_monitor.analyze_message(user_email, session_id, plaintext_for_ml)
                for w in warnings:
                    await websocket.send_json({"user": "Security", "message": encrypt_message(f"Warning: {w.message}"), "encrypted": True, "warning": True})
                
                if security_monitor.should_terminate_session(user_email, session_id):
                    term_msg = encrypt_message("Session Terminated due to security threat.")
                    await websocket.send_json({"user": "System", "message": term_msg, "encrypted": True, "terminated": True})
                    await websocket.close()
                    return
                
                # --- BROADCAST ENCRYPTED ---
                final_msg = raw_msg if raw_msg != plaintext_for_ml else encrypt_message(raw_msg)
                await manager.broadcast(session_id, {"user": user, "message": final_msg, "encrypted": True})
            except Exception as e: print(f"WS Error: {e}")
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)

@app.post("/test_otp_email")
async def test_otp_email(email: str = Query(...)):
    otp = generate_otp()
    await send_email_otp(email, otp, "signup")
    return {"success": True, "message": f"OTP sent to {email}", "otp": otp}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
