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
# This monkey-patches socket.getaddrinfo to ignore IPv6, fixing the Render "Network unreachable" error
old_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args, **kwargs):
    responses = old_getaddrinfo(*args, **kwargs)
    return [response for response in responses if response[0] == socket.AF_INET]
socket.getaddrinfo = new_getaddrinfo

# --- PATH CONFIGURATION ---
BASE_DIR = pathlib.Path(__file__).parent.resolve() # /app/server
ROOT_DIR = BASE_DIR.parent                         # /app
CLIENT_DIR = ROOT_DIR / "client"                   # /app/client

# Ensure we can import modules from the server directory
sys.path.append(str(BASE_DIR))

print(f"📂 Server Directory: {BASE_DIR}")
print(f"📂 Client Directory: {CLIENT_DIR}")

# --- LIGHTWEIGHT SECURITY MONITOR (RAM EFFICIENT) ---
# Replaces CatBoost for Free Tier Deployment to prevent OOM crashes
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
            suspicious_terms = [
                # General Phishing Keywords
                'verify', 'login', 'secure', 'account', 'update', 'banking', 'confirm', 'wallet',
                
                # Known Phishing Hosting/Domains
                'square.site', 'brizy.site', 'ngrok', 'bit.ly', 'customer0-answers', 
                'weebly.com', '000webhostapp', 'firebaseapp', 'vercel.app',
                'duckdns.org', 'pages.dev', 'iamallama.com', 'webflow.io', 
                'abc-paczki.cloud', 'weeblysite.com', 'cloudflare-ipfs.com', 
                'r2.dev', 'wixsite.com', 'imsjuris.com', 'dynv6.net', 
                'x24hr.com', 'findoutwheretogo.com', 'ureqk.com',
                
                # Suspicious TLDs and Shorteners
                '.cfd', '.top', '.xyz', 't.co',
                
                # Docs/Presentation Phishing
                'docs.google.com', 'drive.google.com'
            ]
            
            if any(term in url.lower() for term in suspicious_terms) or len(url) > 120:
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
load_dotenv()  # This will override with .env if it exists in server directory

app = FastAPI(title="Secure Chat App", version="2.0.0")

# Security configuration from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-jwt-key-change-this-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "1"))

# AES encryption configuration
_aes_key_str = os.getenv("AES_SECRET_KEY", "your-32-character-aes-secret-key-here")
_aes_iv_str = os.getenv("AES_IV", "your-16-character-iv-here")

if len(_aes_key_str) != 32:
    if len(_aes_key_str) < 32: _aes_key_str = _aes_key_str.ljust(32, '0')
    else: _aes_key_str = _aes_key_str[:32]

if len(_aes_iv_str) != 16:
    if len(_aes_iv_str) < 16: _aes_iv_str = _aes_iv_str.ljust(16, '0')
    else: _aes_iv_str = _aes_iv_str[:16]

AES_SECRET_KEY = _aes_key_str.encode()
AES_IV = _aes_iv_str.encode()

# MongoDB configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "chat_app")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "users")

mongodb_client = None
mongodb_connected = False

# In-memory fallback storage
in_memory_users = {}
in_memory_qr_tokens = {}
in_memory_otps = {}
in_memory_temp_passwords = {}
in_memory_verification_tokens = {}
in_memory_login_attempts = {}
in_memory_chat_rate_limits = {} # New: For chat rate limiting

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
# SESSIONS dict is kept for local fallback, but MongoDB is preferred
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

# AES Encryption/Decryption functions
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
        # If decryption fails, it's likely already plaintext or invalid. Return as is.
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

# --- N8N OTP SENDER ---
async def send_email_otp(email: str, otp_code: str, purpose: str = "signup") -> bool:
    """Send OTP via n8n Webhook"""
    # Always log to console (Fail-safe)
    print(f"\n{'='*60}\n🚀 TRIGGERING N8N OTP\nTo: {email}\nCode: {otp_code}\n{'='*60}\n")
    
    n8n_url = os.getenv("N8N_WEBHOOK_URL")
    if not n8n_url:
        print("⚠️  N8N_WEBHOOK_URL not set. OTP printed to console only.")
        return True 

    try:
        payload = {"email": email, "otp_code": otp_code, "purpose": purpose, "timestamp": datetime.utcnow().isoformat()}
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            n8n_url, 
            data=data, 
            headers={'Content-Type': 'application/json', 'User-Agent': 'SecureChatApp/1.0'},
            method='POST'
        )
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
    else:
        return True

# --- NEW: CHAT RATE LIMIT CHECKER ---
def check_chat_rate_limit(email: str, limit: int = 30) -> bool:
    """
    Checks if user has sent > limit messages in the last 60 seconds.
    Uses in-memory storage for speed in the websocket loop.
    """
    now = datetime.utcnow()
    if email not in in_memory_chat_rate_limits:
        in_memory_chat_rate_limits[email] = []
    
    # Keep only timestamps from the last 60 seconds
    cutoff_time = now - timedelta(seconds=60)
    
    # Filter old timestamps
    valid_timestamps = [t for t in in_memory_chat_rate_limits[email] if t > cutoff_time]
    in_memory_chat_rate_limits[email] = valid_timestamps
    
    if len(valid_timestamps) >= limit:
        return False
    
    # Add current message timestamp
    in_memory_chat_rate_limits[email].append(now)
    return True

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
def get_sessions_collection():
    if mongodb_client is None: raise RuntimeError("MongoDB not connected")
    return mongodb_client[DATABASE_NAME]["sessions"]

def hash_password(password: str, rounds: int = 12) -> str:
    return bcrypt.hash(password, rounds=rounds)

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.verify(password, password_hash)

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except: return None

# --- STARTUP EVENT ---
@app.on_event("startup")
async def startup_event():
    global mongodb_connected
    try:
        await connect_to_mongo()
        mongodb_connected = True
        # Index for sessions
        try:
            await get_sessions_collection().create_index("created_at", expireAfterSeconds=86400)
        except: pass
        print("✅ MongoDB connected successfully")
    except Exception as e:
        mongodb_connected = False
        print(f"⚠️  MongoDB connection failed: {str(e)[:100]}")
        print("⚠️  Using in-memory storage (data will not persist)")
    
    print("\n🔐 Security features enabled:")
    print(f"   - Storage: {'MongoDB' if mongodb_connected else 'In-Memory (temporary)'}")
    
    n8n_status = '✅ Automated (n8n Webhook)' if os.getenv('N8N_WEBHOOK_URL') else '⚠️  Development Mode (console output)'
    print(f"   - OTP System: {n8n_status}")
    print(f"   - Chat Rate Limit: 30 messages/minute")
    
    print(f"\n🚀 Server is running at http://localhost:8000")

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

if CLIENT_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(CLIENT_DIR)), name="static")
else:
    print("⚠️  Warning: Client directory not found")

@app.get("/")
async def root():
    if (CLIENT_DIR / "index.html").exists(): return FileResponse(CLIENT_DIR / "index.html")
    return {"message": "Secure Chat Server Running", "security": "AES-256 + bcrypt + JWT enabled", "note": "index.html not found in client dir"}

# Favicon endpoint to prevent 404 errors
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)  # No Content - silently ignore favicon requests

# Generic HTML serving endpoint - Updated to use CLIENT_DIR
@app.get("/{page_name}.html")
async def read_html(page_name: str):
    # Security: prevent directory traversal
    if ".." in page_name or "/" in page_name:
        return JSONResponse(content={"error": "Invalid path"}, status_code=400)
    
    file_path = CLIENT_DIR / f"{page_name}.html"
    if file_path.exists():
        return FileResponse(file_path)
    return JSONResponse(content={"error": "Page not found"}, status_code=404)

# QR Validation page
@app.get("/qr-validate")
async def qr_validate_page():
    file_path = CLIENT_DIR / "qr_validate.html"
    if file_path.exists():
        return FileResponse(file_path)
    return JSONResponse(content={"error": "qr_validate.html not found"}, status_code=404)

# Signup endpoint with enhanced bcrypt security
@app.post("/signup")
async def signup(user: UserSignup):
    # Enhanced password validation
    if len(user.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    # Check for special character
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(char in special_chars for char in user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
        )
    
    # Hash password with bcrypt (using helper to handle 72-byte limit)
    hashed_password = hash_password(user.password, rounds=12)
    
    user_doc = {
        "email": user.email,
        "password_hash": hashed_password,
        "created_at": datetime.utcnow(),
        "security_level": "bcrypt-12-rounds"
    }
    
    # Use MongoDB if connected, otherwise use in-memory storage
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            
            # Check if user already exists
            existing_user = await user_collection.find_one({"email": user.email})
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists"
                )
            
            # Insert user into MongoDB
            await user_collection.insert_one(user_doc)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
    else:
        # Use in-memory storage
        if user.email in in_memory_users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )
        in_memory_users[user.email] = user_doc
    
    return {"message": "User registered successfully with enhanced security"}

# OTP Endpoints
@app.post("/send_signup_otp")
async def send_signup_otp(request: OTPRequest):
    """Send OTP for signup verification"""
    email = request.email.lower().strip()
    password = request.password
    
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required for signup"
        )
    
    # Validate password
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(char in special_chars for char in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
        )
    
    # Check if user already exists
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            existing_user = await user_collection.find_one({"email": email})
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists"
                )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
    else:
        if email in in_memory_users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )
    
    # Check rate limit
    if not await check_otp_rate_limit(email, "signup"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Please wait 15 minutes before requesting again."
        )
    
    # Generate and send OTP
    otp_code = generate_otp()
    # Calls our new N8N function
    await send_email_otp(email, otp_code, "signup")
    
    # Store OTP (also store password temporarily for signup completion)
    await store_otp(email, otp_code, "signup")
    
    # Store password temporarily in memory (will be used after OTP verification)
    if mongodb_connected:
        try:
            temp_passwords_collection = mongodb_client[DATABASE_NAME]["temp_passwords"]
            await temp_passwords_collection.delete_many({"email": email})
            await temp_passwords_collection.insert_one({
                "email": email,
                "password_hash": hash_password(password, rounds=12),
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(minutes=10)
            })
        except:
            pass  # Fallback to in-memory
    else:
        in_memory_temp_passwords[email] = {
            "password_hash": hash_password(password, rounds=12),
            "expires_at": datetime.utcnow() + timedelta(minutes=10)
        }
    
    return {
        "message": "OTP sent successfully",
        "email": email,
        "expires_in": "5 minutes"
    }

@app.post("/verify_signup_otp")
async def verify_signup_otp(verification: OTPVerification):
    """Verify OTP and complete signup"""
    email = verification.email.lower().strip()
    otp_code = verification.otp_code.strip()
    
    # Verify OTP
    result = await verify_otp(email, otp_code, "signup")
    if not result["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    # Get stored password
    password_hash = None
    if mongodb_connected:
        try:
            temp_passwords_collection = mongodb_client[DATABASE_NAME]["temp_passwords"]
            temp_doc = await temp_passwords_collection.find_one({"email": email})
            if temp_doc:
                password_hash = temp_doc["password_hash"]
                # Delete temp password
                await temp_passwords_collection.delete_one({"_id": temp_doc["_id"]})
        except:
            pass
    
    if not password_hash:
        # Try in-memory
        if email in in_memory_temp_passwords:
            temp_data = in_memory_temp_passwords[email]
            if datetime.utcnow() <= temp_data["expires_at"]:
                password_hash = temp_data["password_hash"]
            del in_memory_temp_passwords[email]
    
    if not password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password data expired. Please start signup again."
        )
    
    # Create user account
    user_doc = {
        "email": email,
        "password_hash": password_hash,
        "created_at": datetime.utcnow(),
        "security_level": "bcrypt-12-rounds",
        "email_verified": True
    }
    
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            await user_collection.insert_one(user_doc)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create account: {str(e)}"
            )
    else:
        in_memory_users[email] = user_doc
    
    return {
        "message": "Account created successfully. Please login.",
        "email": email
    }

@app.post("/send_forgot_otp")
async def send_forgot_otp(request: OTPRequest):
    """Send OTP for password reset"""
    email = request.email.lower().strip()
    
    # Check if user exists
    user_exists = False
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            user = await user_collection.find_one({"email": email})
            user_exists = user is not None
        except:
            pass
    else:
        user_exists = email in in_memory_users
    
    # For security, don't reveal if user exists or not
    # Always send OTP (but only verify if user exists)
    
    # Check rate limit
    if not await check_otp_rate_limit(email, "forgot_password"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Please wait 15 minutes before requesting again."
        )
    
    # Generate and send OTP
    otp_code = generate_otp()
    await send_email_otp(email, otp_code, "forgot_password")
    
    # Store OTP
    await store_otp(email, otp_code, "forgot_password")
    
    return {
        "message": "If an account exists with this email, an OTP has been sent.",
        "email": email,
        "expires_in": "5 minutes"
    }

async def generate_verification_token(email: str) -> str:
    """Generate a secure verification token for password reset"""
    token = uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=15)  # 15 minutes validity
    
    token_data = {
        "email": email,
        "expires_at": expires_at,
        "created_at": datetime.utcnow()
    }
    
    if mongodb_connected:
        try:
            tokens_collection = mongodb_client[DATABASE_NAME]["verification_tokens"]
            await tokens_collection.delete_many({"email": email})  # Remove old tokens
            await tokens_collection.insert_one({
                "token": token,
                "email": email,
                "expires_at": expires_at,
                "created_at": datetime.utcnow()
            })
        except:
            pass  # Fallback to in-memory
    
    in_memory_verification_tokens[token] = token_data
    return token

async def verify_verification_token(token: str) -> dict:
    """Verify a password reset token"""
    if mongodb_connected:
        try:
            tokens_collection = mongodb_client[DATABASE_NAME]["verification_tokens"]
            token_doc = await tokens_collection.find_one({"token": token})
            if not token_doc:
                return {"valid": False, "error": "Invalid verification token"}
            
            expires_at = token_doc["expires_at"]
            if datetime.utcnow() > expires_at:
                await tokens_collection.delete_one({"token": token})
                return {"valid": False, "error": "Verification token has expired"}
            
            return {"valid": True, "email": token_doc["email"]}
        except:
            pass
    
    # In-memory check
    if token not in in_memory_verification_tokens:
        return {"valid": False, "error": "Invalid verification token"}
    
    token_data = in_memory_verification_tokens[token]
    if datetime.utcnow() > token_data["expires_at"]:
        del in_memory_verification_tokens[token]
        return {"valid": False, "error": "Verification token has expired"}
    
    return {"valid": True, "email": token_data["email"]}

@app.post("/verify_forgot_otp")
async def verify_forgot_otp(verification: OTPVerification):
    """Verify OTP for password reset and return verification token"""
    email = verification.email.lower().strip()
    otp_code = verification.otp_code.strip()
    
    # Verify OTP
    result = await verify_otp(email, otp_code, "forgot_password")
    if not result["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    # Check if user exists
    user_exists = False
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            user = await user_collection.find_one({"email": email})
            user_exists = user is not None
        except:
            pass
    else:
        user_exists = email in in_memory_users
    
    if not user_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Generate verification token (more secure than storing OTP in localStorage)
    verification_token = await generate_verification_token(email)
    
    return {
        "message": "OTP verified successfully. You can now reset your password.",
        "email": email,
        "verification_token": verification_token,
        "expires_in": "15 minutes"
    }

@app.post("/reset_password")
async def reset_password(reset: PasswordReset):
    """Reset password after OTP verification (legacy - accepts OTP)"""
    email = reset.email.lower().strip()
    otp_code = reset.otp_code.strip()
    new_password = reset.new_password
    
    # Verify OTP again (for extra security)
    result = await verify_otp(email, otp_code, "forgot_password")
    if not result["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    # Continue with password reset...
    return await _reset_password_internal(email, new_password)

@app.post("/reset_password_with_token")
async def reset_password_with_token(reset: PasswordResetWithToken):
    """Reset password using verification token (more secure)"""
    verification_token = reset.verification_token.strip()
    new_password = reset.new_password
    
    # Verify token
    token_result = await verify_verification_token(verification_token)
    if not token_result["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=token_result["error"]
        )
    
    email = token_result["email"]
    
    # Delete used token
    if mongodb_connected:
        try:
            tokens_collection = mongodb_client[DATABASE_NAME]["verification_tokens"]
            await tokens_collection.delete_one({"token": verification_token})
        except:
            pass
    
    if verification_token in in_memory_verification_tokens:
        del in_memory_verification_tokens[verification_token]
    
    return await _reset_password_internal(email, new_password)

async def _reset_password_internal(email: str, new_password: str):
    """Internal function to reset password"""
    # Validate new password
    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(char in special_chars for char in new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
        )
    
    # Hash new password (using helper to handle 72-byte limit)
    hashed_password = hash_password(new_password, rounds=12)
    
    # Update password
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            result = await user_collection.update_one(
                {"email": email},
                {"$set": {
                    "password_hash": hashed_password,
                    "password_reset_at": datetime.utcnow()
                }}
            )
            if result.matched_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to reset password: {str(e)}"
            )
    else:
        if email not in in_memory_users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        in_memory_users[email]["password_hash"] = hashed_password
        in_memory_users[email]["password_reset_at"] = datetime.utcnow()
    
    return {
        "message": "Password reset successfully. Please login with your new password.",
        "email": email
    }

# Login rate limiting check
async def check_login_rate_limit(email: str) -> dict:
    """Check login rate limit (max 5 attempts per 15 minutes)"""
    key = f"login:{email}"
    now = datetime.utcnow()
    fifteen_min_ago = now - timedelta(minutes=15)
    
    if key not in in_memory_login_attempts:
        in_memory_login_attempts[key] = []
    
    # Clean old attempts
    in_memory_login_attempts[key] = [
        attempt for attempt in in_memory_login_attempts[key]
        if attempt > fifteen_min_ago
    ]
    
    attempts = in_memory_login_attempts[key]
    if len(attempts) >= 5:
        # Calculate time until next attempt allowed
        oldest_attempt = min(attempts)
        next_allowed = oldest_attempt + timedelta(minutes=15)
        wait_time = (next_allowed - now).total_seconds()
        return {
            "allowed": False,
            "wait_seconds": max(0, int(wait_time)),
            "message": f"Too many login attempts. Please wait {int(wait_time/60)} minutes."
        }
    
    return {"allowed": True}

def record_failed_login(email: str):
    """Record a failed login attempt"""
    key = f"login:{email}"
    if key not in in_memory_login_attempts:
        in_memory_login_attempts[key] = []
    in_memory_login_attempts[key].append(datetime.utcnow())

def clear_login_attempts(email: str):
    """Clear login attempts after successful login"""
    key = f"login:{email}"
    if key in in_memory_login_attempts:
        del in_memory_login_attempts[key]

# Login endpoint with bcrypt verification and rate limiting
@app.post("/login")
async def login(user: UserLogin):
    email = user.email.lower().strip()
    
    # Check rate limit
    rate_limit = await check_login_rate_limit(email)
    if not rate_limit["allowed"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_limit["message"]
        )
    
    db_user = None
    
    # Use MongoDB if connected, otherwise use in-memory storage
    if mongodb_connected:
        try:
            user_collection = get_user_collection()
            db_user = await user_collection.find_one({"email": email})
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
    else:
        # Use in-memory storage
        db_user = in_memory_users.get(email)
    
    if not db_user:
        record_failed_login(email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password with bcrypt (using helper to handle 72-byte limit)
    if not verify_password(user.password, db_user["password_hash"]):
        record_failed_login(email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Clear failed login attempts on success
    clear_login_attempts(email)
    
    # Generate JWT token
    token_data = {"sub": email}
    access_token = create_access_token(data=token_data)
    
    return {
        "message": "Login successful",
        "token": access_token,
        "security_info": "Password verified with bcrypt, JWT token generated"
    }

# Enhanced chat endpoint with encryption
@app.post("/chat")
async def chat(message: ChatMessage):
    # Encrypt the response message
    response_text = f"This is a secure response for: {message.user_message}"
    encrypted_response = encrypt_message(response_text)
    
    return {
        "reply": encrypted_response,
        "encrypted": True,
        "security_note": "Response encrypted with AES-256-CBC"
    }

# Secure QR Code endpoint with encrypted tokens
@app.get("/generate_qr")
async def generate_qrcode(user_email: str = Query(..., description="User email for QR code")):
    try:
        # Generate encrypted token
        encrypted_token = generate_qr_token(user_email)
        if not encrypted_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate QR token"
            )
        
        # Store token in MongoDB with expiry
        qr_tokens_collection = get_qr_tokens_collection() if mongodb_connected else None
        
        token_doc = {
            "token": encrypted_token,
            "user_email": user_email,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=1),
            "used": False
        }
        
        if qr_tokens_collection:
            await qr_tokens_collection.insert_one(token_doc)
        
        # Generate QR code with encrypted token (not raw email)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(encrypted_token)  # Encrypted token instead of raw email
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return Response(content=img_buffer.getvalue(), media_type="image/png")
        
    except Exception as e:
        print(f"QR generation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        )

# QR Token validation endpoint
@app.post("/validate_qr")
async def validate_qr_token_endpoint(qr_token: QRToken):
    try:
        # Validate the encrypted token
        validation_result = validate_qr_token(qr_token.token)
        
        if not validation_result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=validation_result["error"]
            )
        
        # Check if token exists in MongoDB and hasn't been used
        if mongodb_connected:
            qr_tokens_collection = get_qr_tokens_collection()
            token_doc = await qr_tokens_collection.find_one({
                "token": qr_token.token,
                "used": False
            })
            
            if not token_doc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token not found or already used"
                )
            
            # Mark token as used
            await qr_tokens_collection.update_one(
                {"token": qr_token.token},
                {"$set": {"used": True, "used_at": datetime.utcnow()}}
            )
        
        # Generate JWT token for the user
        user_email = validation_result["user_email"]
        token_data = {"sub": user_email}
        access_token = create_access_token(data=token_data)
        
        return {
            "message": "QR token validated successfully",
            "token": access_token,
            "user_email": user_email,
            "security_info": "QR token validated, JWT generated, token marked as used"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"QR validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate QR token"
        )

# New: Create private session and room-based WebSocket
class CreateSessionResponse(BaseModel):
    session_id: str
    join_url: str

@app.post("/create_session", response_model=CreateSessionResponse)
async def create_session():
    session_id = uuid4().hex
    created_at = datetime.utcnow().isoformat()
    
    # Store session in MongoDB for persistent room access
    if mongodb_connected:
        try:
            await get_sessions_collection().insert_one({"session_id": session_id, "created_at": created_at})
        except: pass
    else:
        SESSIONS[session_id] = {"created_at": created_at}
        
    return {"session_id": session_id, "join_url": f"/static/chat.html?session_id={session_id}"}

@app.get("/qr_from_session/{session_id}")
async def qr_from_session(session_id: str):
    # Validate session exists (DB Fallback)
    session_exists = False
    if mongodb_connected:
        try:
            if await get_sessions_collection().find_one({"session_id": session_id}):
                session_exists = True
        except: pass
    
    if not session_exists and session_id in SESSIONS:
        session_exists = True
        
    if not session_exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    # Encode a full join URL for sharing (client will request relative path)
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
    except Exception:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate QR code")

@app.websocket("/ws/{session_id}")
async def websocket_room_endpoint(websocket: WebSocket, session_id: str, token: str = Query(...)):
    user_email = verify_token(token)
    
    # Validate session (DB Fallback)
    session_exists = False
    if mongodb_connected:
        try:
            if await get_sessions_collection().find_one({"session_id": session_id}):
                session_exists = True
        except: pass
    
    if not session_exists and session_id in SESSIONS:
        session_exists = True

    if not user_email:
        print(f"WS REJECT: Invalid Token for {session_id}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    if not session_exists:
        print(f"WS REJECT: Session Not Found {session_id}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(session_id, websocket)
    try:
        # Send welcome message (Unencrypted for readability)
        await websocket.send_json({"user": "System", "message": f"Welcome {user_email}!", "encrypted": False})
        
        while True:
            data = await websocket.receive_text()
            try:
                msg_data = json.loads(data)
                user = msg_data.get("user", user_email)
                raw_msg = msg_data.get("message", "")
                
                # --- 0. RATE LIMIT CHECK ---
                if not check_chat_rate_limit(user_email, limit=30):
                     await websocket.send_json({
                        "user": "System",
                        "message": "Rate limit exceeded. You are sending messages too fast (Max 30/min).",
                        "encrypted": False,
                        "warning": True
                    })
                     continue

                # --- 1. ATTEMPT DECRYPTION (FOR ML) ---
                # We try to decrypt. If it was sent as Plaintext, decrypt returns it as-is.
                plaintext_for_ml = decrypt_message(raw_msg)
                
                print(f"DEBUG: Scanning: {plaintext_for_ml[:30]}...")

                # --- 2. SECURITY SCAN (Lightweight) ---
                if security_monitor:
                    warnings = security_monitor.analyze_message(user_email, session_id, plaintext_for_ml)
                    for w in warnings:
                        security_monitor.add_warning(w)
                        # Send warning (Plaintext so user can read it)
                        await websocket.send_json({
                            "user": "Security", 
                            "message": f"Warning: {w.message}", 
                            "encrypted": False, 
                            "warning": True
                        })
                    
                    if security_monitor.should_terminate_session(user_email, session_id):
                        term_msg = "Session Terminated due to security threat."
                        await websocket.send_json({
                            "user": "System", 
                            "message": term_msg, 
                            "encrypted": False, 
                            "terminated": True
                        })
                        await websocket.close()
                        return
                
                # --- 3. BROADCAST (READABLE) ---
                # We send the PLAINTEXT to the room so users can read it.
                # We also send the 'ciphertext' in a separate field if you want to display it for demo purposes.
                ciphertext = encrypt_message(plaintext_for_ml)
                
                response = {
                    "user": user,
                    "message": plaintext_for_ml,  # Send READABLE text
                    "ciphertext": ciphertext,     # Optional: Keep encrypted version
                    "encrypted": False,           # UI shouldn't try to decrypt this
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                await manager.broadcast(session_id, response)
            except Exception as e:
                print(f"WS Error: {e}")
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
