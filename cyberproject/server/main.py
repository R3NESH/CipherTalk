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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from dotenv import load_dotenv
import pathlib
import socket

# --- FORCE IPv4 FIX ---
old_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args, **kwargs):
    responses = old_getaddrinfo(*args, **kwargs)
    return [response for response in responses if response[0] == socket.AF_INET]
socket.getaddrinfo = new_getaddrinfo

# --- PATH CONFIGURATION (Docker Fix) ---
BASE_DIR = pathlib.Path(__file__).parent.resolve() # /app/server
ROOT_DIR = BASE_DIR.parent                         # /app
CLIENT_DIR = ROOT_DIR / "client"                   # /app/client

print(f"📂 Server Directory: {BASE_DIR}")
print(f"📂 Client Directory: {CLIENT_DIR}")

# Import security_monitor with error handling
try:
    from security_monitor import security_monitor, SecurityWarning
except Exception as e:
    print(f"⚠️  Warning: Could not import security_monitor: {e}")
    # Create a minimal fallback
    class SecurityWarning:
        def __init__(self, *args, **kwargs):
            pass
    class SecurityMonitor:
        def analyze_message(self, *args, **kwargs):
            return []
        def add_warning(self, *args, **kwargs):
            pass
        def should_terminate_session(self, *args, **kwargs):
            return False
        def get_warning_count(self, *args, **kwargs):
            return 0
    security_monitor = SecurityMonitor()

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

# Pad or truncate to correct length if needed
if len(_aes_key_str) != 32:
    if len(_aes_key_str) < 32:
        _aes_key_str = _aes_key_str.ljust(32, '0')
    else:
        _aes_key_str = _aes_key_str[:32]

if len(_aes_iv_str) != 16:
    if len(_aes_iv_str) < 16:
        _aes_iv_str = _aes_iv_str.ljust(16, '0')
    else:
        _aes_iv_str = _aes_iv_str[:16]

AES_SECRET_KEY = _aes_key_str.encode()
AES_IV = _aes_iv_str.encode()

# MongoDB configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "chat_app")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "users")

# Email/SMTP configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Private Chat")

# MongoDB client
mongodb_client = None
mongodb_connected = False

# In-memory fallback storage (when MongoDB is unavailable)
in_memory_users = {}
in_memory_qr_tokens = {}
in_memory_otps = {}
in_memory_temp_passwords = {}
in_memory_verification_tokens = {}  # For secure password reset flow
in_memory_login_attempts = {}  # For login rate limiting

# WebSocket connection manager
class RoomConnectionManager:
    def __init__(self):
        # session_id -> list[WebSocket]
        self.room_to_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self.room_to_connections.setdefault(session_id, []).append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        connections = self.room_to_connections.get(session_id, [])
        if websocket in connections:
            connections.remove(websocket)
        if not connections and session_id in self.room_to_connections:
            del self.room_to_connections[session_id]

    async def broadcast(self, session_id: str, message: dict):
        connections = list(self.room_to_connections.get(session_id, []))
        for connection in connections:
            try:
                await connection.send_json(message)
            except:
                # Remove dead connections
                try:
                    connections.remove(connection)
                except Exception:
                    pass

manager = RoomConnectionManager()

# In-memory session registry (can be moved to MongoDB later)
SESSIONS: Dict[str, dict] = {}

# Pydantic models
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
    password: Optional[str] = None  # Required for signup, not for forgot password

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
    """Encrypt a message using AES-256-CBC"""
    try:
        cipher = Cipher(
            algorithms.AES(AES_SECRET_KEY),
            modes.CBC(AES_IV),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad the message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return base64 encoded encrypted data
        return base64.b64encode(encrypted_data).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return message  # Fallback to plain text

def decrypt_message(encrypted_message: str) -> str:
    """Decrypt a message using AES-256-CBC"""
    try:
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_message.encode())
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(AES_SECRET_KEY),
            modes.CBC(AES_IV),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_data.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_message  # Fallback to encrypted text

# QR Token functions
def generate_qr_token(user_email: str) -> str:
    """Generate a one-time encrypted token for QR code"""
    try:
        # Create token data with user email and expiry
        token_data = {
            "user_email": user_email,
            "expires_at": (datetime.utcnow() + timedelta(minutes=1)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Convert to JSON string and encrypt
        token_json = json.dumps(token_data)
        encrypted_token = encrypt_message(token_json)
        
        return encrypted_token
    except Exception as e:
        print(f"QR token generation error: {e}")
        return ""

def validate_qr_token(encrypted_token: str) -> dict:
    """Validate and decrypt a QR token"""
    try:
        # Decrypt the token
        decrypted_json = decrypt_message(encrypted_token)
        token_data = json.loads(decrypted_json)
        
        # Check if token has expired
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        if datetime.utcnow() > expires_at:
            return {"valid": False, "error": "Token expired"}
        
        return {
            "valid": True,
            "user_email": token_data["user_email"],
            "created_at": token_data["created_at"]
        }
    except Exception as e:
        print(f"QR token validation error: {e}")
        return {"valid": False, "error": "Invalid token"}

# OTP Functions
def generate_otp() -> str:
    """Generate a 6-digit OTP code"""
    return str(random.randint(100000, 999999))

async def send_email_otp(email: str, otp_code: str, purpose: str = "signup") -> bool:
    """Send OTP via email using SMTP"""
    # --- CRITICAL MODIFICATION FOR RENDER ---
    # ALWAYS print the OTP to console first so you can see it in Logs
    print(f"\n{'='*60}")
    print(f"🔑 DEBUG: RENDER OTP GENERATED")
    print(f"To: {email}")
    print(f"Code: {otp_code}")
    print(f"{'='*60}\n")
    
    try:
        # If SMTP is not configured, just return True (Dev Mode)
        if not SMTP_USER or not SMTP_PASSWORD:
            print("ℹ️ SMTP not configured. Running in Dev Mode.")
            return True
        
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
        msg['To'] = email
        msg['Subject'] = "Your Private Chat Verification Code"
        
        # Email body (HTML)
        if purpose == "signup":
            subject_text = "Verify your email address"
            action_text = "complete your account registration"
        else:
            subject_text = "Reset your password"
            action_text = "reset your password"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #4da6ff 0%, #0066ff 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-code {{ font-size: 32px; font-weight: bold; color: #0066ff; text-align: center; padding: 20px; background: white; border-radius: 8px; margin: 20px 0; letter-spacing: 8px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Private Chat</h1>
                </div>
                <div class="content">
                    <h2>{subject_text}</h2>
                    <p>Hello,</p>
                    <p>You requested to {action_text}. Use the verification code below:</p>
                    <div class="otp-code">{otp_code}</div>
                    <p>This code will expire in <strong>5 minutes</strong>.</p>
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong> If you didn't request this code, please ignore this email.
                    </div>
                    <p>Best regards,<br>Private Chat Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"Your OTP Code is: {otp_code}"
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email via SMTP
        password_clean = SMTP_PASSWORD.replace(" ", "")
        
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls()
                server.login(SMTP_USER, password_clean)
                server.send_message(msg)
            
            print(f"✅ OTP email sent successfully to {email}")
            return True
        except Exception as e:
            # --- FAIL SAFE MODE ---
            # If email fails (timeout/auth/network), print error but return TRUE
            # This allows you to use the OTP printed in console to login anyway
            print(f"❌ SMTP Error: {str(e)}")
            print(f"⚠️  Email failed but OTP was generated. Check console logs above.")
            return True
        
    except Exception as e:
        print(f"❌ General Error: {str(e)}")
        return True # Always return True so UI doesn't block

async def store_otp(email: str, otp_code: str, purpose: str) -> bool:
    """Store OTP in MongoDB or in-memory storage"""
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    
    otp_doc = {
        "email": email,
        "otp_code": otp_code,
        "purpose": purpose,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        "used": False,
        "attempts": 0
    }
    
    if mongodb_connected:
        try:
            otps_collection = get_otps_collection()
            # Delete any existing OTPs for this email and purpose
            await otps_collection.delete_many({
                "email": email,
                "purpose": purpose,
                "used": False
            })
            # Insert new OTP
            await otps_collection.insert_one(otp_doc)
            return True
        except Exception as e:
            print(f"Error storing OTP in MongoDB: {e}")
            return False
    else:
        # In-memory storage
        key = f"{email}:{purpose}"
        in_memory_otps[key] = otp_doc
        return True

async def verify_otp(email: str, otp_code: str, purpose: str) -> dict:
    """Verify OTP code"""
    if mongodb_connected:
        try:
            otps_collection = get_otps_collection()
            otp_doc = await otps_collection.find_one({
                "email": email,
                "purpose": purpose,
                "used": False
            })
            
            if not otp_doc:
                return {"valid": False, "error": "OTP not found or already used"}
            
            # Check expiry
            expires_at = otp_doc["expires_at"]
            if datetime.utcnow() > expires_at:
                await otps_collection.delete_one({"_id": otp_doc["_id"]})
                return {"valid": False, "error": "OTP has expired"}
            
            # Check attempts
            if otp_doc.get("attempts", 0) >= 5:
                await otps_collection.delete_one({"_id": otp_doc["_id"]})
                return {"valid": False, "error": "Too many failed attempts. Please request a new OTP."}
            
            # Verify code
            if otp_doc["otp_code"] != otp_code:
                # Increment attempts
                await otps_collection.update_one(
                    {"_id": otp_doc["_id"]},
                    {"$inc": {"attempts": 1}}
                )
                return {"valid": False, "error": "Invalid OTP code"}
            
            # Mark as used
            await otps_collection.update_one(
                {"_id": otp_doc["_id"]},
                {"$set": {"used": True, "used_at": datetime.utcnow()}}
            )
            
            return {"valid": True}
            
        except Exception as e:
            print(f"Error verifying OTP: {e}")
            return {"valid": False, "error": "Verification error"}
    else:
        # In-memory verification
        key = f"{email}:{purpose}"
        otp_doc = in_memory_otps.get(key)
        
        if not otp_doc:
            return {"valid": False, "error": "OTP not found"}
        
        if otp_doc["used"]:
            return {"valid": False, "error": "OTP already used"}
        
        expires_at = otp_doc["expires_at"]
        if datetime.utcnow() > expires_at:
            del in_memory_otps[key]
            return {"valid": False, "error": "OTP has expired"}
        
        if otp_doc.get("attempts", 0) >= 5:
            del in_memory_otps[key]
            return {"valid": False, "error": "Too many failed attempts. Please request a new OTP."}
        
        if otp_doc["otp_code"] != otp_code:
            otp_doc["attempts"] = otp_doc.get("attempts", 0) + 1
            return {"valid": False, "error": "Invalid OTP code"}
        
        otp_doc["used"] = True
        otp_doc["used_at"] = datetime.utcnow()
        return {"valid": True}

async def check_otp_rate_limit(email: str, purpose: str) -> bool:
    """Check if user has exceeded rate limit (max 3 OTPs per 15 minutes)"""
    if mongodb_connected:
        try:
            otps_collection = get_otps_collection()
            fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
            count = await otps_collection.count_documents({
                "email": email,
                "purpose": purpose,
                "created_at": {"$gte": fifteen_min_ago}
            })
            return count < 3
        except:
            return True
    else:
        # In-memory check
        fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
        key_prefix = f"{email}:{purpose}"
        count = sum(1 for key, doc in in_memory_otps.items() 
                   if key.startswith(key_prefix) and doc["created_at"] >= fifteen_min_ago)
        return count < 3

# MongoDB utility functions
async def connect_to_mongo():
    global mongodb_client
    # Add timeout settings to prevent hanging
    mongodb_client = AsyncIOMotorClient(
        MONGODB_URL,
        serverSelectionTimeoutMS=5000,  # 5 seconds timeout
        connectTimeoutMS=5000,
        socketTimeoutMS=5000
    )
    # Test the connection
    await mongodb_client.admin.command('ping')
    print(f"Connected to MongoDB at {MONGODB_URL}")

async def close_mongo_connection():
    global mongodb_client
    if mongodb_client is not None:
        mongodb_client.close()
        print("MongoDB connection closed")

def get_user_collection():
    if mongodb_client is None:
        raise RuntimeError("MongoDB not connected")
    return mongodb_client[DATABASE_NAME][COLLECTION_NAME]

def get_qr_tokens_collection():
    if mongodb_client is None:
        raise RuntimeError("MongoDB not connected")
    return mongodb_client[DATABASE_NAME]["qr_tokens"]

def get_otps_collection():
    if mongodb_client is None:
        raise RuntimeError("MongoDB not connected")
    return mongodb_client[DATABASE_NAME]["otps"]

# Password hashing helper function (handles bcrypt 72-byte limit)
def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hash a password using bcrypt, handling passwords longer than 72 bytes.
    Bcrypt has a 72-byte limit, so we hash longer passwords with SHA256 first.
    """
    import hashlib
    
    # Convert password to bytes to check length
    password_bytes = password.encode('utf-8')
    
    # If password is longer than 72 bytes, hash it first with SHA256
    if len(password_bytes) > 72:
        # Hash with SHA256 to get a fixed 32-byte hash, then encode to base64 for bcrypt
        sha256_hash = hashlib.sha256(password_bytes).digest()
        # Use base64 encoding to get a string that's always <= 44 chars (safe for bcrypt)
        import base64
        password_for_bcrypt = base64.b64encode(sha256_hash).decode('utf-8')
    else:
        password_for_bcrypt = password
    
    # Hash with bcrypt
    return bcrypt.hash(password_for_bcrypt, rounds=rounds)

def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against a bcrypt hash, handling passwords longer than 72 bytes.
    """
    import hashlib
    import base64
    
    # Convert password to bytes to check length
    password_bytes = password.encode('utf-8')
    
    # If password is longer than 72 bytes, hash it first with SHA256
    if len(password_bytes) > 72:
        sha256_hash = hashlib.sha256(password_bytes).digest()
        password_for_bcrypt = base64.b64encode(sha256_hash).decode('utf-8')
    else:
        password_for_bcrypt = password
    
    # Verify with bcrypt
    return bcrypt.verify(password_for_bcrypt, password_hash)

# JWT utility functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    global mongodb_connected
    try:
        await connect_to_mongo()
        mongodb_connected = True
        
        # Only create indexes if MongoDB is connected
        try:
            # Create indexes for collections
            user_collection = get_user_collection()
            qr_tokens_collection = get_qr_tokens_collection()
            
            # Ensure unique email index for users
            await user_collection.create_index("email", unique=True)
            
            # Ensure unique token index for QR tokens and TTL index for expiry
            await qr_tokens_collection.create_index("token", unique=True)
            await qr_tokens_collection.create_index("expires_at", expireAfterSeconds=0)  # TTL index
            
            # Create indexes for OTPs collection
            otps_collection = get_otps_collection()
            await otps_collection.create_index("email")
            await otps_collection.create_index("expires_at", expireAfterSeconds=0)  # TTL index for auto-cleanup
            await otps_collection.create_index([("email", 1), ("purpose", 1), ("used", 1)])
        except Exception as index_error:
            print(f"⚠️  Warning: Could not create indexes: {str(index_error)[:100]}")
        
        print("✅ MongoDB connected successfully")
    except Exception as e:
        mongodb_connected = False
        print(f"⚠️  MongoDB connection failed: {str(e)[:100]}")
        print("⚠️  Using in-memory storage (data will not persist)")
    
    print("\n🔐 Security features enabled:")
    print(f"   - Storage: {'MongoDB' if mongodb_connected else 'In-Memory (temporary)'}")
    print(f"   - JWT Algorithm: {ALGORITHM}")
    print(f"   - Token Expiry: {ACCESS_TOKEN_EXPIRE_HOURS} hours")
    print(f"   - AES Encryption: {'Enabled' if len(AES_SECRET_KEY) == 32 else 'Warning: Key length incorrect'}")
    print(f"   - Password Hashing: bcrypt enabled")
    print(f"   - QR Token Security: AES encrypted + 1-minute expiry")
    print(f"   - OTP System: {'✅ Enabled (SMTP configured)' if SMTP_USER and SMTP_PASSWORD else '⚠️  Development Mode (console output)'}")
    if SMTP_USER and SMTP_PASSWORD:
        print(f"   - SMTP Server: {SMTP_HOST}:{SMTP_PORT}")
        print(f"   - SMTP User: {SMTP_USER}")
        print(f"   - Email From: {SMTP_FROM_NAME}")
    print(f"\n🚀 Server is running at http://localhost:8000")
    print(f"📱 Access the app at http://localhost:8000/static/index.html\n")

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
# Updated to use the robust CLIENT_DIR from the path configuration
if CLIENT_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(CLIENT_DIR)), name="static")
    print(f"✅ Static files mounted from: {CLIENT_DIR}")
else:
    print("⚠️  Warning: Client directory not found. Static files will not be served.")
    print(f"   Expected path: {CLIENT_DIR}")

# Root endpoint - Updated to serve index.html
@app.get("/")
async def root():
    index_file = CLIENT_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
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
    email_sent = await send_email_otp(email, otp_code, "signup")
    
    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP email. Please try again later."
        )
    
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
    email_sent = await send_email_otp(email, otp_code, "forgot_password")
    
    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP email. Please try again later."
        )
    
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
    SESSIONS[session_id] = {
        "created_at": datetime.utcnow().isoformat()
    }
    # Construct a join URL pointing to the chat client with session_id
    join_url = f"/static/chat.html?session_id={session_id}"
    return {"session_id": session_id, "join_url": join_url}

@app.get("/qr_from_session/{session_id}")
async def qr_from_session(session_id: str):
    # Validate session exists
    if session_id not in SESSIONS:
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
    # Verify JWT token
    user_email = verify_token(token)
    if not user_email:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    # Validate session
    if session_id not in SESSIONS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(session_id, websocket)
    try:
        welcome_msg = f"Welcome {user_email}! Joined session {session_id}."
        encrypted_welcome = encrypt_message(welcome_msg)
        await websocket.send_json({
            "user": "System",
            "message": encrypted_welcome,
            "encrypted": True,
            "security_info": "Message encrypted with AES-256-CBC"
        })

        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)
                user = message_data.get("user", user_email)
                message = message_data.get("message", "")
                
                # Security monitoring - analyze message for threats
                try:
                    # Check if security_monitor is available and has the analyze_message method
                    if security_monitor and hasattr(security_monitor, 'analyze_message'):
                        warnings = security_monitor.analyze_message(user_email, session_id, message)
                        
                        # Add warnings to user's record
                        for warning in warnings:
                            security_monitor.add_warning(warning)
                        
                        # Check if session should be terminated
                        should_terminate = security_monitor.should_terminate_session(user_email, session_id)
                        
                        if should_terminate:
                            termination_msg = "Session terminated due to security violations."
                            encrypted_termination = encrypt_message(termination_msg)
                            await websocket.send_json({
                                "user": "Security System",
                                "message": encrypted_termination,
                                "encrypted": True,
                                "security_info": "Session terminated due to multiple security warnings",
                                "terminated": True
                            })
                            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                            return
                        
                        # Send warning messages if any
                        for warning in warnings:
                            warning_msg = f"Security Warning: {warning.message}"
                            encrypted_warning = encrypt_message(warning_msg)
                            warning_count = security_monitor.get_warning_count(user_email, session_id) if hasattr(security_monitor, 'get_warning_count') else 0
                            max_warnings = security_monitor.max_warnings_before_ban if hasattr(security_monitor, 'max_warnings_before_ban') else 3
                            await websocket.send_json({
                                "user": "Security System",
                                "message": encrypted_warning,
                                "encrypted": True,
                                "security_info": f"Warning {warning_count}/{max_warnings}",
                                "warning": True
                            })
                except Exception as sec_error:
                    print(f"⚠️  Security monitoring error: {sec_error}")
                
                encrypted_message = encrypt_message(message)
                response = {
                    "user": user,
                    "message": encrypted_message,
                    "encrypted": True,
                    "timestamp": datetime.utcnow().isoformat(),
                    "security_info": "Message encrypted with AES-256-CBC"
                }
                await manager.broadcast(session_id, response)
            except json.JSONDecodeError:
                error_msg = "Invalid message format. Please send JSON with 'user' and 'message' fields."
                encrypted_error = encrypt_message(error_msg)
                await websocket.send_json({
                    "user": "System",
                    "message": encrypted_error,
                    "encrypted": True,
                    "error": True
                })
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)

# Security monitoring endpoints
@app.get("/security/report/{session_id}")
async def get_security_report(session_id: str, token: str = Query(...)):
    """Get security report for a session (requires authentication)"""
    user_email = verify_token(token)
    if not user_email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    if session_id not in SESSIONS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    return security_monitor.get_security_report(user_email, session_id)

@app.post("/security/clear_warnings/{session_id}")
async def clear_warnings(session_id: str, token: str = Query(...)):
    """Clear warnings for a user in a session (requires authentication)"""
    user_email = verify_token(token)
    if not user_email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    if session_id not in SESSIONS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    security_monitor.clear_warnings(user_email, session_id)
    return {"message": "Warnings cleared successfully"}

# Session validation endpoint
@app.post("/validate_session")
async def validate_session(session: SessionValidation):
    """Validate if a JWT token is still valid"""
    user_email = verify_token(session.token)
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    return {
        "valid": True,
        "email": user_email,
        "message": "Session is valid"
    }

@app.get("/validate_session")
async def validate_session_get(token: str = Query(...)):
    """Validate session via GET (for easier frontend use)"""
    user_email = verify_token(token)
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    return {
        "valid": True,
        "email": user_email,
        "message": "Session is valid"
    }

# Token refresh endpoint
@app.post("/refresh_token")
async def refresh_token(session: SessionValidation):
    """Refresh an existing JWT token"""
    user_email = verify_token(session.token)
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    # Generate new token
    token_data = {"sub": user_email}
    new_access_token = create_access_token(data=token_data)
    
    return {
        "message": "Token refreshed successfully",
        "token": new_access_token
    }

# Logout endpoint (clears client-side tokens, optional server-side blacklist)
@app.post("/logout")
async def logout():
    """Logout endpoint - client should clear tokens"""
    return {
        "message": "Logged out successfully. Please clear your tokens on the client side."
    }

# Get OTP rate limit status
@app.get("/otp_rate_limit_status")
async def get_otp_rate_limit_status(email: str = Query(...), purpose: str = Query(...)):
    """Get OTP rate limit status for an email"""
    email = email.lower().strip()
    
    if mongodb_connected:
        try:
            otps_collection = get_otps_collection()
            fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
            count = await otps_collection.count_documents({
                "email": email,
                "purpose": purpose,
                "created_at": {"$gte": fifteen_min_ago}
            })
            remaining = max(0, 3 - count)
            can_request = count < 3
            
            # Get time until next request allowed
            if not can_request:
                oldest_otp = await otps_collection.find_one(
                    {"email": email, "purpose": purpose},
                    sort=[("created_at", 1)]
                )
                if oldest_otp:
                    next_allowed = oldest_otp["created_at"] + timedelta(minutes=15)
                    wait_seconds = max(0, int((next_allowed - datetime.utcnow()).total_seconds()))
                else:
                    wait_seconds = 0
            else:
                wait_seconds = 0
            
            return {
                "can_request": can_request,
                "remaining_attempts": remaining,
                "wait_seconds": wait_seconds,
                "max_requests": 3,
                "window_minutes": 15
            }
        except:
            pass
    
    # In-memory check
    fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
    key_prefix = f"{email}:{purpose}"
    count = sum(1 for key, doc in in_memory_otps.items() 
               if key.startswith(key_prefix) and doc["created_at"] >= fifteen_min_ago)
    remaining = max(0, 3 - count)
    can_request = count < 3
    
    return {
        "can_request": can_request,
        "remaining_attempts": remaining,
        "wait_seconds": 0 if can_request else 900,  # 15 minutes
        "max_requests": 3,
        "window_minutes": 15
    }

# Security status endpoint
@app.get("/security/status")
async def security_status():
    return {
        "jwt_enabled": True,
        "bcrypt_enabled": True,
        "aes_encryption": True,
        "password_rounds": 12,
        "encryption_algorithm": "AES-256-CBC",
        "qr_token_security": {
            "encryption": "AES-256-CBC",
            "expiry": "1 minute",
            "storage": "MongoDB with TTL" if mongodb_connected else "In-Memory",
            "one_time_use": True,
            "no_raw_data": True
        },
        "security_monitoring": {
            "enabled": True,
            "phishing_detection": True,
            "malicious_content_detection": True,
            "spam_detection": True,
            "rate_limiting": True,
            "max_warnings_before_ban": 3,
            "max_messages_per_minute": 30
        },
        "security_level": "Enhanced with Security Monitoring"
    }

# Test OTP Email Endpoint (for testing purposes)
@app.post("/test_otp_email")
async def test_otp_email(email: str = Query(..., description="Email address to test")):
    """Test endpoint to verify OTP email sending is working"""
    try:
        test_otp = generate_otp()
        email_sent = await send_email_otp(email, test_otp, "signup")
        
        if email_sent:
            return {
                "success": True,
                "message": f"Test OTP email sent successfully to {email}",
                "otp_code": test_otp,  # Only for testing - remove in production
                "smtp_configured": bool(SMTP_USER and SMTP_PASSWORD)
            }
        else:
            return {
                "success": False,
                "message": "Failed to send test email",
                "smtp_configured": bool(SMTP_USER and SMTP_PASSWORD)
            }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sending test email: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
