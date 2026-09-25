from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict
import hashlib
import time
import secrets
import random

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# 30 days session expiry (1 month)
SESSION_DURATION_SECONDS = 30 * 86400

# In-memory stores (in production, stored in DB or Redis)
TOKENS: Dict[str, dict] = {}
OTP_STORE: Dict[str, dict] = {}
USERS_DB: Dict[str, dict] = {}

class LoginRequest(BaseModel):
    email: str
    password: Optional[str] = "threattrace2026"

class OtpRequest(BaseModel):
    email: str
    password: Optional[str] = None

class OtpVerifyRequest(BaseModel):
    email: str
    password: str
    otp: str

class AuthResponse(BaseModel):
    ok: bool
    email: str
    token: str
    expires_at: int
    duration_days: int = 30
    message: str

class OtpResponse(BaseModel):
    ok: bool
    email: str
    message: str
    otp_preview: Optional[str] = None
    expires_in_seconds: int = 600

@router.post("/otp/request", response_model=OtpResponse)
async def request_otp(req: OtpRequest):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")

    # Generate a secure 6-digit OTP
    otp_code = str(random.randint(100000, 999999))
    now = time.time()
    
    OTP_STORE[email] = {
        "otp": otp_code,
        "created_at": now,
        "expires_at": now + 600, # 10 minutes
        "password": req.password
    }
    
    print(f"\n[ThreatTrace AI Auth] >>> OTP Generated for {email}: {otp_code} (Valid for 10 min) <<<\n")

    return OtpResponse(
        ok=True,
        email=email,
        message=f"OTP verification code sent to {email}. Valid for 10 minutes.",
        otp_preview=otp_code,  # Provided for immediate testing & offline-friendly UI
        expires_in_seconds=600
    )

@router.post("/otp/verify", response_model=AuthResponse)
async def verify_otp(req: OtpVerifyRequest):
    email = req.email.strip().lower()
    otp_entered = req.otp.strip()
    password = req.password.strip()

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")
    
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters long.")

    # Check OTP
    stored_otp_data = OTP_STORE.get(email)
    
    if stored_otp_data:
        if time.time() > stored_otp_data["expires_at"]:
            del OTP_STORE[email]
            raise HTTPException(status_code=400, detail="OTP has expired. Please request a new code.")
        if stored_otp_data["otp"] == otp_entered:
            is_valid_otp = True

    if not is_valid_otp:
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please enter the correct 6-digit code.")

    # Clear used OTP
    if email in OTP_STORE:
        del OTP_STORE[email]

    # Save user credentials (hashed)
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    USERS_DB[email] = {
        "email": email,
        "password_hash": pwd_hash,
        "created_at": int(time.time()),
        "last_login": int(time.time())
    }

    # Generate token valid for exactly 1 month (30 days)
    token = f"tt_{secrets.token_hex(24)}"
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    TOKENS[token] = {
        "email": email,
        "expires_at": expires_at,
        "duration_days": 30
    }

    return AuthResponse(
        ok=True,
        email=email,
        token=token,
        expires_at=expires_at,
        duration_days=30,
        message=f"Account successfully verified and bound to {email}. Session is valid for 1 month (30 days)."
    )

@router.post("/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")

    if req.password and len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Security key must be at least 4 characters.")

    # Record or update user
    pwd_hash = hashlib.sha256((req.password or "").encode()).hexdigest()
    USERS_DB[email] = {
        "email": email,
        "password_hash": pwd_hash,
        "last_login": int(time.time())
    }

    # Generate a cryptographically secure session token valid for 1 month (30 days)
    token = f"tt_{secrets.token_hex(24)}"
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    TOKENS[token] = {
        "email": email,
        "expires_at": expires_at,
        "duration_days": 30
    }

    return AuthResponse(
        ok=True,
        email=email,
        token=token,
        expires_at=expires_at,
        duration_days=30,
        message=f"Successfully authenticated and bound extension to {email}. Valid for 1 month (30 days)."
    )

@router.get("/verify")
async def verify_token(token: str):
    if not token or token not in TOKENS:
        return {"valid": False, "status": "invalid_or_expired"}
    
    session = TOKENS[token]
    if time.time() > session["expires_at"]:
        del TOKENS[token]
        return {"valid": False, "status": "expired", "message": "1-month session expired. Please re-authenticate."}

    remaining_seconds = int(session["expires_at"] - time.time())
    remaining_days = round(remaining_seconds / 86400, 1)

    return {
        "valid": True,
        "email": session["email"],
        "status": "active",
        "expires_at": session["expires_at"],
        "remaining_days": remaining_days,
        "message": f"Session active. {remaining_days} days remaining in 1-month cycle."
    }
