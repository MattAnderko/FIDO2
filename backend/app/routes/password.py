from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..db import session_scope
from ..models import User, Credential
from ..credential_helpers import get_credential_by_type, has_credential_type
from ..password_utils import (
    hash_password, verify_password, check_account_locked,
    increment_failed_attempts, reset_failed_attempts, validate_password_strength
)
from ..security import issue_token
from datetime import datetime

router = APIRouter(prefix="/api/v1", tags=["password"])

class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str | None = None

class LoginRequest(BaseModel):
    username: str
    password: str

class PasswordResetRequest(BaseModel):
    username: str

class PasswordResetConfirm(BaseModel):
    username: str
    reset_token: str
    new_password: str

def get_user(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).one_or_none()

@router.post("/password/register")
async def password_register(payload: RegisterRequest):
    """Register a new user with password authentication."""
    username = payload.username.strip()
    password = payload.password
    display_name = payload.display_name or username
    
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    
    # Validate password strength
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    with session_scope() as db:
        # Check if user already exists
        existing_user = get_user(db, username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create new user
        user = User(
            username=username,
            display_name=display_name
        )
        db.add(user)
        db.flush()  # Get user.id
        
        # Create password credential
        password_hash = hash_password(password)
        password_credential = Credential(
            user_id=user.id,
            credential_type='password',
            password_hash=password_hash
        )
        db.add(password_credential)
    
    return {"status": "ok", "message": "Registration successful"}

@router.post("/password/login")
async def password_login(payload: LoginRequest):
    """Login with username and password."""
    username = payload.username.strip()
    password = payload.password
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            # Don't reveal if user exists
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if account is locked
        if check_account_locked(user):
            raise HTTPException(
                status_code=423,
                detail="Account is temporarily locked due to too many failed login attempts"
            )
        
        # Get password credential
        password_credential = get_credential_by_type(db, user, 'password')
        if not password_credential or not password_credential.password_hash:
            increment_failed_attempts(db, user)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not verify_password(password, password_credential.password_hash):
            increment_failed_attempts(db, user)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if TOTP is enabled (requires 2FA)
        totp_credential = get_credential_by_type(db, user, 'totp')
        if totp_credential and totp_credential.totp_enabled:
            raise HTTPException(
                status_code=400,
                detail="TOTP 2FA is enabled for this account. Please use /totp/login endpoint."
            )
        
        # Check if user has FIDO2 credentials (should use FIDO2 login instead)
        if has_credential_type(db, user, 'fido2'):
            raise HTTPException(
                status_code=400,
                detail="User has FIDO2 credentials. Please use FIDO2 authentication."
            )
        
        # Successful login - update last_used_at
        password_credential.last_used_at = datetime.utcnow()
        reset_failed_attempts(db, user)
        token = issue_token(sub=user.username)
    
    return {"status": "ok", "token": token}

@router.post("/password/reset/request")
async def password_reset_request(payload: PasswordResetRequest):
    """Request a password reset token."""
    # In a real implementation, you would:
    # 1. Generate a secure token
    # 2. Store it in Redis with expiration (e.g., 1 hour)
    # 3. Send email with reset link
    # For now, we'll just return a success message
    username = payload.username.strip()
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            # Don't reveal if user exists
            return {"status": "ok", "message": "If the user exists, a reset email has been sent"}
        
        # TODO: Generate token and send email
        # For demo purposes, we'll skip the actual email sending
    
    return {"status": "ok", "message": "If the user exists, a reset email has been sent"}

@router.post("/password/reset/confirm")
async def password_reset_confirm(payload: PasswordResetConfirm):
    """Confirm password reset with token."""
    username = payload.username.strip()
    reset_token = payload.reset_token
    new_password = payload.new_password
    
    # Validate password strength
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    # TODO: Verify reset token from Redis
    # For now, we'll skip token verification in demo
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get or create password credential
        password_credential = get_credential_by_type(db, user, 'password')
        if not password_credential:
            # Create password credential if it doesn't exist
            password_credential = Credential(
                user_id=user.id,
                credential_type='password',
                password_hash=hash_password(new_password)
            )
            db.add(password_credential)
        else:
            # Update existing password credential
            password_credential.password_hash = hash_password(new_password)
        
        # Reset account lockout
        user.failed_login_attempts = 0
        user.locked_until = None
    
    return {"status": "ok", "message": "Password reset successful"}

