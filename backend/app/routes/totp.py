from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
import pyotp
import qrcode
import io
import base64
import json
import hashlib
from datetime import datetime
from ..db import session_scope
from ..models import User, Credential
from ..credential_helpers import get_credential_by_type
from ..password_utils import verify_password, check_account_locked
from ..security import issue_token

router = APIRouter(prefix="/api/v1", tags=["totp"])

class SetupTOTPRequest(BaseModel):
    username: str
    password: str  # Verify password before enabling 2FA

class VerifyTOTPRequest(BaseModel):
    username: str
    totp_code: str

class LoginWithTOTPRequest(BaseModel):
    username: str
    password: str
    totp_code: str

class BackupCodeRequest(BaseModel):
    username: str
    backup_code: str

def get_user(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).one_or_none()

def hash_backup_code(code: str) -> str:
    """Hash a backup code for storage."""
    return hashlib.sha256(code.encode('utf-8')).hexdigest()

def verify_backup_code(code: str, hashed_codes: str) -> bool:
    """Verify a backup code against stored hashes."""
    if not hashed_codes:
        return False
    try:
        code_hashes = json.loads(hashed_codes)
        code_hash = hash_backup_code(code)
        return code_hash in code_hashes
    except Exception:
        return False

def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate backup codes."""
    import secrets
    return [secrets.token_hex(4).upper() for _ in range(count)]

@router.post("/totp/setup")
async def setup_totp(payload: SetupTOTPRequest):
    """Setup TOTP 2FA for a user."""
    username = payload.username.strip()
    password = payload.password
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify password using password credential
        password_credential = get_credential_by_type(db, user, 'password')
        if not password_credential or not password_credential.password_hash:
            raise HTTPException(status_code=401, detail="Invalid password")
        if not verify_password(password, password_credential.password_hash):
            raise HTTPException(status_code=401, detail="Invalid password")
        
        # Check if TOTP credential already exists and is enabled
        totp_credential = get_credential_by_type(db, user, 'totp')
        if totp_credential and totp_credential.totp_enabled:
            raise HTTPException(status_code=400, detail="TOTP already enabled")
        
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = generate_backup_codes(10)
        backup_codes_hashed = [hash_backup_code(code) for code in backup_codes]
        
        # Create or update TOTP credential
        if totp_credential:
            totp_credential.totp_secret = totp_secret
            totp_credential.backup_codes_hash = json.dumps(backup_codes_hashed)
            totp_credential.totp_enabled = False  # Not enabled until verified
        else:
            totp_credential = Credential(
                user_id=user.id,
                credential_type='totp',
                totp_secret=totp_secret,
                totp_enabled=False,
                backup_codes_hash=json.dumps(backup_codes_hashed)
            )
            db.add(totp_credential)
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=user.username,
            issuer_name="FIDO2 Demo"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return {
        "status": "ok",
        "secret": totp_secret,  # For manual entry
        "qr_code": f"data:image/png;base64,{qr_code_base64}",
        "backup_codes": backup_codes,  # Show only once!
        "message": "Scan QR code with authenticator app and verify to enable 2FA"
    }

@router.post("/totp/verify")
async def verify_totp(payload: VerifyTOTPRequest):
    """Verify TOTP code to enable 2FA."""
    username = payload.username.strip()
    totp_code = payload.totp_code.strip()
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get TOTP credential
        totp_credential = get_credential_by_type(db, user, 'totp')
        if not totp_credential or not totp_credential.totp_secret:
            raise HTTPException(status_code=404, detail="TOTP not set up")
        
        # Verify TOTP code
        totp = pyotp.TOTP(totp_credential.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
        
        # Enable TOTP
        totp_credential.totp_enabled = True
    
    return {"status": "ok", "message": "TOTP enabled successfully"}

@router.post("/totp/login")
async def login_with_totp(payload: LoginWithTOTPRequest):
    """Login with password and TOTP code."""
    username = payload.username.strip()
    password = payload.password
    totp_code = payload.totp_code.strip()
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if account is locked
        if check_account_locked(user):
            raise HTTPException(
                status_code=423,
                detail="Account is temporarily locked"
            )
        
        # Verify password using password credential
        password_credential = get_credential_by_type(db, user, 'password')
        if not password_credential or not password_credential.password_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not verify_password(password, password_credential.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get TOTP credential
        totp_credential = get_credential_by_type(db, user, 'totp')
        if not totp_credential or not totp_credential.totp_enabled:
            raise HTTPException(status_code=400, detail="TOTP not enabled for this user")
        
        # Verify TOTP code
        if not totp_credential.totp_secret:
            raise HTTPException(status_code=400, detail="TOTP secret not found")
        totp = pyotp.TOTP(totp_credential.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid TOTP code")
        
        # Successful login - update last_used_at
        totp_credential.last_used_at = datetime.utcnow()
        token = issue_token(sub=user.username)
    
    return {"status": "ok", "token": token}

@router.post("/totp/backup-login")
async def login_with_backup_code(payload: BackupCodeRequest):
    """Login using a backup code (one-time use)."""
    username = payload.username.strip()
    backup_code = payload.backup_code.strip()
    
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get TOTP credential
        totp_credential = get_credential_by_type(db, user, 'totp')
        if not totp_credential or not totp_credential.backup_codes_hash:
            raise HTTPException(status_code=400, detail="No backup codes available")
        
        # Verify backup code
        if not verify_backup_code(backup_code, totp_credential.backup_codes_hash):
            raise HTTPException(status_code=401, detail="Invalid backup code")
        
        # Remove used backup code
        code_hashes = json.loads(totp_credential.backup_codes_hash)
        code_hash = hash_backup_code(backup_code)
        code_hashes.remove(code_hash)
        totp_credential.backup_codes_hash = json.dumps(code_hashes) if code_hashes else None
        totp_credential.last_used_at = datetime.utcnow()
        
        token = issue_token(sub=user.username)
    
    return {"status": "ok", "token": token}

@router.get("/totp/status/{username}")
async def get_totp_status(username: str):
    """Get TOTP status for a user."""
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        totp_credential = get_credential_by_type(db, user, 'totp')
        return {
            "totp_enabled": totp_credential.totp_enabled if totp_credential else False,
            "has_backup_codes": bool(totp_credential.backup_codes_hash) if totp_credential else False
        }

