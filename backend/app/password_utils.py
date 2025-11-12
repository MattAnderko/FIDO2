import bcrypt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .models import User

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

def check_account_locked(user: User) -> bool:
    """Check if account is currently locked."""
    if user.locked_until is None:
        return False
    if user.locked_until > datetime.utcnow():
        return True
    # Lock expired, reset it
    user.locked_until = None
    user.failed_login_attempts = 0
    return False

def increment_failed_attempts(db: Session, user: User):
    """Increment failed login attempts and lock account if threshold reached."""
    user.failed_login_attempts += 1
    max_attempts = 5
    lockout_minutes = 15
    
    if user.failed_login_attempts >= max_attempts:
        user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
    db.commit()

def reset_failed_attempts(db: Session, user: User):
    """Reset failed login attempts on successful login."""
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength. Returns (is_valid, error_message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, ""




