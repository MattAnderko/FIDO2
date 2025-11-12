"""Helper functions for working with unified Credential model."""
from sqlalchemy.orm import Session
from .models import User, Credential

def get_credential_by_type(db: Session, user: User, credential_type: str) -> Credential | None:
    """Get a credential of a specific type for a user."""
    return db.query(Credential).filter(
        Credential.user_id == user.id,
        Credential.credential_type == credential_type
    ).first()

def get_fido2_credentials(db: Session, user: User) -> list[Credential]:
    """Get all FIDO2 credentials for a user."""
    return db.query(Credential).filter(
        Credential.user_id == user.id,
        Credential.credential_type == 'fido2'
    ).all()

def has_credential_type(db: Session, user: User, credential_type: str) -> bool:
    """Check if user has a credential of a specific type."""
    return db.query(Credential).filter(
        Credential.user_id == user.id,
        Credential.credential_type == credential_type
    ).first() is not None

def get_primary_auth_method(db: Session, user: User) -> str:
    """Determine the primary authentication method for a user.
    Priority: fido2 > totp > password
    """
    if has_credential_type(db, user, 'fido2'):
        return 'fido2'
    if has_credential_type(db, user, 'totp'):
        return 'totp'
    if has_credential_type(db, user, 'password'):
        return 'password'
    return 'none'




