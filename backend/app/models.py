from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, DateTime, Boolean, func, Index
from sqlalchemy.orm import relationship, Mapped, mapped_column
from .db import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=True)
    registered_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    
    # Account-level security fields (not credential-specific)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[DateTime] = mapped_column(DateTime, nullable=True)

    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")

class Credential(Base):
    """
    Unified credential model supporting multiple authentication types:
    - 'fido2': WebAuthn/FIDO2 credentials (multiple per user)
    - 'password': Password hash (typically one per user)
    - 'totp': TOTP/2FA credentials (typically one per user)
    """
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    credential_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # 'fido2', 'password', 'totp'
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[DateTime] = mapped_column(DateTime, nullable=True)
    
    # FIDO2-specific fields (nullable, only used when credential_type='fido2')
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)  # FIDO2 credential ID
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)  # FIDO2 COSE public key
    sign_count: Mapped[int] = mapped_column(Integer, default=0)  # FIDO2 signature counter
    aaguid: Mapped[str] = mapped_column(String(64), nullable=True)  # FIDO2 authenticator AAGUID
    transports: Mapped[str] = mapped_column(String(255), nullable=True)  # FIDO2 transports (comma-separated)
    
    # Password-specific fields (nullable, only used when credential_type='password')
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)  # bcrypt hash
    
    # TOTP-specific fields (nullable, only used when credential_type='totp')
    totp_secret: Mapped[str] = mapped_column(String(255), nullable=True)  # TOTP secret key
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # Whether TOTP is enabled
    backup_codes_hash: Mapped[str] = mapped_column(String(2048), nullable=True)  # JSON array of hashed backup codes (10 codes * ~64 chars each + JSON overhead)

    user = relationship("User", back_populates="credentials")
    
    # Composite index for efficient lookups
    __table_args__ = (
        Index('ix_credentials_user_type', 'user_id', 'credential_type'),
    )
