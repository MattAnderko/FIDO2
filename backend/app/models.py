from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship, Mapped, mapped_column
from .db import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=True)
    registered_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")

class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    aaguid: Mapped[str] = mapped_column(String(64), nullable=True)
    transports: Mapped[str] = mapped_column(String(255), nullable=True)  # comma-separated
    last_used_at: Mapped[DateTime] = mapped_column(DateTime, nullable=True)

    user = relationship("User", back_populates="credentials")
