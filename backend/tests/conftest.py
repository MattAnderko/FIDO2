"""
Pytest configuration and fixtures for latency tests.
"""
import pytest
import pytest_asyncio
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from httpx import AsyncClient
from fakeredis import FakeStrictRedis
from contextlib import contextmanager
import sys
from unittest.mock import patch

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.main import app
from app.db import Base
from app.models import User, Credential


# Use in-memory SQLite for testing
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    """Create a test database and override session_scope."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    
    @contextmanager
    def test_session_scope():
        db_session = TestingSessionLocal()
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise
        finally:
            db_session.close()
    
    # Patch session_scope in app.db module
    with patch('app.db.session_scope', test_session_scope):
        with patch('app.db.SessionLocal', TestingSessionLocal):
            with patch('app.db.engine', engine):
                yield TestingSessionLocal
    
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def test_redis():
    """Create a fake Redis instance for testing."""
    fake_redis = FakeStrictRedis()
    
    # Patch redis client in app.redis_store module
    with patch('app.redis_store.r', fake_redis):
        yield fake_redis


@pytest_asyncio.fixture
async def client(test_db, test_redis):
    """Create an async HTTP test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def test_user(test_db):
    """Create a test user."""
    from app.db import session_scope
    with session_scope() as db:
        user = User(username="testuser", display_name="Test User")
        db.add(user)
        db.flush()
        user_id = user.id
    return user_id


@pytest.fixture
def test_user_with_password(test_db):
    """Create a test user with password credential."""
    from app.db import session_scope
    from app.password_utils import hash_password
    
    with session_scope() as db:
        user = User(username="testuser_pwd", display_name="Test User")
        db.add(user)
        db.flush()
        
        password_cred = Credential(
            user_id=user.id,
            credential_type='password',
            password_hash=hash_password("testpassword123")
        )
        db.add(password_cred)
        db.flush()
        user_id = user.id
    
    return {"user_id": user_id, "username": "testuser_pwd", "password": "testpassword123"}


@pytest.fixture
def test_user_with_totp(test_db):
    """Create a test user with password and TOTP credentials."""
    from app.db import session_scope
    from app.password_utils import hash_password
    import pyotp
    import json
    import hashlib
    
    with session_scope() as db:
        user = User(username="testuser_totp", display_name="Test User")
        db.add(user)
        db.flush()
        
        # Password credential
        password_cred = Credential(
            user_id=user.id,
            credential_type='password',
            password_hash=hash_password("testpassword123")
        )
        db.add(password_cred)
        
        # TOTP credential
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        current_code = totp.now()
        
        backup_codes = ["BACKUP1", "BACKUP2"]
        backup_hashes = [hashlib.sha256(code.encode()).hexdigest() for code in backup_codes]
        
        totp_cred = Credential(
            user_id=user.id,
            credential_type='totp',
            totp_secret=totp_secret,
            totp_enabled=True,
            backup_codes_hash=json.dumps(backup_hashes)
        )
        db.add(totp_cred)
        db.flush()
        user_id = user.id
    
    return {
        "user_id": user_id,
        "username": "testuser_totp",
        "password": "testpassword123",
        "totp_secret": totp_secret,
        "totp_code": current_code,
    }


@pytest.fixture(scope="session")
def results_collector():
    """Get the global results collector."""
    from tests.utils.results import get_collector
    return get_collector()


# Register the pytest plugin
pytest_plugins = ["tests.pytest_plugin"]

