import time
import jwt
from .config import settings

ALGO = "HS256"

def issue_token(sub: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGO)
