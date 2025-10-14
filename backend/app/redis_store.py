from redis import Redis
from .config import settings
import json

r = Redis.from_url(settings.REDIS_URL)

def _key(prefix: str, user: str) -> str:
    return f"{prefix}:{user}"

def set_state(prefix: str, user: str, data: dict, ttl_seconds: int = 300):
    r.setex(_key(prefix, user), ttl_seconds, json.dumps(data))

def pop_state(prefix: str, user: str) -> dict | None:
    key = _key(prefix, user)
    pipe = r.pipeline()
    pipe.get(key)
    pipe.delete(key)
    value, _ = pipe.execute()
    if value is None:
        return None
    return json.loads(value)
