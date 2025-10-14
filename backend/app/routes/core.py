from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["core"])  # API váz

@router.get("/health")
def api_health():
    return {"status": "ok", "scope": "api-v1"}
