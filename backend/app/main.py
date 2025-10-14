from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .db import db_ping, Base, engine
from . import models  # ensure models are registered
from .routes import core

app = FastAPI(title="FIDO2 Backend", version="0.0.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Táblák létrehozása induláskor (később Alembic)
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "db": "up" if db_ping() else "down",
    }

# Gateway proxy kompat: /api/healthz → backend /healthz (strip_prefix után /healthz marad)
@app.get("/api/healthz")
def healthz_alias():
    return healthz()

# API v1 mount
app.include_router(core.router)

@app.get("/")
def root():
    return {"service": "backend", "version": "0.0.3"}
