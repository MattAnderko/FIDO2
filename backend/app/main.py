from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .db import db_ping, Base, engine
from . import models  # register models
from .routes import core
from .routes import fido

app = FastAPI(title="FIDO2 Backend", version="0.0.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

@app.get("/healthz")
def healthz():
    return {"status": "ok", "db": "up" if db_ping() else "down"}

@app.get("/api/healthz")
def healthz_alias():
    return healthz()

app.include_router(core.router)
app.include_router(fido.router)

@app.get("/")
def root():
    return {"service": "backend", "version": "0.0.4"}
