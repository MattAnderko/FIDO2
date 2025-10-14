from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from ..db import session_scope, Base, engine
from ..models import User, Credential
from ..config import settings
from ..redis_store import set_state, pop_state
from ..security import issue_token

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, AttestationConveyancePreference
from fido2.webauthn import UserVerificationRequirement
from fido2.utils import websafe_encode, websafe_decode

import datetime

router = APIRouter(prefix="/api/v1", tags=["webauthn"])

Base.metadata.create_all(bind=engine)

rp = PublicKeyCredentialRpEntity(id=settings.RP_ID, name=settings.RP_NAME)
server = Fido2Server(rp, attestation=AttestationConveyancePreference.NONE)

def get_user(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).one_or_none()

@router.post("/register/start")
async def register_start(payload: dict):
    username = payload.get("username")
    display_name = payload.get("displayName") or username
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            user = User(username=username, display_name=display_name)
            db.add(user)
            db.flush()
        exclude = [{"type": "public-key", "id": websafe_encode(c.credential_id)} for c in user.credentials]

    user_entity = PublicKeyCredentialUserEntity(id=str(user.id).encode(), name=username, display_name=display_name)
    options, state = server.register_begin(
        user=user_entity,
        credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
        authenticator_selection={
            "userVerification": "required",
            "residentKey": "preferred",
        },
        exclude_credentials=exclude,
    )

    set_state("reg", username, {"state": websafe_encode(state), "user_id": user.id})
    return JSONResponse(options)

@router.post("/register/finish")
async def register_finish(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    state = pop_state("reg", username)
    if not state:
        raise HTTPException(status_code=400, detail="registration state expired or missing")

    client_data_json = websafe_decode(payload["response"]["clientDataJSON"])
    att_obj = websafe_decode(payload["response"]["attestationObject"])

    auth_data = server.register_complete(
        websafe_decode(state["state"]),
        client_data_json,
        att_obj,
    )

    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="user not found")
        cred = Credential(
            user_id=user.id,
            credential_id=auth_data.credential_data.credential_id,
            public_key=auth_data.credential_data.public_key,
            sign_count=auth_data.sign_count,
            aaguid=str(auth_data.credential_data.aaguid),
            transports=",".join(payload.get("transports", []) or []),
        )
        db.add(cred)

    return {"status": "ok"}

@router.post("/login/start")
async def login_start(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    with session_scope() as db:
        user = get_user(db, username)
        if not user or not user.credentials:
            raise HTTPException(status_code=404, detail="user or credentials not found")
        allowed = [{"type": "public-key", "id": websafe_encode(c.credential_id)} for c in user.credentials]

    options, state = server.authenticate_begin(
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.REQUIRED
    )

    set_state("auth", username, {"state": websafe_encode(state), "user_id": user.id})
    return JSONResponse(options)

@router.post("/login/finish")
async def login_finish(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    state = pop_state("auth", username)
    if not state:
        raise HTTPException(status_code=400, detail="authentication state expired or missing")

    cred_id = websafe_decode(payload["id"])
    client_data_json = websafe_decode(payload["response"]["clientDataJSON"])
    authenticator_data = websafe_decode(payload["response"]["authenticatorData"])
    signature = websafe_decode(payload["response"]["signature"])

    with session_scope() as db:
        cred = db.query(Credential).filter(Credential.credential_id == cred_id).one_or_none()
        if not cred:
            raise HTTPException(status_code=404, detail="credential not found")

        result = server.authenticate_complete(
            websafe_decode(state["state"]),
            [{
                "type": "public-key",
                "id": cred.credential_id,
                "public_key": cred.public_key,
                "sign_count": cred.sign_count,
            }],
            cred_id,
            client_data_json,
            authenticator_data,
            signature,
        )

        cred.sign_count = result.new_sign_count
        cred.last_used_at = datetime.datetime.utcnow()
        user = db.query(User).filter(User.id == cred.user_id).one()
        token = issue_token(sub=user.username)

    return {"status": "ok", "token": token}
