from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from ..db import session_scope, Base, engine
from ..models import User, Credential
from ..config import settings
from ..redis_store import set_state, pop_state
from ..security import issue_token

# --- fido2 v2.0 imports ---
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    AttestedCredentialData,
    Aaguid,
)
from fido2.utils import websafe_encode, websafe_decode

from fido2.cose import CoseKey
import cbor2
import datetime

router = APIRouter(prefix="/api/v1", tags=["webauthn"])

# Create DB tables on first import (bootstrap)
Base.metadata.create_all(bind=engine)

rp = PublicKeyCredentialRpEntity(id=settings.RP_ID, name=settings.RP_NAME)
server = Fido2Server(rp)  # attestation=None by default

# ---------- Helpers ----------
def get_user(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).one_or_none()

def _cred_descriptor_from_db(cred: Credential) -> PublicKeyCredentialDescriptor:
    # For register/authenticate *begin* (exclude/allow lists)
    return PublicKeyCredentialDescriptor(type="public-key", id=cred.credential_id)

def _attested_from_db(cred: Credential) -> AttestedCredentialData:
    """
    Build AttestedCredentialData for authenticate_complete.
    We stored the COSE public key bytes in Credential.public_key.
    """
    # public_key is COSE (CBOR) bytes -> dict -> CoseKey
    cose_map = cbor2.loads(cred.public_key)
    cose_key = CoseKey.parse(cose_map)
    aaguid = Aaguid.parse(cred.aaguid) if cred.aaguid else Aaguid.NONE
    return AttestedCredentialData.create(aaguid=aaguid, credential_id=cred.credential_id, public_key=cose_key)

# ---------- Health ----------
@router.get("/health")
def health():
    return {"status": "ok"}

# ---------- Registration ----------
@router.post("/register/start")
async def register_start(payload: dict):
    username = payload.get("username")
    display_name = payload.get("displayName") or username
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    # Ensure user exists; collect already-registered descriptors
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            user = User(username=username, display_name=display_name)
            db.add(user)
            db.flush()  # get user.id

        uid = int(user.id)  # capture before session closes
        existing_desc = [_cred_descriptor_from_db(c) for c in user.credentials]

    user_entity = PublicKeyCredentialUserEntity(id=str(uid).encode(), name=username, display_name=display_name)

    # fido2 v2.0: use register_begin(..., credentials=existing_desc, resident_key_requirement=..., user_verification=..., authenticator_attachment=...)
    options, state = server.register_begin(
        user=user_entity,
        credentials=existing_desc,  # becomes excludeCredentials in options
        resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        user_verification=UserVerificationRequirement.REQUIRED,
        authenticator_attachment=None,  # allow both platform/cross-platform
    )

    # Store the state safely: CBOR-encode (handles bytes) then base64url
    state_blob = cbor2.dumps(state)
    set_state("reg", username, {"state": websafe_encode(state_blob), "user_id": uid})

    # options is a JsonDataObject → dict(options) is JSON compatible (v2.0 JSON mapping)
    return JSONResponse(dict(options))

@router.post("/register/finish")
async def register_finish(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    s = pop_state("reg", username)
    if not s:
        raise HTTPException(status_code=400, detail="registration state expired or missing")

    state_blob = websafe_decode(s["state"])
    state = cbor2.loads(state_blob)

    # Build RegistrationResponse mapping (standard JSON field names)
    reg_response = {
        "id": payload["id"],
        "rawId": websafe_decode(payload.get("rawId") or payload["id"]),
        "type": "public-key",
        "response": {
            "clientDataJSON": websafe_decode(payload["response"]["clientDataJSON"]),
            "attestationObject": websafe_decode(payload["response"]["attestationObject"]),
        },
        # optional:
        "clientExtensionResults": payload.get("clientExtensionResults", {}),
    }

    auth_data = server.register_complete(state, reg_response)

    # Persist credential
    with session_scope() as db:
        user = get_user(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="user not found")

        # COSE public key -> CBOR bytes for storage
        public_key_cbor = cbor2.dumps(dict(auth_data.credential_data.public_key))

        cred = Credential(
            user_id=user.id,
            credential_id=auth_data.credential_data.credential_id,
            public_key=public_key_cbor,
            sign_count=auth_data.counter,
            aaguid=str(auth_data.credential_data.aaguid),
            transports=",".join(payload.get("transports", []) or []),
        )
        db.add(cred)

    return {"status": "ok"}

# ---------- Authentication ----------
@router.post("/login/start")
async def login_start(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    with session_scope() as db:
        user = get_user(db, username)
        if not user or not user.credentials:
            raise HTTPException(status_code=404, detail="user or credentials not found")

        allowed_desc = [_cred_descriptor_from_db(c) for c in user.credentials]

    # fido2 v2.0: authenticate_begin(credentials=..., user_verification=...)
    request_options, state = server.authenticate_begin(
        credentials=allowed_desc,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    state_blob = cbor2.dumps(state)
    set_state("auth", username, {"state": websafe_encode(state_blob)})

    return JSONResponse(dict(request_options))

@router.post("/login/finish")
async def login_finish(payload: dict):
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    s = pop_state("auth", username)
    if not s:
        raise HTTPException(status_code=400, detail="authentication state expired or missing")

    state_blob = websafe_decode(s["state"])
    state = cbor2.loads(state_blob)

    cred_id = websafe_decode(payload.get("rawId") or payload["id"])

    # Build AuthenticationResponse mapping (standard JSON field names)
    authn_response = {
        "id": payload["id"],
        "rawId": cred_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": websafe_decode(payload["response"]["clientDataJSON"]),
            "authenticatorData": websafe_decode(payload["response"]["authenticatorData"]),
            "signature": websafe_decode(payload["response"]["signature"]),
            "userHandle": websafe_decode(payload["response"]["userHandle"]) if payload["response"].get("userHandle") else None,
        },
        "clientExtensionResults": payload.get("clientExtensionResults", {}),
    }

    # Load the single matching credential from DB and create AttestedCredentialData
    with session_scope() as db:
        cred = db.query(Credential).filter(Credential.credential_id == cred_id).one_or_none()
        if not cred:
            raise HTTPException(status_code=404, detail="credential not found")

        attested = _attested_from_db(cred)

        # v2.0: authenticate_complete(state, credentials=[AttestedCredentialData], response)
        result = server.authenticate_complete(state, [attested], authn_response)

        # Update sign counter and last used timestamp
        cred.sign_count = result.counter
        cred.last_used_at = datetime.datetime.utcnow()

        user = db.query(User).filter(User.id == cred.user_id).one()
        token = issue_token(sub=user.username)

    return {"status": "ok", "token": token}
