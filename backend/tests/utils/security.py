"""
Security testing utilities for STRIDE threat validation.
"""
from typing import Dict, Any, Optional
from fido2.utils import websafe_encode, websafe_decode
import cbor2
import secrets
import hashlib


def modify_challenge(response: Dict[str, Any], new_challenge: bytes) -> Dict[str, Any]:
    """
    Modify the challenge in a WebAuthn response to test tampering resistance.
    
    Args:
        response: Original WebAuthn response
        new_challenge: New challenge bytes to use
    
    Returns:
        Modified response with tampered challenge
    """
    modified = response.copy()
    
    # Decode clientDataJSON
    client_data_bytes = websafe_decode(modified["response"]["clientDataJSON"])
    client_data_dict = cbor2.loads(client_data_bytes)
    
    # Modify challenge
    client_data_dict[b"challenge"] = websafe_encode(new_challenge)
    
    # Re-encode
    modified["response"]["clientDataJSON"] = websafe_encode(cbor2.dumps(client_data_dict))
    
    return modified


def modify_signature(response: Dict[str, Any], new_signature: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Modify the signature in a WebAuthn authentication response.
    
    Args:
        response: Original WebAuthn authentication response
        new_signature: New signature bytes (random if None)
    
    Returns:
        Modified response with tampered signature
    """
    modified = response.copy()
    
    if new_signature is None:
        new_signature = secrets.token_bytes(64)  # Random signature
    
    modified["response"]["signature"] = websafe_encode(new_signature)
    
    return modified


def modify_authenticator_data(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Modify authenticator data in a WebAuthn response.
    
    Args:
        response: Original WebAuthn authentication response
    
    Returns:
        Modified response with tampered authenticator data
    """
    modified = response.copy()
    
    # Decode authenticator data
    auth_data_bytes = websafe_decode(modified["response"]["authenticatorData"])
    
    # Modify sign count (increment it incorrectly)
    # Authenticator data format: RP ID hash (32) + flags (1) + sign count (4)
    if len(auth_data_bytes) >= 37:
        # Modify sign count bytes
        tampered_auth_data = bytearray(auth_data_bytes)
        # Set sign count to a different value
        tampered_auth_data[33:37] = (999999).to_bytes(4, 'big')
        modified["response"]["authenticatorData"] = websafe_encode(bytes(tampered_auth_data))
    
    return modified


def create_malicious_origin_response(
    response: Dict[str, Any],
    malicious_rp_id: str
) -> Dict[str, Any]:
    """
    Create a response with a malicious origin/RP ID for testing origin binding.
    
    Args:
        response: Original WebAuthn response
        malicious_rp_id: RP ID to use in the malicious response
    
    Returns:
        Response with modified origin/RP ID
    """
    modified = response.copy()
    
    # Modify clientDataJSON to use malicious origin
    client_data_bytes = websafe_decode(modified["response"]["clientDataJSON"])
    client_data_dict = cbor2.loads(client_data_bytes)
    
    # Change origin
    client_data_dict[b"origin"] = f"https://{malicious_rp_id}".encode()
    
    # Re-encode
    modified["response"]["clientDataJSON"] = websafe_encode(cbor2.dumps(client_data_dict))
    
    # Also modify authenticator data RP ID hash if present
    if "authenticatorData" in modified["response"]:
        auth_data_bytes = websafe_decode(modified["response"]["authenticatorData"])
        if len(auth_data_bytes) >= 32:
            # Replace RP ID hash
            malicious_rp_id_hash = hashlib.sha256(malicious_rp_id.encode()).digest()
            tampered_auth_data = bytearray(auth_data_bytes)
            tampered_auth_data[0:32] = malicious_rp_id_hash
            modified["response"]["authenticatorData"] = websafe_encode(bytes(tampered_auth_data))
    
    return modified


def extract_credential_id_from_response(response: Dict[str, Any]) -> bytes:
    """
    Extract credential ID from a WebAuthn response.
    
    Args:
        response: WebAuthn response
    
    Returns:
        Credential ID bytes
    """
    raw_id = response.get("rawId") or response.get("id")
    if isinstance(raw_id, str):
        return websafe_decode(raw_id)
    return raw_id


def create_replay_attack_response(original_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create an exact copy of a response for replay attack testing.
    
    Args:
        original_response: Original WebAuthn response
    
    Returns:
        Identical response (replay)
    """
    # Deep copy the response
    import copy
    return copy.deepcopy(original_response)

