"""
Mock WebAuthn authenticator for testing.
Generates valid WebAuthn registration and authentication responses using fido2 library.
"""
import time
from typing import Dict, Any, Optional
from fido2.client import CollectedClientData
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
from fido2.utils import websafe_encode
import cbor2


class MockAuthenticator:
    """
    Mock authenticator that simulates WebAuthn operations.
    
    Note: This is a simplified mock for latency testing. For full cryptographic
    validity, you would need to use fido2's software authenticator or a test device.
    For latency measurement purposes, we simulate the structure and timing.
    """
    
    def __init__(self, rp_id: str = "localhost", authenticator_delay_ms: int = 100):
        """
        Initialize mock authenticator.
        
        Args:
            rp_id: Relying Party ID
            authenticator_delay_ms: Simulated delay for authenticator operations (ms)
                Default 100ms represents typical hardware authenticator response time
                (based on empirical observations: USB security keys and platform 
                authenticators typically require 50-200ms for key generation/signing,
                user verification, and browser communication)
        """
        self.rp_id = rp_id
        self.authenticator_delay_ms = authenticator_delay_ms
        self.credentials: Dict[bytes, Dict[str, Any]] = {}  # credential_id -> credential data
    
    def simulate_delay(self):
        """Simulate authenticator processing delay."""
        if self.authenticator_delay_ms > 0:
            time.sleep(self.authenticator_delay_ms / 1000.0)
    
    def create_credential(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate WebAuthn credential creation (registration).
        
        Args:
            options: PublicKeyCredentialCreationOptions from server (as dict)
        
        Returns:
            Registration response compatible with WebAuthn API
        """
        self.simulate_delay()
        
        # Extract challenge from options (for latency testing, we don't need full parsing)
        # The options dict comes from the server as JSON-compatible dict
        challenge = options.get("challenge", "")
        if isinstance(challenge, str):
            from fido2.utils import websafe_decode
            challenge_bytes = websafe_decode(challenge)
        else:
            challenge_bytes = challenge
        
        # Create client data
        origin = f"https://{self.rp_id}"
        client_data = CollectedClientData.create(
            type="webauthn.create",
            challenge=challenge_bytes,
            origin=origin
        )
        
        # Generate credential ID
        import secrets
        credential_id = secrets.token_bytes(32)
        
        # For latency testing, we create a structure that matches the expected format
        # Note: This won't pass cryptographic verification, but allows us to measure
        # server-side processing time. For full validity, use fido2's software authenticator.
        
        # Create minimal attestation object structure
        # Format: { "fmt": "none", "attStmt": {}, "authData": bytes }
        import hashlib
        
        # Create authenticator data (simplified structure)
        # RP ID hash (32 bytes) + flags (1 byte) + sign count (4 bytes) + AAGUID (16 bytes) + credential
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = 0x41  # User present + Attested credential data
        sign_count = 0
        
        # AAGUID (all zeros for test)
        aaguid = b'\x00' * 16
        
        # Credential ID length (2 bytes) + credential ID + public key
        cred_id_len = len(credential_id)
        cred_id_len_bytes = cred_id_len.to_bytes(2, 'big')
        
        # Minimal COSE key (ES256) - using proper COSE key structure
        from fido2.cose import ES256
        public_key_cose = {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            -2: secrets.token_bytes(32),  # x
            -3: secrets.token_bytes(32),  # y
            3: ES256.ALGORITHM,  # alg: ES256
        }
        public_key_cbor = cbor2.dumps(public_key_cose)
        
        # Build authenticator data
        auth_data = (
            rp_id_hash +
            bytes([flags]) +
            sign_count.to_bytes(4, 'big') +
            aaguid +
            cred_id_len_bytes +
            credential_id +
            public_key_cbor
        )
        
        # Create attestation object
        att_obj = {
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data
        }
        
        # Encode attestation object
        attestation_object = cbor2.dumps(att_obj)
        
        # Build response
        response = {
            "id": websafe_encode(credential_id),
            "rawId": websafe_encode(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(bytes(client_data)),
                "attestationObject": websafe_encode(attestation_object),
            }
        }
        
        # Store credential for later use
        self.credentials[credential_id] = {
            "public_key": public_key_cose,
            "sign_count": 0,
            "credential_id": credential_id,
        }
        
        return response
    
    def get_assertion(
        self,
        options: Dict[str, Any],
        credential_id: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Simulate WebAuthn assertion (authentication).
        
        Args:
            options: PublicKeyCredentialRequestOptions from server (as dict)
            credential_id: Optional credential ID to use
        
        Returns:
            Authentication response compatible with WebAuthn API
        """
        self.simulate_delay()
        
        # Extract challenge from options (for latency testing, we don't need full parsing)
        challenge = options.get("challenge", "")
        if isinstance(challenge, str):
            from fido2.utils import websafe_decode
            challenge_bytes = websafe_decode(challenge)
        else:
            challenge_bytes = challenge
        
        # Use first credential if not specified
        if credential_id is None:
            if not self.credentials:
                raise ValueError("No credentials available")
            credential_id = list(self.credentials.keys())[0]
        
        if credential_id not in self.credentials:
            raise ValueError(f"Credential not found")
        
        cred_data = self.credentials[credential_id]
        
        # Create client data
        origin = f"https://{self.rp_id}"
        client_data = CollectedClientData.create(
            type="webauthn.get",
            challenge=challenge_bytes,
            origin=origin
        )
        
        # Increment sign count
        cred_data["sign_count"] += 1
        
        # Create authenticator data
        import hashlib
        
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = 0x05  # User present + User verified
        sign_count = cred_data["sign_count"]
        
        # Build authenticator data (without credential)
        auth_data = (
            rp_id_hash +
            bytes([flags]) +
            sign_count.to_bytes(4, 'big')
        )
        
        # Create signature (placeholder - won't pass verification but allows latency measurement)
        import secrets
        signature = secrets.token_bytes(64)  # Placeholder ECDSA signature
        
        # Build response
        response = {
            "id": websafe_encode(credential_id),
            "rawId": websafe_encode(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(bytes(client_data)),
                "authenticatorData": websafe_encode(auth_data),
                "signature": websafe_encode(signature),
                "userHandle": None,
            }
        }
        
        return response


def create_mock_registration_response(
    options: Dict[str, Any],
    rp_id: str = "localhost",
    delay_ms: int = 100
) -> Dict[str, Any]:
    """
    Create a mock WebAuthn registration response.
    
    Args:
        options: PublicKeyCredentialCreationOptions from server
        rp_id: Relying Party ID
        delay_ms: Simulated authenticator delay in milliseconds
    
    Returns:
        Registration response dict
    """
    authenticator = MockAuthenticator(rp_id=rp_id, authenticator_delay_ms=delay_ms)
    return authenticator.create_credential(options)


def create_mock_authentication_response(
    options: Dict[str, Any],
    credential_id: Optional[bytes] = None,
    rp_id: str = "localhost",
    delay_ms: int = 100
) -> Dict[str, Any]:
    """
    Create a mock WebAuthn authentication response.
    
    Args:
        options: PublicKeyCredentialRequestOptions from server
        credential_id: Optional credential ID to use
        rp_id: Relying Party ID
        delay_ms: Simulated authenticator delay in milliseconds
    
    Returns:
        Authentication response dict
    """
    authenticator = MockAuthenticator(rp_id=rp_id, authenticator_delay_ms=delay_ms)
    return authenticator.get_assertion(options, credential_id)

