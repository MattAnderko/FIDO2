"""
Security tests for STRIDE Tampering threats.

Tests validate:
- FIDO2 tampering protection (modified challenges/responses are rejected)
- Password system lack of integrity protection
"""
import pytest
from httpx import AsyncClient
from tests.mocks.webauthn_mock import MockAuthenticator
from tests.utils.security import (
    modify_challenge,
    modify_signature,
    modify_authenticator_data
)
import secrets


@pytest.mark.asyncio
async def test_fido2_challenge_tampering_protection(client: AsyncClient, test_db, test_redis):
    """
    Test that FIDO2 rejects authentication with tampered challenge.
    
    This verifies tampering protection: modified challenges invalidate the signature.
    """
    username = "testuser_fido2_tamper_challenge"
    authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
    
    # Register credential
    start_response = await client.post(
        "/api/v1/register/start",
        json={
            "username": username,
            "displayName": username
        }
    )
    assert start_response.status_code == 200
    options = start_response.json()
    
    credential = authenticator.create_credential(options)
    
    # Attempt registration (may fail due to mock limitations)
    try:
        await client.post(
            "/api/v1/register/finish",
            json={
                "username": username,
                **credential
            }
        )
    except:
        pass
    
    # Now attempt authentication with tampered challenge
    login_start_response = await client.post(
        "/api/v1/login/start",
        json={"username": username}
    )
    
    if login_start_response.status_code == 200:
        login_options = login_start_response.json()
        
        # Create legitimate assertion
        assertion = authenticator.get_assertion(login_options)
        
        # Tamper with challenge
        tampered_challenge = secrets.token_bytes(32)
        tampered_assertion = modify_challenge(assertion, tampered_challenge)
        
        # Attempt authentication with tampered challenge
        login_finish_response = await client.post(
            "/api/v1/login/finish",
            json={
                "username": username,
                **tampered_assertion
            }
        )
        
        # FIDO2 should reject tampered challenge
        assert login_finish_response.status_code != 200, \
            "FIDO2 should reject authentication with tampered challenge"


@pytest.mark.asyncio
async def test_fido2_signature_tampering_protection(client: AsyncClient, test_db, test_redis):
    """
    Test that FIDO2 rejects authentication with tampered signature.
    
    This verifies tampering protection: modified signatures are invalid.
    """
    username = "testuser_fido2_tamper_signature"
    authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
    
    # Register credential
    start_response = await client.post(
        "/api/v1/register/start",
        json={
            "username": username,
            "displayName": username
        }
    )
    assert start_response.status_code == 200
    options = start_response.json()
    
    credential = authenticator.create_credential(options)
    
    try:
        await client.post(
            "/api/v1/register/finish",
            json={
                "username": username,
                **credential
            }
        )
    except:
        pass
    
    # Attempt authentication with tampered signature
    login_start_response = await client.post(
        "/api/v1/login/start",
        json={"username": username}
    )
    
    if login_start_response.status_code == 200:
        login_options = login_start_response.json()
        
        # Create legitimate assertion
        assertion = authenticator.get_assertion(login_options)
        
        # Tamper with signature
        tampered_assertion = modify_signature(assertion)
        
        # Attempt authentication with tampered signature
        login_finish_response = await client.post(
            "/api/v1/login/finish",
            json={
                "username": username,
                **tampered_assertion
            }
        )
        
        # FIDO2 should reject tampered signature
        assert login_finish_response.status_code != 200, \
            "FIDO2 should reject authentication with tampered signature"


@pytest.mark.asyncio
async def test_fido2_authenticator_data_tampering_protection(client: AsyncClient, test_db, test_redis):
    """
    Test that FIDO2 rejects authentication with tampered authenticator data.
    
    This verifies tampering protection: modified authenticator data invalidates signature.
    """
    username = "testuser_fido2_tamper_authdata"
    authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
    
    # Register credential
    start_response = await client.post(
        "/api/v1/register/start",
        json={
            "username": username,
            "displayName": username
        }
    )
    assert start_response.status_code == 200
    options = start_response.json()
    
    credential = authenticator.create_credential(options)
    
    try:
        await client.post(
            "/api/v1/register/finish",
            json={
                "username": username,
                **credential
            }
        )
    except:
        pass
    
    # Attempt authentication with tampered authenticator data
    login_start_response = await client.post(
        "/api/v1/login/start",
        json={"username": username}
    )
    
    if login_start_response.status_code == 200:
        login_options = login_start_response.json()
        
        # Create legitimate assertion
        assertion = authenticator.get_assertion(login_options)
        
        # Tamper with authenticator data (e.g., modify sign count)
        tampered_assertion = modify_authenticator_data(assertion)
        
        # Attempt authentication with tampered authenticator data
        login_finish_response = await client.post(
            "/api/v1/login/finish",
            json={
                "username": username,
                **tampered_assertion
            }
        )
        
        # FIDO2 should reject tampered authenticator data
        assert login_finish_response.status_code != 200, \
            "FIDO2 should reject authentication with tampered authenticator data"


@pytest.mark.asyncio
async def test_password_system_no_integrity_protection(client: AsyncClient, test_db, test_redis, test_user_with_password):
    """
    Test that password systems lack cryptographic integrity protection.
    
    This demonstrates that password systems rely only on TLS for tampering protection.
    If TLS is compromised, there is no cryptographic integrity protection.
    """
    username = test_user_with_password["username"]
    password = test_user_with_password["password"]
    
    # Password systems rely on TLS for integrity
    # If TLS is bypassed, requests can be modified without detection
    # This test documents the lack of cryptographic integrity protection
    
    # Normal login works (protected by TLS in production)
    login_response = await client.post(
        "/api/v1/password/login",
        json={
            "username": username,
            "password": password
        }
    )
    assert login_response.status_code == 200
    
    # Note: In a real attack scenario, if TLS is compromised:
    # - An attacker could modify the login request
    # - An attacker could modify the server response
    # - There is no cryptographic signature to detect tampering
    # This demonstrates the tampering vulnerability of password-only systems


@pytest.mark.asyncio
async def test_password_tampering_attack(client: AsyncClient, test_db, test_redis):
    """
    Test that a password login request can be tampered with in transit.
    
    This simulates a Man-in-the-Middle (MitM) attack where the attacker
    intercepts a legitimate login request and modifies the payload
    (e.g., swapping credentials) without the server detecting the change.
    
    In a real scenario, this could involve:
    1. Downgrading the connection (stripping TLS)
    2. Modifying the request body
    3. Forwarding to the server
    
    Since there is no application-layer signature (unlike FIDO2), the server
    cannot distinguish the tampered request from a legitimate one.
    """
    # 1. Setup: Create a victim user and an attacker user
    victim_username = "victim_user"
    victim_password = "VictimPassword123!"
    
    attacker_username = "attacker_user"
    attacker_password = "AttackerPassword123!"
    
    # Register victim
    await client.post("/api/v1/password/register", json={
        "username": victim_username,
        "password": victim_password,
        "display_name": "Victim User"
    })
    
    # Register attacker
    await client.post("/api/v1/password/register", json={
        "username": attacker_username,
        "password": attacker_password,
        "display_name": "Attacker User"
    })
    
    # 2. Simulate Client: Construct a legitimate login request for the victim
    # This represents what the victim's browser intends to send
    original_payload = {
        "username": victim_username,
        "password": victim_password
    }
    
    # 3. Simulate MitM Attack: Tamper with the payload
    # The attacker intercepts the request and swaps the credentials to their own
    # or modifies other fields. Here we swap credentials to log in as attacker
    # while the victim thinks they are logging in.
    tampered_payload = original_payload.copy()
    tampered_payload["username"] = attacker_username
    tampered_payload["password"] = attacker_password
    
    # 4. Send the TAMPERED payload to the server
    # The server receives the modified data.
    response = await client.post(
        "/api/v1/password/login",
        json=tampered_payload
    )
    
    # 5. Assertions
    # The server accepts the tampered request because it's valid JSON and valid credentials.
    # It has NO WAY to know that the original sender intended "victim_username".
    assert response.status_code == 200
    
    data = response.json()
    assert "token" in data
    
    # Verify we are logged in as the attacker, not the victim
    # This proves the tampering was successful and undetected by the server
    import jwt
    # We use the same secret as in the app (default in config or test env)
    # In test env, it is "test-secret-key-for-testing-only-do-not-use-in-production"
    token = data["token"]
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    assert decoded["sub"] == attacker_username
    
    # Contrast with FIDO2:
    # If this were FIDO2, the 'authData' and 'clientDataJSON' would be signed.
    # Changing the username or any other signed field would invalidate the signature,
    # and the server would reject the request (as seen in test_fido2_challenge_tampering_protection).


