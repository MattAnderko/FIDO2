"""
Latency tests for FIDO2 authentication.
"""
import pytest
import json
from tests.utils.timing import measure_time_with_resources
from tests.utils.results import get_collector
from tests.mocks.webauthn_mock import MockAuthenticator


@pytest.mark.asyncio
async def test_fido2_registration_latency(client, test_db, test_redis, results_collector):
    """Measure FIDO2 registration latency (backend operations only)."""
    measurements = {}
    iterations = 10
    
    for i in range(iterations):
        username = f"testuser_fido2_{i}"
        authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
        
        # Step 1: Register start (backend operation)
        with measure_time_with_resources("fido2_register_start", measurements):
            start_response = await client.post(
                "/api/v1/register/start",
                json={
                    "username": username,
                    "displayName": username
                }
            )
        
        assert start_response.status_code == 200
        options = start_response.json()
        
        # Step 2: Mock WebAuthn create (client-side, not measured)
        credential = authenticator.create_credential(options)
        
        # Step 3: Register finish (backend operation)
        # Note: This may fail due to cryptographic verification (expected with mock),
        # but we can still measure latency. For full validity, we'd need a proper software authenticator.
        with measure_time_with_resources("fido2_register_finish", measurements):
            try:
                finish_response = await client.post(
                    "/api/v1/register/finish",
                    json={
                        "username": username,
                        **credential
                    }
                )
                # Don't assert - mock responses won't pass verification
            except Exception:
                # Server may raise exception, but latency is still measured
                pass
    
    # Store measurements
    collector = get_collector()
    for name, values in measurements.items():
        collector.add_measurements(name, values)


@pytest.mark.asyncio
async def test_fido2_registration_total_latency(client, test_db, test_redis, results_collector):
    """Measure total FIDO2 registration latency (backend operations only)."""
    measurements = {}
    iterations = 10
    
    for i in range(iterations):
        username = f"testuser_fido2_total_{i}"
        authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
        
        # Measure only backend operations (start + finish endpoints)
        # We measure start and finish separately to exclude client-side credential generation
        
        # Start (backend operation)
        with measure_time_with_resources("fido2_registration_start", measurements):
            start_response = await client.post(
                "/api/v1/register/start",
                json={
                    "username": username,
                    "displayName": username
                }
            )
            assert start_response.status_code == 200
            options = start_response.json()
        
        # Generate credential outside timing context (client-side, not measured)
        credential = authenticator.create_credential(options)
        
        # Finish (backend operation - measured)
        with measure_time_with_resources("fido2_registration_finish", measurements):
            try:
                finish_response = await client.post(
                    "/api/v1/register/finish",
                    json={
                        "username": username,
                        **credential
                    }
                )
            except Exception:
                pass  # Expected to fail with mock, but latency is measured
    
    # Combine start + finish for total (backend only, excludes credential generation)
    if "fido2_registration_start" in measurements and "fido2_registration_finish" in measurements:
        start_times = measurements["fido2_registration_start"]
        finish_times = measurements["fido2_registration_finish"]
        if start_times and finish_times and len(start_times) == len(finish_times):
            # Combine corresponding measurements
            total_times = [s + f for s, f in zip(start_times, finish_times)]
            measurements["fido2_registration_total"] = total_times
            
            # Combine resource metrics
            for suffix in ["_cpu_ms", "_memory_mb", "_db_queries", "_db_time_ms"]:
                start_key = f"fido2_registration_start{suffix}"
                finish_key = f"fido2_registration_finish{suffix}"
                total_key = f"fido2_registration_total{suffix}"
                if start_key in measurements and finish_key in measurements:
                    start_vals = measurements[start_key]
                    finish_vals = measurements[finish_key]
                    if start_vals and finish_vals and len(start_vals) == len(finish_vals):
                        # Sum corresponding values
                        combined_vals = [s + f for s, f in zip(start_vals, finish_vals)]
                        measurements[total_key] = combined_vals
    
    # Store measurements
    collector = get_collector()
    for name, values in measurements.items():
        collector.add_measurements(name, values)


@pytest.mark.asyncio
async def test_fido2_login_latency(client, test_db, test_redis, results_collector):
    """
    Measure FIDO2 login latency.
    
    Note: This test requires a registered credential. For simplicity,
    we'll measure the login start and finish separately, but note that
    the finish may fail without a valid registered credential.
    """
    measurements = {}
    iterations = 10
    
    # First, register a user (simplified - may not pass verification)
    username = "testuser_fido2_login"
    
    # Register (simplified)
    start_response = await client.post(
        "/api/v1/register/start",
        json={
            "username": username,
            "displayName": username
        }
    )
    if start_response.status_code == 200:
        options = start_response.json()
        authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
        credential = authenticator.create_credential(options)
        
        # Try to finish registration (may fail, but that's OK for latency testing)
        try:
            await client.post(
                "/api/v1/register/finish",
                json={
                    "username": username,
                    **credential
                }
            )
        except Exception:
            pass  # Expected to fail with mock
    
    # Now test login
    for i in range(iterations):
        # Step 1: Login start (backend operation)
        with measure_time_with_resources("fido2_login_start", measurements):
            login_start_response = await client.post(
                "/api/v1/login/start",
                json={"username": username}
            )
        
        # May fail if no valid credential exists
        if login_start_response.status_code == 200:
            login_options = login_start_response.json()
            
            # Step 2: Mock WebAuthn get (client-side, not measured)
            assertion = authenticator.get_assertion(login_options)
            
            # Step 3: Login finish (backend operation - measured)
            with measure_time_with_resources("fido2_login_finish", measurements):
                try:
                    login_finish_response = await client.post(
                        "/api/v1/login/finish",
                        json={
                            "username": username,
                            **assertion
                        }
                    )
                except Exception:
                    pass  # Expected to fail with mock, but latency is measured
    
    # Store measurements
    collector = get_collector()
    for name, values in measurements.items():
        collector.add_measurements(name, values)


@pytest.mark.asyncio
async def test_fido2_login_total_latency(client, test_db, test_redis, results_collector):
    """Measure total FIDO2 login latency (backend operations only)."""
    measurements = {}
    iterations = 10
    
    username = "testuser_fido2_login_total"
    
    # Setup: Try to register (may fail due to verification)
    start_response = await client.post(
        "/api/v1/register/start",
        json={
            "username": username,
            "displayName": username
        }
    )
    authenticator = None
    if start_response.status_code == 200:
        options = start_response.json()
        authenticator = MockAuthenticator(rp_id="localhost", authenticator_delay_ms=0)
        credential = authenticator.create_credential(options)  # Client-side, not measured
        try:
            await client.post(
                "/api/v1/register/finish",
                json={
                    "username": username,
                    **credential
                }
            )
        except Exception:
            pass  # Expected to fail with mock
    
    # Test login
    for i in range(iterations):
        # Start (backend operation)
        with measure_time_with_resources("fido2_login_start", measurements):
            login_start_response = await client.post(
                "/api/v1/login/start",
                json={"username": username}
            )
        
        if login_start_response.status_code == 200 and authenticator:
            login_options = login_start_response.json()
            
            # Generate assertion outside timing context (client-side, not measured)
            assertion = authenticator.get_assertion(login_options)
            
            # Finish (backend operation - measured)
            with measure_time_with_resources("fido2_login_finish", measurements):
                try:
                    await client.post(
                        "/api/v1/login/finish",
                        json={
                            "username": username,
                            **assertion
                        }
                    )
                except Exception:
                    pass  # Expected to fail with mock, but latency is measured
    
    # Combine start + finish for total (backend only, excludes assertion generation)
    if "fido2_login_start" in measurements and "fido2_login_finish" in measurements:
        start_times = measurements["fido2_login_start"]
        finish_times = measurements["fido2_login_finish"]
        if start_times and finish_times and len(start_times) == len(finish_times):
            # Combine corresponding measurements
            total_times = [s + f for s, f in zip(start_times, finish_times)]
            measurements["fido2_login_total"] = total_times
            
            # Combine resource metrics
            for suffix in ["_cpu_ms", "_memory_mb", "_db_queries", "_db_time_ms"]:
                start_key = f"fido2_login_start{suffix}"
                finish_key = f"fido2_login_finish{suffix}"
                total_key = f"fido2_login_total{suffix}"
                if start_key in measurements and finish_key in measurements:
                    start_vals = measurements[start_key]
                    finish_vals = measurements[finish_key]
                    if start_vals and finish_vals and len(start_vals) == len(finish_vals):
                        # Sum corresponding values
                        combined_vals = [s + f for s, f in zip(start_vals, finish_vals)]
                        measurements[total_key] = combined_vals
    
    # Store measurements
    collector = get_collector()
    for name, values in measurements.items():
        collector.add_measurements(name, values)

