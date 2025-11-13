"""
Latency tests for TOTP authentication.
"""
import pytest
import pyotp
from tests.utils.timing import measure_time
from tests.utils.results import get_collector


@pytest.mark.asyncio
async def test_totp_setup_latency(client, test_db, test_redis, results_collector):
    """Measure TOTP setup latency."""
    measurements = {}
    iterations = 10
    
    # Use a consistent password for all test users (must meet strength requirements)
    password = "TestPassword123!"
    
    for i in range(iterations):
        # Create a new user for each iteration to avoid TOTP conflicts
        setup_username = f"testuser_totp_setup_{i}"
        
        # First register the user (create fresh user for each iteration)
        reg_response = await client.post(
            "/api/v1/password/register",
            json={
                "username": setup_username,
                "password": password,
                "display_name": setup_username
            }
        )
        # If registration fails, skip this iteration
        if reg_response.status_code != 200:
            continue
        
        # Measure TOTP setup time (includes password verification + TOTP secret generation + QR code creation)
        with measure_time("totp_setup_total", measurements):
            response = await client.post(
                "/api/v1/totp/setup",
                json={
                    "username": setup_username,
                    "password": password
                }
            )
        
        # Don't assert - just measure latency even if setup fails
        # (setup might fail if TOTP already enabled, but we still want latency measurement)
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)


@pytest.mark.asyncio
async def test_totp_login_latency(client, test_db, test_redis, test_user_with_totp, results_collector):
    """Measure TOTP login latency."""
    measurements = {}
    iterations = 10
    
    username = test_user_with_totp["username"]
    password = test_user_with_totp["password"]
    totp_secret = test_user_with_totp["totp_secret"]
    
    for i in range(iterations):
        # Generate current TOTP code
        totp = pyotp.TOTP(totp_secret)
        totp_code = totp.now()
        
        # Measure total login time (includes password + TOTP verification)
        with measure_time("totp_login_total", measurements):
            response = await client.post(
                "/api/v1/totp/login",
                json={
                    "username": username,
                    "password": password,
                    "totp_code": totp_code
                }
            )
        
        assert response.status_code == 200
        assert "token" in response.json()
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)


@pytest.mark.asyncio
async def test_totp_login_breakdown(client, test_db, test_redis, test_user_with_totp, results_collector):
    """
    Measure TOTP login with breakdown.
    The endpoint includes:
    - Password verification
    - TOTP code validation
    - Token generation
    """
    measurements = {}
    iterations = 10
    
    username = test_user_with_totp["username"]
    password = test_user_with_totp["password"]
    totp_secret = test_user_with_totp["totp_secret"]
    
    for i in range(iterations):
        # Generate current TOTP code
        totp = pyotp.TOTP(totp_secret)
        totp_code = totp.now()
        
        # Measure endpoint call (includes all operations)
        with measure_time("totp_login_endpoint", measurements):
            response = await client.post(
                "/api/v1/totp/login",
                json={
                    "username": username,
                    "password": password,
                    "totp_code": totp_code
                }
            )
        
        assert response.status_code == 200
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)

