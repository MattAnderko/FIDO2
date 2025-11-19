"""
Latency tests for password authentication.
"""
import pytest
import json
from tests.utils.timing import measure_time_with_resources
from tests.utils.results import get_collector


@pytest.mark.asyncio
async def test_password_registration_latency(client, test_db, test_redis, results_collector):
    """Measure password registration latency."""
    measurements = {}
    iterations = 10
    
    for i in range(iterations):
        username = f"testuser_pwd_{i}"
        
        # Measure total registration time
        with measure_time_with_resources("password_registration_total", measurements):
            response = await client.post(
                "/api/v1/password/register",
                json={
                    "username": username,
                    "password": "TestPassword123!",
                    "display_name": username
                }
            )
        
        assert response.status_code == 200
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)


@pytest.mark.asyncio
async def test_password_login_latency(client, test_db, test_redis, test_user_with_password, results_collector):
    """Measure password login latency."""
    measurements = {}
    iterations = 10
    username = test_user_with_password["username"]
    password = test_user_with_password["password"]
    
    for i in range(iterations):
        # Measure total login time
        with measure_time_with_resources("password_login_total", measurements):
            response = await client.post(
                "/api/v1/password/login",
                json={
                    "username": username,
                    "password": password
                }
            )
        
        assert response.status_code == 200
        assert "token" in response.json()
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)


@pytest.mark.asyncio
async def test_password_login_breakdown(client, test_db, test_redis, test_user_with_password, results_collector):
    """
    Measure password login with breakdown of operations.
    This test measures the endpoint latency which includes:
    - Database query time
    - Password verification time
    - Token generation time
    """
    measurements = {}
    iterations = 10
    username = test_user_with_password["username"]
    password = test_user_with_password["password"]
    
    for i in range(iterations):
        # Measure endpoint call (includes all operations)
        with measure_time_with_resources("password_login_endpoint", measurements):
            response = await client.post(
                "/api/v1/password/login",
                json={
                    "username": username,
                    "password": password
                }
            )
        
        assert response.status_code == 200
    
    # Store measurements
    collector = get_collector()
    for name, times in measurements.items():
        collector.add_measurements(name, times)


