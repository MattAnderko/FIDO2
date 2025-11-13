#!/bin/bash
# Helper script to run latency tests with proper environment setup

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Set test environment variables
export DATABASE_URL="sqlite:///:memory:"
export REDIS_URL="redis://localhost:6379/0"
export RP_ID="localhost"
export RP_NAME="Test RP"
export JWT_SECRET="test-secret-key-for-testing-only-do-not-use-in-production"
export ENV="test"
export ALLOWED_ORIGINS="http://localhost:8080"

# Run pytest with provided arguments or default
if [ $# -eq 0 ]; then
    pytest tests/ -v --asyncio-mode=auto
else
    pytest tests/ -v --asyncio-mode=auto "$@"
fi


