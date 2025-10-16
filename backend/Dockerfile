# -------------------------------
# Backend Dockerfile (FastAPI + FIDO2)
# Compatible with fido2==2.0.0 (May 2025)
# -------------------------------
FROM python:3.11-slim

# Prevent Python from writing .pyc and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for psycopg2 & build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt ./

# Upgrade pip to ensure modern dependency resolver
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app

# Expose FastAPI default port
EXPOSE 8000

# Launch with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
