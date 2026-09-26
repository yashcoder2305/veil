# Dockerfile
# VEIL — Verifiable Execution Isolation Layer
#
# Single image used for both services (api and dashboard).
# The CMD is overridden per-service in docker-compose.yml.
#
# Build:
#   docker build -t veil .
#
# Run API:
#   docker run -p 8000:8000 --env-file .env veil \
#       uvicorn api.main:app --host 0.0.0.0 --port 8000
#
# Run Dashboard:
#   docker run -p 8501:8501 --env-file .env veil \
#       streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached until requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Install the veil package in editable mode so imports resolve correctly
RUN pip install --no-cache-dir -e .

# Create data directory for audit and threat JSONL files
RUN mkdir -p data

# Default command — override in docker-compose
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
