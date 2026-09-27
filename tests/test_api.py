"""
tests/test_api.py

Unit tests for FastAPI gateway endpoints including lightweight health check.
"""

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_lightweight_health_check():
    """Verify GET /health returns 200 OK and expected JSON schema."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok", "service": "VEIL"}


def test_detailed_health_check():
    """Verify GET /api/v1/health continues to work as expected."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "components" in data
