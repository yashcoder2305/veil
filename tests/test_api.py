"""
tests/test_api.py

Unit tests for FastAPI gateway endpoints including lightweight health check.
"""

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_lightweight_health_check():
    """Verify GET and HEAD /health return 200 OK for uptime monitoring services like UptimeRobot."""
    # Test GET
    get_res = client.get("/health")
    assert get_res.status_code == 200
    assert get_res.json() == {"status": "ok", "service": "VEIL"}

    # Test HEAD (used by default by UptimeRobot)
    head_res = client.head("/health")
    assert head_res.status_code == 200



def test_detailed_health_check():
    """Verify GET /api/v1/health continues to work as expected."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "components" in data
