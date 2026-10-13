from fastapi.testclient import TestClient
from apps.api.config import Settings


def test_root_endpoint(client: TestClient):
    """Test that root endpoint returns online status and project baseline."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "IRYX"
    assert data["status"] == "online"
    assert "The Piercing Eye of Incident Response" in data["baseline"]


def test_health_endpoint(client: TestClient):
    """Test that health check endpoint verifies storage and configuration."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["storage_ready"] is True
    assert data["database_configured"] is True


def test_platform_info_endpoint(client: TestClient):
    """Test that metadata endpoint returns hackathon and supported DFIR domains."""
    response = client.get("/api/v1/info")
    assert response.status_code == 200
    data = response.json()
    assert data["hackathon"] == "Nebius × NVIDIA Global AI Hackathon 2026"
    assert data["track"] == "Best Apps and Agents"
    assert "Memory (Volatility 3)" in data["supported_forensic_domains"]
    assert "Threat Intel (Tavily)" in data["supported_forensic_domains"]


def test_settings_storage_path(test_settings: Settings):
    """Test that storage path exists and is an absolute directory."""
    path = test_settings.storage_path
    assert path.exists()
    assert path.is_dir()
