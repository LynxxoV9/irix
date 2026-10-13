import pytest
from fastapi.testclient import TestClient
from apps.api.app import app
from apps.api.config import get_settings, Settings


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Fixture providing testing settings."""
    settings = get_settings()
    settings.ENVIRONMENT = "testing"
    settings.DATABASE_URL = "sqlite:///:memory:"
    return settings


@pytest.fixture(scope="session")
def client(test_settings: Settings) -> TestClient:
    """Fixture providing FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client
