from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from apps.api.app import app
from apps.api.config import get_settings, Settings
from apps.api.database import Base, get_db
import evidence.models  # Ensure all SQLAlchemy models are registered


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Fixture providing testing settings."""
    settings = get_settings()
    settings.ENVIRONMENT = "testing"
    settings.DATABASE_URL = "sqlite:///:memory:"
    return settings


@pytest.fixture(scope="function")
def test_engine():
    """Fixture providing an isolated in-memory SQLite engine with StaticPool."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_engine) -> Generator[Session, None, None]:
    """Fixture providing an isolated database session per test."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(test_engine) -> Generator[TestClient, None, None]:
    """Fixture providing FastAPI test client using the isolated test database."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
