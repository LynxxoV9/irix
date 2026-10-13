from functools import lru_cache
from pathlib import Path
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for IRYX backend application."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Project metadata
    PROJECT_NAME: str = "IRYX"
    PROJECT_BASELINE: str = "The Piercing Eye of Incident Response"
    VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "production", "testing"] = "development"
    LOG_LEVEL: str = "INFO"

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite:///./data/iryx.db"

    # Evidence storage
    STORAGE_DIR: str = "./data/artifacts"

    # MCP Server
    MCP_SERVER_HOST: str = "0.0.0.0"
    MCP_SERVER_PORT: int = 8001
    MCP_SERVER_URL: str = "http://localhost:8001"

    # Nebius / NVIDIA Nemotron LLM
    NEBIUS_API_KEY: str = ""
    NEBIUS_BASE_URL: str = "https://api.tokenfactory.nebius.ai/v1"
    NEBIUS_FAST_MODEL: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    NEBIUS_DEEP_MODEL: str = "nvidia/llama-3.1-nemotron-70b-instruct"

    # Threat Intelligence
    TAVILY_API_KEY: str = ""

    @property
    def storage_path(self) -> Path:
        """Return resolved Path to the storage directory and ensure it exists."""
        path = Path(self.STORAGE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache()
def get_settings() -> Settings:
    """Return a cached singleton instance of Settings."""
    return Settings()
