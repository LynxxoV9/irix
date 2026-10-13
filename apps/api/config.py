from functools import lru_cache
from pathlib import Path
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ### Configuration centralisée d'IRYX avec support du fichier .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Métadonnées du projet (Cahier des charges)
    PROJECT_NAME: str = "IRYX"
    PROJECT_BASELINE: str = "The Piercing Eye of Incident Response"
    VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "production", "testing"] = "development"
    LOG_LEVEL: str = "INFO"

    # Serveur API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # Persistance (PostgreSQL en production, SQLite localement ou pour les tests)
    DATABASE_URL: str = "sqlite:///./data/iryx.db"

    # Répertoire de conservation sécurisée des preuves
    STORAGE_DIR: str = "./data/artifacts"

    # Serveur MCP
    MCP_SERVER_HOST: str = "0.0.0.0"
    MCP_SERVER_PORT: int = 8001
    MCP_SERVER_URL: str = "http://localhost:8001"

    ### =========================================================================
    ### PASSERELLE LLM PLUG & PLAY (RhodiumAI, Nebius Token Factory, Groq, etc.)
    ### =========================================================================
    ### Clé principale requise par l'utilisateur (nommée THE_API_KEY dans le .env)
    THE_API_KEY: str = ""
    ### Clé de compatibilité si l'utilisateur utilisait NEBIUS_API_KEY
    NEBIUS_API_KEY: str = ""

    ### URL de base pour les appels OpenAI-compatible (ex: https://api.rhodium.ai/v1 ou Nebius)
    LLM_BASE_URL: str = "https://api.rhodium.ai/v1"
    NEBIUS_BASE_URL: str = "https://api.tokenfactory.nebius.ai/v1"

    ### Modèle rapide (Fast tier) pour les synthèses courtes, le routing et la planification initiale
    LLM_FAST_MODEL: str = "meta-llama/Meta-Llama-3.1-8B-Instruct"
    NEBIUS_FAST_MODEL: str = "nvidia/llama-3.1-nemotron-70b-instruct"

    ### Modèle approfondi (Deep tier) pour la corrélation multi-sources et la vérification d'hypothèses
    LLM_DEEP_MODEL: str = "meta-llama/Meta-Llama-3.1-70B-Instruct"
    NEBIUS_DEEP_MODEL: str = "nvidia/llama-3.1-nemotron-70b-instruct"

    # Threat Intelligence externe
    TAVILY_API_KEY: str = ""

    @property
    def api_key(self) -> str:
        ### Priorise THE_API_KEY (définie par l'utilisateur), avec fallback sur NEBIUS_API_KEY
        return self.THE_API_KEY or self.NEBIUS_API_KEY

    @property
    def base_url(self) -> str:
        ### Retourne l'URL de base active
        return self.LLM_BASE_URL or self.NEBIUS_BASE_URL

    @property
    def fast_model(self) -> str:
        ### Modèle rapide actif
        return self.LLM_FAST_MODEL or self.NEBIUS_FAST_MODEL

    @property
    def deep_model(self) -> str:
        ### Modèle approfondi actif
        return self.LLM_DEEP_MODEL or self.NEBIUS_DEEP_MODEL

    @property
    def storage_path(self) -> Path:
        ### Chemin résolu du dossier de stockage avec création automatique si inexistant
        path = Path(self.STORAGE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache()
def get_settings() -> Settings:
    ### Instance singleton de la configuration avec mise en cache
    return Settings()
