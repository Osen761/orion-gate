"""Runtime settings for standalone Orion Gate."""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings for standalone Orion Gate."""

    PORT: int = 8080
    ENVIRONMENT: str = "development"
    ALLOW_LOCALHOST_IN_PRODUCTION: bool = False
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000",
        validation_alias=AliasChoices("ORION_CORS_ALLOWED_ORIGINS", "CORS_ORIGINS"),
    )
    REDIS_URL: str = ""
    UPSTASH_REDIS_REST_URL: str = ""
    UPSTASH_REDIS_REST_TOKEN: str = ""
    ORION_CONNECTOR_CONNECT_TIMEOUT_SECONDS: int = 10
    ORION_CONNECTOR_QUERY_TIMEOUT_SECONDS: int = 60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
