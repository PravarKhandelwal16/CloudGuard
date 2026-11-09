import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    """Secure application settings loaded strictly from runtime environment variables."""
    app_name: str = os.getenv("APP_NAME", "CleanSecureService")
    port: int = int(os.getenv("PORT", "8000"))
    environment: str = os.getenv("ENVIRONMENT", "production")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Secrets are dynamically injected via environment variables or secret manager
    database_url: str = os.getenv("DATABASE_URL", "")
    api_key: str = os.getenv("API_KEY", "")


config = AppConfig()

