"""Application settings.

Values come from (highest priority first):
  1. Environment variables starting with PCAPMAN_
  2. A local ".env" file
  3. The defaults written below
"""
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# apps/backend/  (this file is apps/backend/app/core/config.py)
BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PCAPMAN_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "PCAP-MAN"
    app_version: str = "0.1.0"
    environment: str = "development"

    # Local-first: only listen on this computer, never on the network.
    host: str = "127.0.0.1"
    port: int = 8000

    log_level: str = "INFO"
    log_format: str = "console"  # "console" or "json"

    # Empty means "use the default SQLite file inside <backend>/data/".
    database_url: str = ""
    data_directory: Path | None = None

    # Create/update the database structure automatically when the backend starts.
    auto_migrate: bool = True
    max_upload_size_bytes: int = 1_073_741_824

    # Who may call the API from a browser context (Vite dev server + Tauri).
    cors_origins: list[str] = [
        "http://localhost:1420",
        "http://127.0.0.1:1420",
        "tauri://localhost",
        "http://tauri.localhost",
    ]

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return value

    @field_validator("log_format")
    @classmethod
    def _check_log_format(cls, value: str) -> str:
        value = value.lower()
        if value not in {"console", "json"}:
            raise ValueError("log_format must be 'console' or 'json'")
        return value

    @property
    def data_dir(self) -> Path:
        return self.data_directory or BACKEND_DIR / "data"

    @property
    def evidence_dir(self) -> Path:
        directory = self.data_dir / "evidence"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{(self.data_dir / 'pcapman.db').as_posix()}"


@lru_cache
def get_settings() -> Settings:
    """Load settings once and reuse them everywhere."""
    return Settings()
