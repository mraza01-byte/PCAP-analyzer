"""Checks that the migration files build exactly the tables the models describe."""
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

import app.models  # noqa: F401
from app.core.config import get_settings
from app.database.base import Base

BACKEND_DIR = Path(__file__).resolve().parents[1]
EXPECTED_TABLES = {
    "captures", "hosts", "flows", "investigations",
    "investigation_captures", "investigation_flows", "timeline_events",
    "dns_records", "http_requests", "tls_records", "certificates",
}


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return config


def test_upgrade_matches_models_and_downgrade_is_clean(tmp_path, monkeypatch):
    url = f"sqlite:///{(tmp_path / 'migrate.db').as_posix()}"
    monkeypatch.setenv("PCAPMAN_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        command.upgrade(_alembic_config(), "head")

        engine = create_engine(url)
        assert EXPECTED_TABLES <= set(inspect(engine).get_table_names())

        with engine.connect() as connection:
            differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
        assert differences == [], f"Models and migrations disagree: {differences}"

        command.downgrade(_alembic_config(), "base")
        assert not (EXPECTED_TABLES & set(inspect(create_engine(url)).get_table_names()))
    finally:
        get_settings.cache_clear()
