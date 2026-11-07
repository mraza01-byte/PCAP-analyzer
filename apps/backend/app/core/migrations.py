"""Run database migrations from inside the app.

This makes the backend self-contained: starting it creates or updates the SQLite
database to the latest structure, so nobody has to remember to run Alembic first.
"""
from alembic import command
from alembic.config import Config

from app.core.config import BACKEND_DIR


def run_migrations() -> None:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic").replace("%", "%%"))
    config.attributes["configure_logger"] = False  # keep our structured logging
    command.upgrade(config, "head")
