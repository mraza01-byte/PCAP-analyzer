import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.core.config import get_settings
from app.database.base import Base
from app.database.session import get_engine, get_session_factory


def _clear_caches():
    get_session_factory.cache_clear()
    get_engine.cache_clear()
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    """Every test gets its own empty database file, never the developer's real one."""
    monkeypatch.setenv("PCAPMAN_DATABASE_URL", f"sqlite:///{(tmp_path / 'app.db').as_posix()}")
    _clear_caches()
    yield
    get_engine().dispose() if get_engine.cache_info().currsize else None
    _clear_caches()


@pytest.fixture
def db_session(tmp_path):
    """A fresh, empty SQLite database (tables created from the models) for model tests."""
    engine = create_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()
