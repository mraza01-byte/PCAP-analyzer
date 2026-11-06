import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.database.base import Base


@pytest.fixture
def db_session(tmp_path):
    """A fresh, empty SQLite database for each test."""
    engine = create_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()
