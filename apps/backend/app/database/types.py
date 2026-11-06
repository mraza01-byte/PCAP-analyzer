"""Small helpers shared by all models: UTC time and UUIDs."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator):
    """A datetime column that is always UTC.

    SQLite forgets timezones, so this type:
      - refuses naive datetimes (no timezone) when saving
      - converts anything saved to UTC
      - hands back timezone-aware UTC datetimes when reading
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Datetime must have a timezone (use UTC).")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
