from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Every database model (table) will inherit from this class."""
