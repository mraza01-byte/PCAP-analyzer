from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class HttpRequest(IdTimestampMixin, Base):
    """An extracted HTTP request/response transaction."""

    __tablename__ = "http_requests"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    flow_id: Mapped[Optional[str]] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    method: Mapped[str] = mapped_column(String(16))  # GET, POST, PUT, DELETE, etc.
    host: Mapped[Optional[str]] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(Text)
    path: Mapped[Optional[str]] = mapped_column(String(1024))
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    response_phrase: Mapped[Optional[str]] = mapped_column(String(64))
    content_type: Mapped[Optional[str]] = mapped_column(String(128))

    capture: Mapped["Capture"] = relationship(back_populates="http_requests")
    flow: Mapped[Optional["Flow"]] = relationship()

    __table_args__ = (
        Index("ix_http_requests_capture_id", "capture_id"),
        Index("ix_http_requests_host", "host"),
        Index("ix_http_requests_timestamp", "timestamp"),
    )

