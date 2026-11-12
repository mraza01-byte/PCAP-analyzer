from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class TlsRecord(IdTimestampMixin, Base):
    """An extracted TLS handshake metadata record."""

    __tablename__ = "tls_records"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    flow_id: Mapped[Optional[str]] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    version: Mapped[str] = mapped_column(String(32))  # TLS 1.2, TLS 1.3, etc.
    sni: Mapped[Optional[str]] = mapped_column(String(255))
    cipher_suite: Mapped[Optional[str]] = mapped_column(String(128))
    alpn: Mapped[Optional[str]] = mapped_column(String(64))

    capture: Mapped["Capture"] = relationship(back_populates="tls_records")
    flow: Mapped[Optional["Flow"]] = relationship()

    __table_args__ = (
        Index("ix_tls_records_capture_id", "capture_id"),
        Index("ix_tls_records_sni", "sni"),
        Index("ix_tls_records_timestamp", "timestamp"),
    )

