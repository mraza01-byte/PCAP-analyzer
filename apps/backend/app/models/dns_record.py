from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class DnsRecord(IdTimestampMixin, Base):
    """An extracted DNS query and response record."""

    __tablename__ = "dns_records"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    flow_id: Mapped[Optional[str]] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    query_name: Mapped[str] = mapped_column(String(255))
    query_type: Mapped[str] = mapped_column(String(16))  # A, AAAA, CNAME, PTR, TXT, MX, etc.
    response_code: Mapped[Optional[str]] = mapped_column(String(16))  # NOERROR, NXDOMAIN, etc.
    answers: Mapped[Optional[str]] = mapped_column(Text)  # JSON list of answers
    ttl: Mapped[Optional[int]] = mapped_column(Integer)

    capture: Mapped["Capture"] = relationship(back_populates="dns_records")
    flow: Mapped[Optional["Flow"]] = relationship()

    __table_args__ = (
        Index("ix_dns_records_capture_id", "capture_id"),
        Index("ix_dns_records_query_name", "query_name"),
        Index("ix_dns_records_timestamp", "timestamp"),
    )

