from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class Host(IdTimestampMixin, Base):
    """A device seen in one capture, identified by its IP address."""

    __tablename__ = "hosts"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    ip_address: Mapped[str] = mapped_column(String(45))  # fits IPv4 and IPv6
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)

    role: Mapped[Optional[str]] = mapped_column(String(64))
    packet_count: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    open_ports: Mapped[Any] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    capture: Mapped["Capture"] = relationship(back_populates="hosts")

    __table_args__ = (
        UniqueConstraint("capture_id", "ip_address", name="uq_hosts_capture_id_ip_address"),
        Index("ix_hosts_capture_id", "capture_id"),
        Index("ix_hosts_ip_address", "ip_address"),
    )
