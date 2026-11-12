from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class Flow(IdTimestampMixin, Base):
    """One conversation between two hosts inside a capture."""

    __tablename__ = "flows"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    src_host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    dst_host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    src_port: Mapped[Optional[int]] = mapped_column(Integer)  # empty for protocols without ports (e.g. ICMP)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))  # e.g. TCP, UDP, ICMP
    start_time: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    end_time: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    packet_count: Mapped[int] = mapped_column(BigInteger, default=0)
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_forward: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_reverse: Mapped[int] = mapped_column(BigInteger, default=0)
    application: Mapped[str] = mapped_column(String(32), default="")
    tcp_flags: Mapped[str] = mapped_column(String(32), default="-")
    summary: Mapped[Optional[str]] = mapped_column(String(512))
    payload_preview: Mapped[Optional[str]] = mapped_column(Text)

    capture: Mapped["Capture"] = relationship(back_populates="flows")
    src_host: Mapped["Host"] = relationship(foreign_keys=[src_host_id])
    dst_host: Mapped["Host"] = relationship(foreign_keys=[dst_host_id])
    investigations: Mapped[list["Investigation"]] = relationship(secondary="investigation_flows", back_populates="flows")

    __table_args__ = (
        Index("ix_flows_capture_id_start_time", "capture_id", "start_time"),
        Index("ix_flows_src_host_id", "src_host_id"),
        Index("ix_flows_dst_host_id", "dst_host_id"),
        Index("ix_flows_protocol", "protocol"),
    )
