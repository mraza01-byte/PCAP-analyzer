from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class Host(IdTimestampMixin, Base):
    """A device seen in one capture, identified by its IP address."""

    __tablename__ = "hosts"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    ip_address: Mapped[str] = mapped_column(String(45))  # fits IPv4 and IPv6
    mac_address: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    packet_count: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    open_ports: Mapped[list[int]] = mapped_column(JSON, default=list)

    capture: Mapped["Capture"] = relationship(back_populates="hosts")

    __table_args__ = (
        UniqueConstraint("capture_id", "ip_address", name="uq_hosts_capture_id_ip_address"),
        Index("ix_hosts_capture_id", "capture_id"),
        Index("ix_hosts_ip_address", "ip_address"),
    )
