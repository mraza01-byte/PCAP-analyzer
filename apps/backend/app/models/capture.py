import enum
from datetime import datetime

from sqlalchemy import BigInteger, Enum, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class CaptureFormat(str, enum.Enum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class CaptureStatus(str, enum.Enum):
    IMPORTED = "imported"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Capture(IdTimestampMixin, Base):
    """One imported PCAP/PCAPNG file (the evidence file)."""

    __tablename__ = "captures"

    original_filename: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(1024))
    file_size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))  # fingerprint of the file
    file_format: Mapped[CaptureFormat] = mapped_column(
        Enum(CaptureFormat, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e])
    )
    status: Mapped[CaptureStatus] = mapped_column(
        Enum(CaptureStatus, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]),
        default=CaptureStatus.IMPORTED,
    )

    # Filled in later by the PCAP parser. Empty (NULL) until then.
    packet_count: Mapped[int | None] = mapped_column(BigInteger)
    first_packet_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_packet_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    error_message: Mapped[str | None] = mapped_column(String(2000))
    processing_token: Mapped[str | None] = mapped_column(String(36))
    processing_lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    hosts: Mapped[list["Host"]] = relationship(back_populates="capture", cascade="all, delete-orphan", passive_deletes=True)
    flows: Mapped[list["Flow"]] = relationship(back_populates="capture", cascade="all, delete-orphan", passive_deletes=True)
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(back_populates="capture", cascade="all, delete-orphan", passive_deletes=True)
    investigations: Mapped[list["Investigation"]] = relationship(secondary="investigation_captures", back_populates="captures")

    __table_args__ = (Index("ix_captures_sha256", "sha256", unique=True),)
