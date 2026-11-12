from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class Certificate(IdTimestampMixin, Base):
    """An extracted X.509 TLS certificate."""

    __tablename__ = "certificates"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    flow_id: Mapped[Optional[str]] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    subject_cn: Mapped[Optional[str]] = mapped_column(String(255))
    subject_org: Mapped[Optional[str]] = mapped_column(String(255))
    issuer_cn: Mapped[Optional[str]] = mapped_column(String(255))
    issuer_org: Mapped[Optional[str]] = mapped_column(String(255))
    valid_from: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    valid_to: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128))
    san_list: Mapped[Optional[str]] = mapped_column(Text)  # JSON list of Subject Alternative Names
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)

    capture: Mapped["Capture"] = relationship(back_populates="certificates")
    flow: Mapped[Optional["Flow"]] = relationship()

    __table_args__ = (
        Index("ix_certificates_capture_id", "capture_id"),
        Index("ix_certificates_fingerprint_sha256", "fingerprint_sha256"),
    )

