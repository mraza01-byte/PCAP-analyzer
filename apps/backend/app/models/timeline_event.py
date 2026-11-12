from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class TimelineEvent(IdTimestampMixin, Base):
    """Something that happened at a point in time, belonging to a capture."""

    __tablename__ = "timeline_events"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    investigation_id: Mapped[Optional[str]] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"))
    flow_id: Mapped[Optional[str]] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    event_time: Mapped[datetime] = mapped_column(UTCDateTime)
    event_type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    category: Mapped[str] = mapped_column(String(64), default="General")
    protocol: Mapped[Optional[str]] = mapped_column(String(16))
    src: Mapped[Optional[str]] = mapped_column(String(64))
    dst: Mapped[Optional[str]] = mapped_column(String(64))

    capture: Mapped["Capture"] = relationship(back_populates="timeline_events")
    investigation: Mapped[Optional["Investigation"]] = relationship(back_populates="timeline_events")
    flow: Mapped[Optional["Flow"]] = relationship()

    __table_args__ = (
        Index("ix_timeline_events_capture_id_event_time", "capture_id", "event_time"),
        Index("ix_timeline_events_investigation_id_event_time", "investigation_id", "event_time"),
        Index("ix_timeline_events_flow_id", "flow_id"),
    )
