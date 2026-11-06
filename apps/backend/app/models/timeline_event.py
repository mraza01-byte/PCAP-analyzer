from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime
from app.models.mixins import IdTimestampMixin


class TimelineEvent(IdTimestampMixin, Base):
    """Something that happened at a point in time, belonging to a capture."""

    __tablename__ = "timeline_events"

    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"))
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id", ondelete="SET NULL"))
    event_time: Mapped[datetime] = mapped_column(UTCDateTime)
    event_type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)

    capture: Mapped["Capture"] = relationship(back_populates="timeline_events")
    investigation: Mapped["Investigation | None"] = relationship(back_populates="timeline_events")
    flow: Mapped["Flow | None"] = relationship()

    __table_args__ = (
        Index("ix_timeline_events_capture_id_event_time", "capture_id", "event_time"),
        Index("ix_timeline_events_investigation_id_event_time", "investigation_id", "event_time"),
        Index("ix_timeline_events_flow_id", "flow_id"),
    )
