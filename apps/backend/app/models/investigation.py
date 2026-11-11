import enum
from datetime import datetime

from sqlalchemy import Column, Enum, ForeignKey, Index, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.database.types import UTCDateTime, utcnow
from app.models.mixins import IdTimestampMixin


class InvestigationStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    CLOSED = "closed"


# Link tables: one investigation can include many captures/flows,
# and one capture/flow can be part of many investigations.
investigation_captures = Table(
    "investigation_captures",
    Base.metadata,
    Column("investigation_id", ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True),
    Column("capture_id", ForeignKey("captures.id", ondelete="CASCADE"), primary_key=True),
    Column("added_at", UTCDateTime, default=utcnow),
    Index("ix_investigation_captures_capture_id", "capture_id"),
)

investigation_flows = Table(
    "investigation_flows",
    Base.metadata,
    Column("investigation_id", ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True),
    Column("flow_id", ForeignKey("flows.id", ondelete="CASCADE"), primary_key=True),
    Column("added_at", UTCDateTime, default=utcnow),
    Index("ix_investigation_flows_flow_id", "flow_id"),
)


class Investigation(IdTimestampMixin, Base):
    """A case folder that collects the captures and flows you are looking into."""

    __tablename__ = "investigations"

    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    lead_analyst: Mapped[str] = mapped_column(String(255), default="")
    findings: Mapped[str | None] = mapped_column(Text)
    ioc_list: Mapped[str | None] = mapped_column(Text)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]),
        default=InvestigationStatus.OPEN,
    )
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    captures: Mapped[list["Capture"]] = relationship(secondary=investigation_captures, back_populates="investigations")
    flows: Mapped[list["Flow"]] = relationship(secondary=investigation_flows, back_populates="investigations")
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(back_populates="investigation")

    __table_args__ = (Index("ix_investigations_status", "status"),)
