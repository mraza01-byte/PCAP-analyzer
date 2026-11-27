from __future__ import annotations

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.search import contains_pattern
from app.database.session import get_db
from app.models import Flow, TimelineEvent
from app.schemas.entities import TimelineEventOut, TimelineList

router = APIRouter(prefix="/timeline", tags=["timeline"])

SEVERITIES = ("critical", "high", "warning", "info")
TRANSPORT_FILTERS = {"TCP", "UDP", "ICMP", "OTHER"}  # kept so the existing page buttons keep working
KNOWN_TRANSPORTS = ["TCP", "UDP", "ICMP", "ICMPv6"]


class CategoryCount(BaseModel):
    category: str
    count: int


class TimelineSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: list[CategoryCount]


class RelatedEvent(BaseModel):
    relation: str  # same_flow | same_host
    event: TimelineEventOut


class RelatedEvents(BaseModel):
    event_id: str
    total: int
    related: list[RelatedEvent]


def _apply_filters(query, *, search=None, severity=None, category=None, protocol=None,
                   capture_id=None, investigation_id=None):
    if capture_id:
        query = query.where(TimelineEvent.capture_id == capture_id)
    if investigation_id:
        query = query.where(TimelineEvent.investigation_id == investigation_id)
    if search:
        pattern = contains_pattern(search)
        query = query.where(or_(
            TimelineEvent.title.like(pattern, escape="\\"),
            TimelineEvent.description.like(pattern, escape="\\"),
        ))
    if severity:
        value = severity.lower()
        if value not in SEVERITIES:
            raise HTTPException(status_code=422, detail=f"Severity must be one of: {', '.join(SEVERITIES)}")
        query = query.where(func.lower(TimelineEvent.severity) == value)
    if protocol:
        query = query.where(func.upper(TimelineEvent.protocol) == protocol.upper())
    if category:
        if category.upper() in TRANSPORT_FILTERS:
            # Transport buttons (TCP / UDP / ICMP / Other) look at the protocol of the event's flow.
            if category.upper() == "OTHER":
                condition = Flow.protocol.notin_(KNOWN_TRANSPORTS)
            else:
                condition = func.upper(Flow.protocol).in_([category.upper(), category.upper() + "V6"])
            query = query.where(TimelineEvent.flow.has(condition))
        else:
            query = query.where(func.lower(TimelineEvent.category) == category.lower())
    return query


@router.get("", response_model=TimelineList)
def list_events(search: Optional[str] = None, severity: Optional[str] = None, category: Optional[str] = None,
                protocol: Optional[str] = None, capture_id: Optional[str] = None,
                investigation_id: Optional[str] = None,
                limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    """Timeline events with their real stored severity, category and endpoints."""
    query = _apply_filters(select(TimelineEvent), search=search, severity=severity, category=category,
                           protocol=protocol, capture_id=capture_id, investigation_id=investigation_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    events = db.scalars(query.order_by(TimelineEvent.event_time).limit(limit)).all()
    return TimelineList(total=total, events=events)


@router.get("/summary", response_model=TimelineSummary)
def timeline_summary(capture_id: Optional[str] = None, investigation_id: Optional[str] = None,
                     db: Session = Depends(get_db)):
    """Real counts per severity and per category (used for the filter buttons)."""
    base = _apply_filters(select(TimelineEvent), capture_id=capture_id, investigation_id=investigation_id).subquery()
    total = db.scalar(select(func.count()).select_from(base)) or 0
    severity_rows = db.execute(select(func.lower(base.c.severity), func.count()).group_by(func.lower(base.c.severity))).all()
    by_severity = {name: 0 for name in SEVERITIES}
    for name, count in severity_rows:
        by_severity[name] = by_severity.get(name, 0) + count
    category_rows = db.execute(
        select(base.c.category, func.count()).group_by(base.c.category).order_by(func.count().desc(), base.c.category)
    ).all()
    return TimelineSummary(total=total, by_severity=by_severity,
                           by_category=[CategoryCount(category=c or "General", count=n) for c, n in category_rows])


@router.get("/{event_id}", response_model=TimelineEventOut)
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = db.get(TimelineEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Timeline event not found")
    return event


@router.get("/{event_id}/related", response_model=RelatedEvents)
def related_events(event_id: str, window_seconds: int = Query(60, ge=1, le=86400),
                   limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    """Events correlated with this one, computed from stored data.

    same_flow: events that belong to the same network flow.
    same_host: events in the same capture, within the time window, whose flow involves
               either host of this event's flow.
    """
    event = db.get(TimelineEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Timeline event not found")
    found: dict[str, str] = {}
    if event.flow_id:
        for other in db.scalars(select(TimelineEvent).where(
                TimelineEvent.flow_id == event.flow_id, TimelineEvent.id != event.id)):
            found[other.id] = "same_flow"
        flow = event.flow
        hosts = {flow.src_host_id, flow.dst_host_id}
        window = timedelta(seconds=window_seconds)
        host_matches = db.scalars(
            select(TimelineEvent).join(Flow, TimelineEvent.flow_id == Flow.id).where(
                TimelineEvent.capture_id == event.capture_id,
                TimelineEvent.id != event.id,
                TimelineEvent.event_time >= event.event_time - window,
                TimelineEvent.event_time <= event.event_time + window,
                or_(Flow.src_host_id.in_(hosts), Flow.dst_host_id.in_(hosts)),
            )
        )
        for other in host_matches:
            found.setdefault(other.id, "same_host")
    events = {e.id: e for e in db.scalars(select(TimelineEvent).where(TimelineEvent.id.in_(found.keys())))} if found else {}
    ordered = sorted(events.values(), key=lambda e: (found[e.id] != "same_flow", e.event_time))[:limit]
    return RelatedEvents(event_id=event.id, total=len(found),
                         related=[RelatedEvent(relation=found[e.id], event=e) for e in ordered])
