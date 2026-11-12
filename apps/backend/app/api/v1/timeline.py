from fastapi import APIRouter, Depends, Query
from sqlalchemy import false, func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import TimelineEvent
from app.schemas.entities import TimelineList
from app.api.v1.search import contains_pattern

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("", response_model=TimelineList)
def list_events(search: str | None = None, severity: str | None = None, category: str | None = None,
                capture_id: str | None = None,
                limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    query = select(TimelineEvent)
    if capture_id:
        query = query.where(TimelineEvent.capture_id == capture_id)
    if search:
        pattern = contains_pattern(search)
        query = query.where(or_(
            TimelineEvent.title.like(pattern, escape="\\"),
            TimelineEvent.description.like(pattern, escape="\\"),
        ))
    if severity and severity != "info":
        query = query.where(false())
    if category:
        from app.models import Flow
        if category.upper() in {"TCP", "UDP", "ICMP", "OTHER"}:
            query = query.where(TimelineEvent.flow.has(
                Flow.protocol == category.upper() if category.upper() != "OTHER" else Flow.protocol.notin_(["TCP", "UDP", "ICMP", "ICMPv6"])
            ))
        else:
            query = query.where(false())
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    events = db.scalars(query.order_by(TimelineEvent.event_time).limit(limit)).all()
    return TimelineList(total=total, events=[{
        "id": event.id,
        "timestamp": event.event_time,
        "event_type": event.event_type,
        "protocol": event.flow.protocol if event.flow else "",
        "src": f"{event.flow.src_host.ip_address}:{event.flow.src_port or '-'}" if event.flow else "",
        "dst": f"{event.flow.dst_host.ip_address}:{event.flow.dst_port or '-'}" if event.flow else "",
        "severity": "info",
        "category": event.event_type.replace("_", " ").title(),
        "description": event.description or event.title,
        "capture_filename": event.capture.original_filename,
    } for event in events])
