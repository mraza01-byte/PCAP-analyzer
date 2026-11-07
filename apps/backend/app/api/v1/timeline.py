from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import TimelineEvent
from app.schemas.entities import TimelineList

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("", response_model=TimelineList)
def list_events(search: str | None = None, limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    query = select(TimelineEvent)
    if search:
        like = f"%{search}%"
        query = query.where(or_(TimelineEvent.title.like(like), TimelineEvent.description.like(like)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    events = db.scalars(query.order_by(TimelineEvent.event_time).limit(limit)).all()
    return TimelineList(total=total, events=events)
