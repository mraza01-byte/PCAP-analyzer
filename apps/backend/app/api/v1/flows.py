from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Flow
from app.schemas.entities import FlowList

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowList)
def list_flows(protocol: str | None = None, limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    query = select(Flow)
    if protocol:
        query = query.where(func.upper(Flow.protocol) == protocol.upper())
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    flows = db.scalars(query.order_by(Flow.start_time).limit(limit)).all()
    return FlowList(total=total, flows=flows)
