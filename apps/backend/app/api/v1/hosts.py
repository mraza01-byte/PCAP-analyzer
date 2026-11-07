from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Host
from app.schemas.entities import HostList

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=HostList)
def list_hosts(search: str | None = None, limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    query = select(Host)
    if search:
        like = f"%{search}%"
        query = query.where(or_(Host.ip_address.like(like), Host.hostname.like(like), Host.mac_address.like(like)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    hosts = db.scalars(query.order_by(Host.ip_address).limit(limit)).all()
    return HostList(total=total, hosts=hosts)
