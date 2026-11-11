from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Host
from app.schemas.entities import HostList
from app.api.v1.search import contains_pattern

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=HostList)
def list_hosts(
    search: str | None = None,
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(Host)
    if capture_id:
        query = query.where(Host.capture_id == capture_id)
    if search:
        pattern = contains_pattern(search)
        query = query.where(or_(
            Host.ip_address.like(pattern, escape="\\"),
            Host.hostname.like(pattern, escape="\\"),
            Host.mac_address.like(pattern, escape="\\"),
        ))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    hosts = db.scalars(query.order_by(Host.ip_address).limit(limit)).all()
    return HostList(total=total, hosts=[{
        "ip": host.ip_address,
        "mac": host.mac_address or "",
        "hostname": host.hostname or "",
        "role": "Observed endpoint",
        "open_ports": host.open_ports or [],
        "bytes_total": host.bytes_sent + host.bytes_received,
        "bytes_sent": host.bytes_sent,
        "bytes_received": host.bytes_received,
        "packet_count": host.packet_count,
        "first_seen": host.first_seen_at,
        "last_seen": host.last_seen_at,
    } for host in hosts])
