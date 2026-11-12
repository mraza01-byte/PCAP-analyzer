from __future__ import annotations

import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.search import contains_pattern
from app.database.session import get_db
from app.models.host import Host
from app.schemas.entities import HostList, HostOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=HostList)
def list_hosts(
    search: str | None = None,
    capture_id: str | None = None,
    role: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(Host)
    if capture_id:
        query = query.where(Host.capture_id == capture_id)
    if role:
        query = query.where(Host.role == role)
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                Host.ip_address.like(pattern, escape="\\"),
                Host.hostname.like(pattern, escape="\\"),
                Host.mac_address.like(pattern, escape="\\"),
            )
        )

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    hosts = db.scalars(query.order_by(Host.packet_count.desc(), Host.ip_address).limit(limit)).all()
    return HostList(total=total, hosts=[_host_record(host) for host in hosts])


@router.get("/{host_id}", response_model=HostOut)
def get_host(host_id: str, db: Session = Depends(get_db)):
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return _host_record(host)


def _host_record(host: Host) -> dict:
    open_ports = host.open_ports or []
    if isinstance(open_ports, str):
        try:
            parsed = json.loads(open_ports)
            open_ports = parsed if isinstance(parsed, list) else []
        except Exception:
            open_ports = []
    return {
        "id": host.id,
        "capture_id": host.capture_id,
        "ip": host.ip_address,
        "ip_address": host.ip_address,
        "mac": host.mac_address or "",
        "mac_address": host.mac_address or "",
        "hostname": host.hostname or "",
        "role": host.role or "Observed endpoint",
        "open_ports": open_ports,
        "bytes_total": host.bytes_sent + host.bytes_received,
        "bytes_sent": host.bytes_sent,
        "bytes_received": host.bytes_received,
        "packet_count": host.packet_count,
        "risk_score": host.risk_score,
        "first_seen": host.first_seen_at,
        "first_seen_at": host.first_seen_at,
        "last_seen": host.last_seen_at,
        "last_seen_at": host.last_seen_at,
    }
