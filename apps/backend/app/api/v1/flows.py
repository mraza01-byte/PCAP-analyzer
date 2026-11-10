from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture, Flow, Host
from app.schemas.entities import FlowList

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowList)
def list_flows(protocol: str | None = None, search: str | None = None,
               limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    query = select(Flow)
    if protocol:
        query = query.where(or_(func.upper(Flow.protocol) == protocol.upper(), func.upper(Flow.application) == protocol.upper()))
    if search:
        like = f"%{search}%"
        query = query.where(or_(
            Flow.src_host.has(Host.ip_address.like(like)),
            Flow.dst_host.has(Host.ip_address.like(like)),
            Flow.capture.has(Capture.original_filename.like(like)),
            Flow.application.like(like),
            Flow.protocol.like(like),
        ))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    flows = db.scalars(query.order_by(Flow.start_time).limit(limit)).all()
    return FlowList(total=total, flows=[_flow_record(flow) for flow in flows])


@router.get("/{flow_id}")
def get_flow(flow_id: str, db: Session = Depends(get_db)):
    flow = db.get(Flow, flow_id)
    if not flow:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Flow not found")
    return _flow_record(flow)


def _flow_record(flow: Flow) -> dict:
    return {
        "id": flow.id,
        "flow_key": f"{flow.src_host.ip_address}:{flow.src_port or '-'}<->{flow.dst_host.ip_address}:{flow.dst_port or '-'}/{flow.protocol}",
        "src_ip": flow.src_host.ip_address,
        "src_port": flow.src_port or 0,
        "dst_ip": flow.dst_host.ip_address,
        "dst_port": flow.dst_port or 0,
        "protocol": flow.protocol,
        "application": flow.application,
        "packet_count": flow.packet_count,
        "bytes_total": flow.byte_count,
        "bytes_forward": flow.bytes_forward,
        "bytes_reverse": flow.bytes_reverse,
        "start_time": flow.start_time,
        "end_time": flow.end_time,
        "tcp_flags": flow.tcp_flags,
        "summary": f"{flow.protocol} flow, {flow.packet_count} packets, {flow.byte_count} bytes",
        "capture_filename": flow.capture.original_filename,
    }
