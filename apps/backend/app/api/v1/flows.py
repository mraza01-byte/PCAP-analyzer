from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.api.v1.search import contains_pattern
from app.database.session import get_db
from app.models.capture import Capture
from app.models.flow import Flow
from app.models.host import Host
from app.schemas.entities import FlowList, FlowOut

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowList)
def list_flows(
    protocol: str | None = None,
    application: str | None = None,
    search: str | None = None,
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(Flow).options(
        joinedload(Flow.src_host),
        joinedload(Flow.dst_host),
        joinedload(Flow.capture),
    )
    if capture_id:
        query = query.where(Flow.capture_id == capture_id)
    if protocol:
        query = query.where(
            or_(
                func.upper(Flow.protocol) == protocol.upper(),
                func.upper(Flow.application) == protocol.upper(),
            )
        )
    if application:
        query = query.where(func.upper(Flow.application) == application.upper())
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                Flow.src_host.has(Host.ip_address.like(pattern, escape="\\")),
                Flow.dst_host.has(Host.ip_address.like(pattern, escape="\\")),
                Flow.capture.has(Capture.original_filename.like(pattern, escape="\\")),
                Flow.application.like(pattern, escape="\\"),
                Flow.protocol.like(pattern, escape="\\"),
                Flow.summary.like(pattern, escape="\\"),
            )
        )

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    flows = db.scalars(query.order_by(Flow.start_time.asc()).limit(limit)).unique().all()
    return FlowList(total=total, flows=[_flow_record(flow) for flow in flows])


@router.get("/{flow_id}", response_model=FlowOut)
def get_flow(flow_id: str, db: Session = Depends(get_db)):
    flow = db.scalar(
        select(Flow)
        .options(
            joinedload(Flow.src_host),
            joinedload(Flow.dst_host),
            joinedload(Flow.capture),
        )
        .where(Flow.id == flow_id)
    )
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return _flow_record(flow)


def _flow_record(flow: Flow) -> dict:
    src_ip = flow.src_host.ip_address if flow.src_host else ""
    dst_ip = flow.dst_host.ip_address if flow.dst_host else ""
    cap_name = flow.capture.original_filename if flow.capture else ""
    summary = flow.summary or f"{flow.protocol} flow, {flow.packet_count} packets, {flow.byte_count} bytes"
    return {
        "id": flow.id,
        "capture_id": flow.capture_id,
        "src_host_id": flow.src_host_id,
        "dst_host_id": flow.dst_host_id,
        "flow_key": f"{src_ip}:{flow.src_port or '-'}<->{dst_ip}:{flow.dst_port or '-'}/{flow.protocol}",
        "src_ip": src_ip,
        "src_port": flow.src_port or 0,
        "dst_ip": dst_ip,
        "dst_port": flow.dst_port or 0,
        "protocol": flow.protocol,
        "application": flow.application or "",
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "bytes_total": flow.byte_count,
        "bytes_forward": flow.bytes_forward,
        "bytes_reverse": flow.bytes_reverse,
        "start_time": flow.start_time,
        "end_time": flow.end_time,
        "tcp_flags": flow.tcp_flags or "-",
        "summary": summary,
        "payload_preview": flow.payload_preview,
        "payload_hex_preview": flow.payload_preview,
        "capture_filename": cap_name,
    }
