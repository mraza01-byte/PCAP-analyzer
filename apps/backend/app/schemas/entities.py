"""Response shapes for the read-only list endpoints. Fields mirror the database models."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CaptureOut(_Out):
    id: str
    filename: str
    file_size_bytes: int
    sha256: str
    file_type: str
    status: str
    packet_count: int | None
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    flow_count: int
    duration_seconds: float
    notes: str | None
    created_at: datetime
    updated_at: datetime


class HostOut(_Out):
    ip: str
    mac: str
    hostname: str
    role: str
    open_ports: list[int]
    bytes_total: int
    bytes_sent: int
    bytes_received: int
    packet_count: int
    first_seen: datetime | None
    last_seen: datetime | None


class FlowOut(_Out):
    id: str
    flow_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    application: str
    packet_count: int
    bytes_total: int
    bytes_forward: int
    bytes_reverse: int
    start_time: datetime | None
    end_time: datetime | None
    tcp_flags: str
    summary: str
    capture_filename: str


class TimelineEventOut(_Out):
    id: str
    timestamp: datetime
    event_type: str
    protocol: str
    src: str
    dst: str
    severity: str
    category: str
    description: str
    capture_filename: str


class InvestigationOut(_Out):
    id: str
    title: str
    description: str | None
    status: str
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class HostList(BaseModel):
    total: int
    hosts: list[HostOut]


class FlowList(BaseModel):
    total: int
    flows: list[FlowOut]


class TimelineList(BaseModel):
    total: int
    events: list[TimelineEventOut]
