"""Response shapes for the read-only list endpoints. Fields mirror the database models."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CaptureOut(_Out):
    id: str
    original_filename: str
    file_size_bytes: int
    sha256: str
    file_format: str
    status: str
    packet_count: int | None
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    created_at: datetime
    updated_at: datetime


class HostOut(_Out):
    id: str
    capture_id: str
    ip_address: str
    mac_address: str | None
    hostname: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class FlowOut(_Out):
    id: str
    capture_id: str
    src_host_id: str
    dst_host_id: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    start_time: datetime | None
    end_time: datetime | None
    packet_count: int
    byte_count: int


class TimelineEventOut(_Out):
    id: str
    capture_id: str
    investigation_id: str | None
    flow_id: str | None
    event_time: datetime
    event_type: str
    title: str
    description: str | None


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
