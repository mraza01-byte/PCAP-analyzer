"""Response shapes for the read-only list endpoints. Fields mirror the database models."""
from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Optional
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True, extra="allow")


class CaptureOut(_Out):
    id: str
    original_filename: Optional[str] = None
    filename: Optional[str] = None
    file_size_bytes: int
    sha256: str
    file_format: Optional[str] = None
    file_type: Optional[str] = None
    status: str
    packet_count: Optional[int] = None
    first_packet_at: Optional[datetime] = None
    last_packet_at: Optional[datetime] = None
    flow_count: int = 0
    duration_seconds: float = 0.0
    notes: Optional[str] = None
    tshark_processed: int = 0
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _read_from_attributes(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            orig = getattr(data, "original_filename", None)
            fmt = getattr(data, "file_format", None)
            fmt_str = fmt.value if hasattr(fmt, "value") else (str(fmt) if fmt is not None else None)
            fc = getattr(data, "_flow_count", 0)
            return {
                "id": data.id,
                "original_filename": orig,
                "filename": orig,
                "file_size_bytes": getattr(data, "file_size_bytes", 0),
                "sha256": getattr(data, "sha256", ""),
                "file_format": fmt_str,
                "file_type": fmt_str,
                "status": getattr(data, "status", ""),
                "packet_count": getattr(data, "packet_count", None),
                "first_packet_at": getattr(data, "first_packet_at", None),
                "last_packet_at": getattr(data, "last_packet_at", None),
                "flow_count": fc,
                "notes": getattr(data, "notes", None) or getattr(data, "error_message", None),
                "created_at": getattr(data, "created_at", datetime.now()),
                "updated_at": getattr(data, "updated_at", datetime.now()),
            }
        return data

    @model_validator(mode="after")
    def _sync_fields(self) -> Self:
        if self.original_filename and not self.filename:
            self.filename = self.original_filename
        elif self.filename and not self.original_filename:
            self.original_filename = self.filename
        if self.file_format and not self.file_type:
            val = self.file_format.value if hasattr(self.file_format, "value") else str(self.file_format)
            self.file_type = val
        elif self.file_type and not self.file_format:
            self.file_format = self.file_type
        if self.first_packet_at and self.last_packet_at and self.duration_seconds == 0.0:
            delta = (self.last_packet_at - self.first_packet_at).total_seconds()
            self.duration_seconds = max(0.0, round(delta, 3))
        return self


class HostOut(_Out):
    id: Optional[str] = None
    capture_id: Optional[str] = None
    ip: Optional[str] = None
    ip_address: Optional[str] = None
    mac: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = ""
    role: Optional[str] = "Observed endpoint"
    open_ports: Any = Field(default_factory=list)
    bytes_total: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    risk_score: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def _read_from_attributes(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            ip_val = getattr(data, "ip_address", None) or getattr(data, "ip", "")
            mac_val = getattr(data, "mac_address", None) or getattr(data, "mac", "")
            ports = getattr(data, "open_ports", [])
            bs = getattr(data, "bytes_sent", 0)
            br = getattr(data, "bytes_received", 0)
            fs = getattr(data, "first_seen_at", None) or getattr(data, "first_seen", None)
            ls = getattr(data, "last_seen_at", None) or getattr(data, "last_seen", None)
            return {
                "id": getattr(data, "id", None),
                "capture_id": getattr(data, "capture_id", None),
                "ip": ip_val,
                "ip_address": ip_val,
                "mac": mac_val,
                "mac_address": mac_val,
                "hostname": getattr(data, "hostname", "") or "",
                "role": getattr(data, "role", None) or "Observed endpoint",
                "open_ports": ports,
                "bytes_total": bs + br,
                "bytes_sent": bs,
                "bytes_received": br,
                "packet_count": getattr(data, "packet_count", 0),
                "risk_score": getattr(data, "risk_score", 0),
                "first_seen": fs,
                "first_seen_at": fs,
                "last_seen": ls,
                "last_seen_at": ls,
            }
        return data

    @model_validator(mode="after")
    def _sync_host(self) -> Self:
        if self.ip_address and not self.ip:
            self.ip = self.ip_address
        elif self.ip and not self.ip_address:
            self.ip_address = self.ip
        if self.mac_address and not self.mac:
            self.mac = self.mac_address
        elif self.mac and not self.mac_address:
            self.mac_address = self.mac
        if not self.mac:
            self.mac = "00:00:00:00:00:00"
            self.mac_address = "00:00:00:00:00:00"
        if not self.bytes_total and (self.bytes_sent or self.bytes_received):
            self.bytes_total = self.bytes_sent + self.bytes_received
        if self.first_seen_at and not self.first_seen:
            self.first_seen = self.first_seen_at
        elif self.first_seen and not self.first_seen_at:
            self.first_seen_at = self.first_seen
        if self.last_seen_at and not self.last_seen:
            self.last_seen = self.last_seen_at
        elif self.last_seen and not self.last_seen_at:
            self.last_seen_at = self.last_seen
        if isinstance(self.open_ports, str):
            try:
                parsed = json.loads(self.open_ports)
                self.open_ports = parsed if isinstance(parsed, list) else []
            except Exception:
                self.open_ports = []
        elif not isinstance(self.open_ports, list):
            self.open_ports = list(self.open_ports) if self.open_ports else []
        return self


class FlowOut(_Out):
    id: str
    capture_id: Optional[str] = None
    src_host_id: Optional[str] = None
    dst_host_id: Optional[str] = None
    flow_key: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = 0
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = 0
    protocol: str = ""
    application: Optional[str] = ""
    packet_count: int = 0
    byte_count: int = 0
    bytes_total: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    tcp_flags: Optional[str] = "-"
    summary: Optional[str] = None
    payload_preview: Optional[str] = None
    payload_hex_preview: Optional[str] = None
    capture_filename: Optional[str] = None
    src_ip_val: Optional[str] = Field(default=None, alias="_src_ip")
    dst_ip_val: Optional[str] = Field(default=None, alias="_dst_ip")

    @model_validator(mode="before")
    @classmethod
    def _read_from_attributes(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            src_ip = getattr(data, "src_ip", None) or getattr(data, "_src_ip", None)
            if not src_ip and hasattr(data, "src_host") and data.src_host:
                src_ip = data.src_host.ip_address
            dst_ip = getattr(data, "dst_ip", None) or getattr(data, "_dst_ip", None)
            if not dst_ip and hasattr(data, "dst_host") and data.dst_host:
                dst_ip = data.dst_host.ip_address
            cap_fn = getattr(data, "capture_filename", None)
            if not cap_fn and hasattr(data, "capture") and data.capture:
                cap_fn = data.capture.original_filename
            bc = getattr(data, "byte_count", 0)
            bt = getattr(data, "bytes_total", 0) or bc
            preview = getattr(data, "payload_preview", None)
            return {
                "id": data.id,
                "capture_id": getattr(data, "capture_id", None),
                "src_host_id": getattr(data, "src_host_id", None),
                "dst_host_id": getattr(data, "dst_host_id", None),
                "src_ip": src_ip or "",
                "src_port": getattr(data, "src_port", 0) or 0,
                "dst_ip": dst_ip or "",
                "dst_port": getattr(data, "dst_port", 0) or 0,
                "protocol": getattr(data, "protocol", ""),
                "application": getattr(data, "application", "") or "",
                "packet_count": getattr(data, "packet_count", 0),
                "byte_count": bt,
                "bytes_total": bt,
                "bytes_forward": getattr(data, "bytes_forward", 0),
                "bytes_reverse": getattr(data, "bytes_reverse", 0),
                "start_time": getattr(data, "start_time", None),
                "end_time": getattr(data, "end_time", None),
                "tcp_flags": getattr(data, "tcp_flags", "-") or "-",
                "summary": getattr(data, "summary", None),
                "payload_preview": preview,
                "payload_hex_preview": preview,
                "capture_filename": cap_fn,
            }
        return data

    @model_validator(mode="after")
    def _sync_flow(self) -> Self:
        if self.byte_count and not self.bytes_total:
            self.bytes_total = self.byte_count
        elif self.bytes_total and not self.byte_count:
            self.byte_count = self.bytes_total
        if self.src_ip_val and not self.src_ip:
            self.src_ip = self.src_ip_val
        if self.dst_ip_val and not self.dst_ip:
            self.dst_ip = self.dst_ip_val
        if not self.src_ip:
            self.src_ip = ""
        if not self.dst_ip:
            self.dst_ip = ""
        if not self.flow_key:
            s_port = f":{self.src_port}" if self.src_port else ""
            d_port = f":{self.dst_port}" if self.dst_port else ""
            self.flow_key = f"{self.src_ip}{s_port}<->{self.dst_ip}{d_port}/{self.protocol}"
        if not self.summary:
            self.summary = f"{self.protocol} flow, {self.packet_count} packets, {self.bytes_total or self.byte_count} bytes"
        if not self.payload_hex_preview and self.payload_preview:
            self.payload_hex_preview = self.payload_preview
        elif not self.payload_preview and self.payload_hex_preview:
            self.payload_preview = self.payload_hex_preview
        return self


class TimelineEventOut(_Out):
    id: str
    capture_id: Optional[str] = None
    investigation_id: Optional[str] = None
    flow_id: Optional[str] = None
    event_time: Optional[datetime] = None
    timestamp: Optional[datetime] = None
    event_type: str = ""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: str = "info"
    category: str = "General"
    protocol: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    capture_filename: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _read_from_attributes(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            t = getattr(data, "timestamp", None) or getattr(data, "event_time", None)
            cap_fn = getattr(data, "capture_filename", None)
            if not cap_fn and hasattr(data, "capture") and data.capture:
                cap_fn = data.capture.original_filename
            proto = getattr(data, "protocol", None)
            src = getattr(data, "src", None)
            dst = getattr(data, "dst", None)
            if hasattr(data, "flow") and data.flow:
                if not proto:
                    proto = data.flow.protocol
                if not src and hasattr(data.flow, "src_host") and data.flow.src_host:
                    src = f"{data.flow.src_host.ip_address}:{data.flow.src_port or '-'}"
                if not dst and hasattr(data.flow, "dst_host") and data.flow.dst_host:
                    dst = f"{data.flow.dst_host.ip_address}:{data.flow.dst_port or '-'}"
            return {
                "id": data.id,
                "capture_id": getattr(data, "capture_id", None),
                "investigation_id": getattr(data, "investigation_id", None),
                "flow_id": getattr(data, "flow_id", None),
                "event_time": t,
                "timestamp": t,
                "event_type": getattr(data, "event_type", ""),
                "title": getattr(data, "title", None),
                "description": getattr(data, "description", None),
                "severity": getattr(data, "severity", "info") or "info",
                "category": getattr(data, "category", "General") or "General",
                "protocol": proto or "",
                "src": src or "",
                "dst": dst or "",
                "capture_filename": cap_fn or "",
            }
        return data

    @model_validator(mode="after")
    def _sync_timeline(self) -> Self:
        if self.event_time and not self.timestamp:
            self.timestamp = self.event_time
        elif self.timestamp and not self.event_time:
            self.event_time = self.timestamp
        if self.title and not self.description:
            self.description = self.title
        elif self.description and not self.title:
            self.title = self.description
        return self


class InvestigationOut(_Out):
    id: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "medium"
    lead_analyst: Optional[str] = ""
    findings: Optional[str] = None
    ioc_list: Optional[str] = None
    status: str
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class DnsRecordOut(_Out):
    id: str
    capture_id: str
    flow_id: Optional[str] = None
    timestamp: datetime
    query_name: str
    query_type: str
    response_code: Optional[str] = None
    answers: Optional[str] = None
    ttl: Optional[int] = None

    @property
    def answers_list(self) -> list[str]:
        if not self.answers:
            return []
        try:
            parsed = json.loads(self.answers)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [self.answers]


class HttpRequestOut(_Out):
    id: str
    capture_id: str
    flow_id: Optional[str] = None
    timestamp: datetime
    method: str
    host: Optional[str] = None
    url: str
    path: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    response_phrase: Optional[str] = None
    content_type: Optional[str] = None


class TlsRecordOut(_Out):
    id: str
    capture_id: str
    flow_id: Optional[str] = None
    timestamp: datetime
    version: str
    sni: Optional[str] = None
    cipher_suite: Optional[str] = None
    alpn: Optional[str] = None


class CertificateOut(_Out):
    id: str
    capture_id: str
    flow_id: Optional[str] = None
    fingerprint_sha256: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    serial_number: Optional[str] = None
    san_list: Optional[str] = None
    is_self_signed: bool = False

    @property
    def sans(self) -> list[str]:
        if not self.san_list:
            return []
        try:
            parsed = json.loads(self.san_list)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return []


class HostList(BaseModel):
    total: int
    hosts: list[HostOut]


class FlowList(BaseModel):
    total: int
    flows: list[FlowOut]


class TimelineList(BaseModel):
    total: int
    events: list[TimelineEventOut]


class DnsList(BaseModel):
    total: int
    records: list[DnsRecordOut]


class HttpList(BaseModel):
    total: int
    requests: list[HttpRequestOut]


class TlsList(BaseModel):
    total: int
    records: list[TlsRecordOut]


class CertificateList(BaseModel):
    total: int
    certificates: list[CertificateOut]


class NetworkMapOut(BaseModel):
    capture_id: str
    total_hosts: int
    total_flows: int
    protocols: dict[str, int]
    applications: dict[str, int]
    hosts: list[HostOut]
    flows: list[FlowOut]
    top_domains: list[str]
