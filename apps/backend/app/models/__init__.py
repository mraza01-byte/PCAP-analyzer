"""Import every model here so SQLAlchemy and Alembic can see all the tables."""
from app.models.capture import Capture, CaptureFormat, CaptureStatus
from app.models.certificate import Certificate
from app.models.dns_record import DnsRecord
from app.models.flow import Flow
from app.models.host import Host
from app.models.http_request import HttpRequest
from app.models.investigation import (
    Investigation,
    InvestigationStatus,
    investigation_captures,
    investigation_flows,
)
from app.models.timeline_event import TimelineEvent
from app.models.tls_record import TlsRecord

__all__ = [
    "Capture", "CaptureFormat", "CaptureStatus",
    "Host", "Flow",
    "Investigation", "InvestigationStatus", "investigation_captures", "investigation_flows",
    "TimelineEvent",
    "DnsRecord", "HttpRequest", "TlsRecord", "Certificate",
]
