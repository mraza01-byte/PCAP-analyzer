from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class TimelineEventItem:
    id: str
    event_time: datetime
    event_type: str
    title: str
    description: str
    severity: str  # info, warning, high, critical
    category: str  # Resolution, Encryption, Web Traffic, C2 Traffic, Standard, etc.
    protocol: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    flow_id: Optional[str] = None


class TimelineGenerator:
    """Creates forensic timeline events from network protocol records."""

    def __init__(self):
        self.events: list[TimelineEventItem] = []

    def add_dns_event(
        self,
        timestamp: datetime,
        query_name: str,
        query_type: str,
        response_code: Optional[str],
        answers: list[str],
        src: str,
        dst: str,
        flow_id: Optional[str],
    ) -> TimelineEventItem:
        ans_text = f" -> Resolved to {', '.join(answers)}" if answers else ""
        desc = f"DNS Query: {query_name} ({query_type}){ans_text} [{response_code or 'NOERROR'}]"
        
        event = TimelineEventItem(
            id=str(uuid.uuid4()),
            event_time=timestamp,
            event_type="DNS_QUERY",
            title=f"DNS {query_type}: {query_name}",
            description=desc,
            severity="info",
            category="Resolution",
            protocol="DNS",
            src=src,
            dst=dst,
            flow_id=flow_id,
        )
        self.events.append(event)
        return event

    def add_tls_event(
        self,
        timestamp: datetime,
        version: str,
        sni: Optional[str],
        cipher_suite: Optional[str],
        src: str,
        dst: str,
        flow_id: Optional[str],
    ) -> TimelineEventItem:
        title = f"TLS Handshake ({version})"
        if sni:
            title += f": {sni}"
            desc = f"TLS Client Hello with SNI: {sni} [Cipher: {cipher_suite or 'negotiated'}]"
        else:
            desc = f"TLS {version} Handshake negotiation [Cipher: {cipher_suite or 'standard'}]"

        event = TimelineEventItem(
            id=str(uuid.uuid4()),
            event_time=timestamp,
            event_type="TLS_HANDSHAKE",
            title=title,
            description=desc,
            severity="info",
            category="Encryption",
            protocol="TLS",
            src=src,
            dst=dst,
            flow_id=flow_id,
        )
        self.events.append(event)
        return event

    def add_certificate_event(
        self,
        timestamp: datetime,
        subject_cn: Optional[str],
        issuer_cn: Optional[str],
        fingerprint: str,
        is_self_signed: bool,
        src: str,
        dst: str,
        flow_id: Optional[str],
    ) -> TimelineEventItem:
        title = f"Certificate: {subject_cn or fingerprint[:12]}"
        severity = "warning" if is_self_signed else "info"
        category = "Certificate"
        desc = f"X.509 Certificate for CN={subject_cn or 'Unknown'} issued by CN={issuer_cn or 'Unknown'} (SHA256: {fingerprint[:16]}...)"
        if is_self_signed:
            desc += " [Self-Signed Certificate Detected]"

        event = TimelineEventItem(
            id=str(uuid.uuid4()),
            event_time=timestamp,
            event_type="TLS_CERTIFICATE",
            title=title,
            description=desc,
            severity=severity,
            category=category,
            protocol="TLS",
            src=src,
            dst=dst,
            flow_id=flow_id,
        )
        self.events.append(event)
        return event

    def add_http_event(
        self,
        timestamp: datetime,
        is_request: bool,
        method: Optional[str],
        url: str,
        host: Optional[str],
        status_code: Optional[int],
        response_phrase: Optional[str],
        src: str,
        dst: str,
        flow_id: Optional[str],
    ) -> TimelineEventItem:
        if is_request:
            is_suspicious = any(s in url.lower() for s in ["/beacon", "/checkin", "c2", "gate.php", "cmd", "shell"])
            severity = "critical" if is_suspicious else "info"
            category = "C2 Traffic" if is_suspicious else "Web Traffic"
            title = f"HTTP {method} {host or ''}"
            desc = f"HTTP {method} {url} [Host: {host or 'Direct IP'}]"
            etype = "HTTP_REQUEST"
        else:
            severity = "warning" if status_code and status_code >= 400 else "info"
            category = "Web Traffic"
            title = f"HTTP Response: {status_code} {response_phrase or ''}"
            desc = f"HTTP {status_code} {response_phrase or 'OK'}"
            etype = "HTTP_RESPONSE"

        event = TimelineEventItem(
            id=str(uuid.uuid4()),
            event_time=timestamp,
            event_type=etype,
            title=title,
            description=desc,
            severity=severity,
            category=category,
            protocol="HTTP",
            src=src,
            dst=dst,
            flow_id=flow_id,
        )
        self.events.append(event)
        return event

    def get_sorted_events(self) -> list[TimelineEventItem]:
        return sorted(self.events, key=lambda e: e.event_time)

