from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.models.capture import Capture, CaptureFormat, CaptureStatus
from app.models.certificate import Certificate
from app.models.dns_record import DnsRecord
from app.models.flow import Flow
from app.models.host import Host
from app.models.http_request import HttpRequest
from app.models.timeline_event import TimelineEvent
from app.models.tls_record import TlsRecord
from app.services.pcap.certificate import parse_x509_certificate
from app.services.pcap.dns import parse_dns_payload
from app.services.pcap.flow_tracker import FlowTracker
from app.services.pcap.host_tracker import HostTracker
from app.services.pcap.http import parse_http_payload
from app.services.pcap.parser import PCAPParser
from app.services.pcap.timeline_generator import TimelineGenerator
from app.services.pcap.tls import parse_tls_payload


@dataclass
class IngestionResult:
    capture_id: str
    packet_count: int
    hosts_count: int
    flows_count: int
    dns_count: int
    http_count: int
    tls_count: int
    cert_count: int
    timeline_count: int
    first_packet_at: Optional[datetime]
    last_packet_at: Optional[datetime]


def ingest_pcap_file(
    file_path: str,
    capture: Capture,
    db: Session,
) -> IngestionResult:
    """Executes the full forensic ingestion pipeline on a PCAP or PCAPNG evidence file.
    
    Pipeline:
    PCAP Import -> Host Discovery -> Flow Generation -> DNS/HTTP/TLS Extraction -> Conversation Mapping -> Timeline Generation
    """
    capture.status = CaptureStatus.PROCESSING
    db.commit()

    parser = PCAPParser.from_file(file_path)
    flow_tracker = FlowTracker()
    host_tracker = HostTracker()
    timeline_gen = TimelineGenerator()

    dns_records_to_insert: list[dict] = []
    http_records_to_insert: list[dict] = []
    tls_records_to_insert: list[dict] = []
    cert_records_to_insert: list[dict] = []

    packet_count = 0
    first_packet_at: Optional[datetime] = None
    last_packet_at: Optional[datetime] = None

    seen_cert_fingerprints: set[str] = set()

    for packet in parser.iter_parsed_packets():
        packet_count += 1
        if first_packet_at is None:
            first_packet_at = packet.timestamp
        last_packet_at = packet.timestamp

        # 1. Host Discovery tracking
        host_tracker.process_packet(packet)

        detected_app: Optional[str] = None
        summary_hint: Optional[str] = None
        current_flow_id: Optional[str] = None

        src_str = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip or ""
        dst_str = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip or ""

        # Pre-calculate flow canonical key to get stable flow_id
        src_endpoint = (packet.src_ip or "", packet.src_port or 0)
        dst_endpoint = (packet.dst_ip or "", packet.dst_port or 0)
        canonical_key = tuple(sorted([src_endpoint, dst_endpoint])) + (packet.protocol,)
        existing_flow = flow_tracker.get_flow(canonical_key)

        # 2. Protocol Extraction
        payload = packet.payload
        is_dns_port = packet.src_port == 53 or packet.dst_port == 53
        is_http_port = packet.src_port in (80, 8080, 8000) or packet.dst_port in (80, 8080, 8000)
        is_tls_port = packet.src_port in (443, 8443) or packet.dst_port in (443, 8443)

        # DNS Extraction
        if (is_dns_port or packet.protocol == "UDP") and payload:
            dns_info = parse_dns_payload(payload)
            if dns_info:
                detected_app = "DNS"
                answers_data = [a.data for a in dns_info.answers]
                ans_str = ", ".join(answers_data) if answers_data else None
                summary_hint = f"DNS {dns_info.query_type}: {dns_info.query_name}"
                if ans_str:
                    summary_hint += f" -> {ans_str}"

                # Correlate resolved IPs with hostnames in HostTracker
                for ans in dns_info.answers:
                    if ans.type in ("A", "AAAA"):
                        host_tracker.associate_hostname(ans.data, dns_info.query_name)
                    elif ans.type == "PTR":
                        host_tracker.associate_hostname(dns_info.query_name.replace(".in-addr.arpa", ""), ans.data)

                # Store for insertion
                dns_records_to_insert.append({
                    "capture_id": capture.id,
                    "canonical_key": canonical_key,
                    "timestamp": packet.timestamp,
                    "query_name": dns_info.query_name,
                    "query_type": dns_info.query_type,
                    "response_code": dns_info.response_code,
                    "answers": json.dumps(answers_data) if answers_data else None,
                    "ttl": dns_info.answers[0].ttl if dns_info.answers else None,
                })

                # Timeline event
                timeline_gen.add_dns_event(
                    timestamp=packet.timestamp,
                    query_name=dns_info.query_name,
                    query_type=dns_info.query_type,
                    response_code=dns_info.response_code,
                    answers=answers_data,
                    src=src_str,
                    dst=dst_str,
                    flow_id=existing_flow.id if existing_flow else None,
                )

        # TLS Extraction & Certificate Extraction
        if (is_tls_port or (len(payload) > 5 and payload[0] == 0x16)) and payload:
            tls_handshakes = parse_tls_payload(payload)
            if tls_handshakes:
                detected_app = "TLS"
                for hs in tls_handshakes:
                    if hs.is_client_hello and hs.sni:
                        summary_hint = f"TLS SNI: {hs.sni}"
                        # Associate SNI domain with destination host
                        if packet.dst_ip:
                            host_tracker.associate_hostname(packet.dst_ip, hs.sni)

                    # Add TLS record
                    if hs.is_client_hello or hs.is_server_hello:
                        tls_records_to_insert.append({
                            "capture_id": capture.id,
                            "canonical_key": canonical_key,
                            "timestamp": packet.timestamp,
                            "version": hs.version,
                            "sni": hs.sni,
                            "cipher_suite": hs.cipher_suite,
                            "alpn": hs.alpn,
                        })

                        timeline_gen.add_tls_event(
                            timestamp=packet.timestamp,
                            version=hs.version,
                            sni=hs.sni,
                            cipher_suite=hs.cipher_suite,
                            src=src_str,
                            dst=dst_str,
                            flow_id=existing_flow.id if existing_flow else None,
                        )

                    # Extract X.509 Certificates
                    if hs.raw_certificates:
                        for raw_cert in hs.raw_certificates:
                            parsed_cert = parse_x509_certificate(raw_cert)
                            if parsed_cert and parsed_cert.fingerprint_sha256 not in seen_cert_fingerprints:
                                seen_cert_fingerprints.add(parsed_cert.fingerprint_sha256)

                                if parsed_cert.subject_cn and packet.src_ip:
                                    host_tracker.associate_hostname(packet.src_ip, parsed_cert.subject_cn)

                                cert_records_to_insert.append({
                                    "capture_id": capture.id,
                                    "canonical_key": canonical_key,
                                    "fingerprint_sha256": parsed_cert.fingerprint_sha256,
                                    "subject_cn": parsed_cert.subject_cn,
                                    "subject_org": parsed_cert.subject_org,
                                    "issuer_cn": parsed_cert.issuer_cn,
                                    "issuer_org": parsed_cert.issuer_org,
                                    "valid_from": parsed_cert.valid_from,
                                    "valid_to": parsed_cert.valid_to,
                                    "serial_number": parsed_cert.serial_number,
                                    "san_list": json.dumps(parsed_cert.san_list) if parsed_cert.san_list else None,
                                    "is_self_signed": parsed_cert.is_self_signed,
                                })

                                timeline_gen.add_certificate_event(
                                    timestamp=packet.timestamp,
                                    subject_cn=parsed_cert.subject_cn,
                                    issuer_cn=parsed_cert.issuer_cn,
                                    fingerprint=parsed_cert.fingerprint_sha256,
                                    is_self_signed=parsed_cert.is_self_signed,
                                    src=src_str,
                                    dst=dst_str,
                                    flow_id=existing_flow.id if existing_flow else None,
                                )

        # HTTP Extraction
        if (is_http_port or (len(payload) > 4 and payload[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD"))) and payload:
            http_info = parse_http_payload(payload)
            if http_info:
                detected_app = "HTTP"
                if http_info.is_request:
                    summary_hint = f"HTTP {http_info.method} {http_info.path or ''}"
                    if http_info.host and packet.dst_ip:
                        host_tracker.associate_hostname(packet.dst_ip, http_info.host)

                    http_records_to_insert.append({
                        "capture_id": capture.id,
                        "canonical_key": canonical_key,
                        "timestamp": packet.timestamp,
                        "method": http_info.method or "GET",
                        "host": http_info.host,
                        "url": http_info.url,
                        "path": http_info.path,
                        "user_agent": http_info.user_agent,
                        "status_code": None,
                        "response_phrase": None,
                        "content_type": http_info.content_type,
                    })

                    timeline_gen.add_http_event(
                        timestamp=packet.timestamp,
                        is_request=True,
                        method=http_info.method,
                        url=http_info.url,
                        host=http_info.host,
                        status_code=None,
                        response_phrase=None,
                        src=src_str,
                        dst=dst_str,
                        flow_id=existing_flow.id if existing_flow else None,
                    )
                else:
                    summary_hint = f"HTTP Response: {http_info.status_code} {http_info.response_phrase or ''}"
                    http_records_to_insert.append({
                        "capture_id": capture.id,
                        "canonical_key": canonical_key,
                        "timestamp": packet.timestamp,
                        "method": "RESPONSE",
                        "host": None,
                        "url": "",
                        "path": None,
                        "user_agent": None,
                        "status_code": http_info.status_code,
                        "response_phrase": http_info.response_phrase,
                        "content_type": http_info.content_type,
                    })

                    timeline_gen.add_http_event(
                        timestamp=packet.timestamp,
                        is_request=False,
                        method=None,
                        url="",
                        host=None,
                        status_code=http_info.status_code,
                        response_phrase=http_info.response_phrase,
                        src=src_str,
                        dst=dst_str,
                        flow_id=existing_flow.id if existing_flow else None,
                    )

        # 3. Flow Generation & Conversation Mapping
        flow_item = flow_tracker.process_packet(packet, detected_app=detected_app, summary_hint=summary_hint)

    # Finalize host profiles
    host_tracker.finalize_profiles()

    # 4. Save Extracted Data into Database within Transaction
    # Insert Hosts
    host_orm_map: dict[str, Host] = {}
    for h_item in host_tracker.hosts.values():
        h_orm = Host(
            id=h_item.id,
            capture_id=capture.id,
            ip_address=h_item.ip_address,
            mac_address=h_item.mac_address,
            hostname=h_item.hostname,
            first_seen_at=h_item.first_seen_at,
            last_seen_at=h_item.last_seen_at,
            role=h_item.role,
            bytes_sent=h_item.bytes_sent,
            bytes_received=h_item.bytes_received,
            packet_count=h_item.packet_count,
            open_ports=h_item.to_open_ports_json(),
            risk_score=h_item.risk_score,
        )
        db.add(h_orm)
        host_orm_map[h_item.ip_address] = h_orm

    db.flush()

    # Insert Flows
    canonical_to_flow_id: dict[tuple, str] = {}
    for f_item in flow_tracker.flows.values():
        src_h = host_orm_map.get(f_item.src_ip)
        dst_h = host_orm_map.get(f_item.dst_ip)
        if not src_h or not dst_h:
            continue

        flow_summary = f_item.summary or f"{f_item.src_ip}:{f_item.src_port or 0} <-> {f_item.dst_ip}:{f_item.dst_port or 0} ({f_item.application or f_item.protocol})"

        f_orm = Flow(
            id=f_item.id,
            capture_id=capture.id,
            src_host_id=src_h.id,
            dst_host_id=dst_h.id,
            src_port=f_item.src_port,
            dst_port=f_item.dst_port,
            protocol=f_item.protocol,
            start_time=f_item.start_time,
            end_time=f_item.end_time,
            packet_count=f_item.packet_count,
            byte_count=f_item.byte_count,
            bytes_forward=f_item.bytes_forward,
            bytes_reverse=f_item.bytes_reverse,
            application=f_item.application,
            tcp_flags=f_item.tcp_flags_str,
            summary=flow_summary,
            payload_preview=f_item.payload_preview,
        )
        db.add(f_orm)
        canonical_to_flow_id[f_item.canonical_key] = f_item.id

    db.flush()

    # Insert Protocol Records with mapped flow_ids
    for d_dict in dns_records_to_insert:
        ck = d_dict.pop("canonical_key", None)
        flow_id = canonical_to_flow_id.get(ck)
        db.add(DnsRecord(**d_dict, flow_id=flow_id))

    for h_dict in http_records_to_insert:
        ck = h_dict.pop("canonical_key", None)
        flow_id = canonical_to_flow_id.get(ck)
        db.add(HttpRequest(**h_dict, flow_id=flow_id))

    for t_dict in tls_records_to_insert:
        ck = t_dict.pop("canonical_key", None)
        flow_id = canonical_to_flow_id.get(ck)
        db.add(TlsRecord(**t_dict, flow_id=flow_id))

    for c_dict in cert_records_to_insert:
        ck = c_dict.pop("canonical_key", None)
        flow_id = canonical_to_flow_id.get(ck)
        db.add(Certificate(**c_dict, flow_id=flow_id))

    # Insert Timeline Events
    for t_item in timeline_gen.get_sorted_events():
        db.add(TimelineEvent(
            id=t_item.id,
            capture_id=capture.id,
            flow_id=t_item.flow_id,
            event_time=t_item.event_time,
            event_type=t_item.event_type,
            title=t_item.title,
            description=t_item.description,
            severity=t_item.severity,
            category=t_item.category,
            protocol=t_item.protocol,
            src=t_item.src,
            dst=t_item.dst,
        ))

    # Update Capture status and statistics
    capture.packet_count = packet_count
    capture.first_packet_at = first_packet_at
    capture.last_packet_at = last_packet_at
    capture.status = CaptureStatus.COMPLETED
    db.commit()

    return IngestionResult(
        capture_id=capture.id,
        packet_count=packet_count,
        hosts_count=len(host_tracker.hosts),
        flows_count=len(flow_tracker.flows),
        dns_count=len(dns_records_to_insert),
        http_count=len(http_records_to_insert),
        tls_count=len(tls_records_to_insert),
        cert_count=len(cert_records_to_insert),
        timeline_count=len(timeline_gen.events),
        first_packet_at=first_packet_at,
        last_packet_at=last_packet_at,
    )

