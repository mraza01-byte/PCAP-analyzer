from datetime import datetime, timezone

from sqlalchemy import update

from app.models import (
    Capture,
    CaptureStatus,
    Certificate,
    DnsRecord,
    Flow,
    Host,
    HttpRequest,
    TimelineEvent,
    TlsRecord,
)


class CaptureLeaseLost(Exception):
    """Raised when a worker no longer owns the capture processing lease."""


def persist_analysis(db, capture: Capture, analysis: dict, processing_token: str) -> None:
    claim = db.execute(
        update(Capture)
        .where(
            Capture.id == capture.id,
            Capture.status == CaptureStatus.PROCESSING,
            Capture.processing_token == processing_token,
            Capture.processing_lease_expires_at > datetime.now(timezone.utc),
        )
        .values(
            status=CaptureStatus.COMPLETED,
            processing_token=None,
            processing_lease_expires_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        raise CaptureLeaseLost(f"Processing lease was lost for capture {capture.id}")

    hostnames = analysis.get("hostnames", {})
    flow_apps = analysis.get("flow_applications", {})
    flow_sums = analysis.get("flow_summaries", {})

    hosts_by_ip = {}
    for data in analysis["hosts"]:
        hostname = data.get("hostname") or hostnames.get(data["ip_address"])
        if hostname:
            hostname = hostname[:255]
        host = Host(
            capture_id=capture.id,
            ip_address=data["ip_address"],
            mac_address=data["mac_address"],
            hostname=hostname,
            first_seen_at=data["first_seen_at"],
            last_seen_at=data["last_seen_at"],
            packet_count=data["packet_count"],
            bytes_sent=data["bytes_sent"],
            bytes_received=data["bytes_received"],
            open_ports=data["open_ports"],
            role=data.get("role", "Observed endpoint"),
            risk_score=data.get("risk_score", 0),
        )
        db.add(host)
        hosts_by_ip[data["ip_address"]] = host
    db.flush()

    flows_by_key = {}
    flows_by_canonical = {}
    for data in analysis["flows"]:
        src_port = data["src_port"] or 0
        dst_port = data["dst_port"] or 0
        canonical_key = tuple(sorted([(data["src_ip"], src_port), (data["dst_ip"], dst_port)])) + (data["protocol"],)

        application = flow_apps.get(canonical_key) or data.get("application") or ""
        summary = flow_sums.get(canonical_key) or data.get("summary")
        if summary:
            summary = summary[:512]

        flow = Flow(
            capture_id=capture.id,
            src_host_id=hosts_by_ip[data["src_ip"]].id,
            dst_host_id=hosts_by_ip[data["dst_ip"]].id,
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            start_time=data["start_time"],
            end_time=data["end_time"],
            packet_count=data["packet_count"],
            byte_count=data["bytes_total"],
            bytes_forward=data["bytes_forward"],
            bytes_reverse=data["bytes_reverse"],
            application=application[:32],
            tcp_flags=data["tcp_flags"],
            summary=summary,
            payload_preview=data.get("payload_preview"),
        )
        db.add(flow)
        flows_by_key[data["flow_key"]] = flow
        flows_by_canonical[canonical_key] = flow
    db.flush()

    for data in analysis["timeline_events"]:
        flow_obj = flows_by_key.get(data.get("flow_key"))
        if not flow_obj and data.get("canonical_key"):
            flow_obj = flows_by_canonical.get(data["canonical_key"])
        flow_id = flow_obj.id if flow_obj else None
        db.add(TimelineEvent(
            capture_id=capture.id,
            flow_id=flow_id,
            event_time=data["event_time"],
            event_type=data["event_type"][:64],
            title=data["title"][:255],
            description=data["description"],
            severity=data.get("severity", "info"),
            category=data.get("category", "General"),
            protocol=data.get("protocol", flow_obj.protocol if flow_obj else None),
            src=data.get("src"),
            dst=data.get("dst"),
        ))

    # Persist extracted protocol entities
    for data in analysis.get("dns_records", []):
        flow_obj = flows_by_canonical.get(data.get("canonical_key"))
        response_code = data.get("response_code")
        db.add(DnsRecord(
            capture_id=capture.id,
            flow_id=flow_obj.id if flow_obj else None,
            timestamp=data["timestamp"],
            query_name=data["query_name"][:255],
            query_type=data["query_type"][:16],
            response_code=response_code[:16] if response_code else None,
            answers=data.get("answers"),
            ttl=data.get("ttl"),
        ))

    for data in analysis.get("http_requests", []):
        flow_obj = flows_by_canonical.get(data.get("canonical_key"))
        host = data.get("host")
        path = data.get("path")
        user_agent = data.get("user_agent")
        response_phrase = data.get("response_phrase")
        content_type = data.get("content_type")
        db.add(HttpRequest(
            capture_id=capture.id,
            flow_id=flow_obj.id if flow_obj else None,
            timestamp=data["timestamp"],
            method=data["method"][:16],
            host=host[:255] if host else None,
            url=data.get("url") or "",
            path=path[:1024] if path else None,
            user_agent=user_agent[:512] if user_agent else None,
            status_code=data.get("status_code"),
            response_phrase=response_phrase[:64] if response_phrase else None,
            content_type=content_type[:128] if content_type else None,
        ))

    for data in analysis.get("tls_records", []):
        flow_obj = flows_by_canonical.get(data.get("canonical_key"))
        sni = data.get("sni")
        cipher_suite = data.get("cipher_suite")
        alpn = data.get("alpn")
        db.add(TlsRecord(
            capture_id=capture.id,
            flow_id=flow_obj.id if flow_obj else None,
            timestamp=data["timestamp"],
            version=data["version"][:32],
            sni=sni[:255] if sni else None,
            cipher_suite=cipher_suite[:128] if cipher_suite else None,
            alpn=alpn[:64] if alpn else None,
        ))

    for data in analysis.get("certificates", []):
        flow_obj = flows_by_canonical.get(data.get("canonical_key"))
        subject_cn = data.get("subject_cn")
        subject_org = data.get("subject_org")
        issuer_cn = data.get("issuer_cn")
        issuer_org = data.get("issuer_org")
        serial_number = data.get("serial_number")
        db.add(Certificate(
            capture_id=capture.id,
            flow_id=flow_obj.id if flow_obj else None,
            fingerprint_sha256=data["fingerprint_sha256"][:64],
            subject_cn=subject_cn[:255] if subject_cn else None,
            subject_org=subject_org[:255] if subject_org else None,
            issuer_cn=issuer_cn[:255] if issuer_cn else None,
            issuer_org=issuer_org[:255] if issuer_org else None,
            valid_from=data.get("valid_from"),
            valid_to=data.get("valid_to"),
            serial_number=serial_number[:128] if serial_number else None,
            san_list=data.get("san_list"),
            is_self_signed=data.get("is_self_signed", False),
        ))

    capture.packet_count = analysis["packet_count"]
    capture.first_packet_at = analysis["first_packet_at"]
    capture.last_packet_at = analysis["last_packet_at"]
    capture.error_message = None
    capture.status = CaptureStatus.COMPLETED
    capture.processing_token = None
    capture.processing_lease_expires_at = None
    db.commit()
