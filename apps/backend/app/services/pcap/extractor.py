from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
from typing import Any, Optional

from app.services.pcap.certificate import parse_x509_certificate
from app.services.pcap.dns import parse_dns_payload
from app.services.pcap.http import parse_http_payload
from app.services.pcap.parser import PCAPParser
from app.services.pcap.tls import parse_tls_payload


class ProtocolExtractionCancelled(Exception):
    """Raised when protocol extraction is cancelled due to lease loss."""
    pass


def extract_protocols(
    file_path: str | Path,
    is_cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Extracts DNS records, HTTP requests, TLS metadata, and certificates from a capture file."""
    if is_cancelled and is_cancelled():
        raise ProtocolExtractionCancelled("Protocol extraction cancelled after processing ownership was lost")

    dns_records: list[dict[str, Any]] = []
    http_requests: list[dict[str, Any]] = []
    tls_records: list[dict[str, Any]] = []
    certificates: list[dict[str, Any]] = []
    timeline_events: list[dict[str, Any]] = []
    hostnames: dict[str, str] = {}
    flow_applications: dict[tuple, str] = {}
    flow_summaries: dict[tuple, str] = {}
    seen_cert_fps: set[str] = set()

    try:
        with open(str(file_path), "rb") as stream:
            parser = PCAPParser(stream)
            for packet in parser.iter_parsed_packets():
                if is_cancelled and is_cancelled():
                    raise ProtocolExtractionCancelled("Protocol extraction cancelled after processing ownership was lost")

                payload = packet.payload
                if not payload:
                    continue

                src_ip = packet.src_ip or ""
                dst_ip = packet.dst_ip or ""
                src_port = packet.src_port or 0
                dst_port = packet.dst_port or 0
                protocol = packet.protocol

                endpoints = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                canonical_key = endpoints + (protocol,)
                src_str = f"{src_ip}:{src_port}" if src_port else src_ip
                dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

                is_dns_port = src_port == 53 or dst_port == 53
                is_http_port = src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000)
                is_tls_port = src_port in (443, 8443) or dst_port in (443, 8443)

                # 1. DNS Extraction
                if (is_dns_port or protocol == "UDP"):
                    dns_info = parse_dns_payload(payload)
                    if dns_info:
                        flow_applications[canonical_key] = "DNS"
                        answers_data = [a.data for a in dns_info.answers]
                        ans_str = ", ".join(answers_data) if answers_data else ""
                        summary = f"DNS {dns_info.query_type}: {dns_info.query_name}"
                        if ans_str:
                            summary += f" -> {ans_str}"
                        flow_summaries[canonical_key] = summary

                        for ans in dns_info.answers:
                            if ans.type in ("A", "AAAA"):
                                hostnames[ans.data] = dns_info.query_name
                            elif ans.type == "PTR":
                                hostnames[dns_info.query_name.replace(".in-addr.arpa", "")] = ans.data

                        dns_records.append({
                            "canonical_key": canonical_key,
                            "timestamp": packet.timestamp,
                            "query_name": dns_info.query_name,
                            "query_type": dns_info.query_type,
                            "response_code": dns_info.response_code,
                            "answers": json.dumps(answers_data) if answers_data else None,
                            "ttl": dns_info.answers[0].ttl if dns_info.answers else None,
                        })

                        timeline_events.append({
                            "canonical_key": canonical_key,
                            "event_time": packet.timestamp,
                            "event_type": "dns_query" if not dns_info.is_response else "dns_response",
                            "title": f"DNS {dns_info.query_type} query for {dns_info.query_name}" if not dns_info.is_response else f"DNS response for {dns_info.query_name}",
                            "description": summary,
                            "severity": "info",
                            "category": "DNS",
                            "protocol": "DNS",
                            "src": src_str,
                            "dst": dst_str,
                        })

                # 2. TLS Extraction & Certificate Extraction
                if (is_tls_port or (len(payload) > 5 and payload[0] == 0x16)):
                    tls_handshakes = parse_tls_payload(payload)
                    if tls_handshakes:
                        flow_applications[canonical_key] = "TLS"
                        for hs in tls_handshakes:
                            if hs.is_client_hello and hs.sni:
                                flow_summaries[canonical_key] = f"TLS SNI: {hs.sni}"
                                if dst_ip:
                                    hostnames[dst_ip] = hs.sni

                            if hs.is_client_hello or hs.is_server_hello:
                                tls_records.append({
                                    "canonical_key": canonical_key,
                                    "timestamp": packet.timestamp,
                                    "version": hs.version,
                                    "sni": hs.sni,
                                    "cipher_suite": hs.cipher_suite,
                                    "alpn": hs.alpn,
                                })

                                timeline_events.append({
                                    "canonical_key": canonical_key,
                                    "event_time": packet.timestamp,
                                    "event_type": "tls_client_hello" if hs.is_client_hello else "tls_server_hello",
                                    "title": f"TLS Handshake ({hs.version})",
                                    "description": f"TLS SNI: {hs.sni or 'None'}, Cipher: {hs.cipher_suite or 'Unknown'}",
                                    "severity": "info",
                                    "category": "TLS",
                                    "protocol": "TLS",
                                    "src": src_str,
                                    "dst": dst_str,
                                })

                            if hs.raw_certificates:
                                for raw_cert in hs.raw_certificates:
                                    parsed_cert = parse_x509_certificate(raw_cert)
                                    if parsed_cert and parsed_cert.fingerprint_sha256 not in seen_cert_fps:
                                        seen_cert_fps.add(parsed_cert.fingerprint_sha256)
                                        if parsed_cert.subject_cn and src_ip:
                                            hostnames[src_ip] = parsed_cert.subject_cn

                                        certificates.append({
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

                                        timeline_events.append({
                                            "canonical_key": canonical_key,
                                            "event_time": packet.timestamp,
                                            "event_type": "tls_certificate",
                                            "title": f"X.509 Certificate: {parsed_cert.subject_cn or parsed_cert.fingerprint_sha256[:16]}",
                                            "description": f"Issuer: {parsed_cert.issuer_cn or 'Unknown'}, Self-Signed: {parsed_cert.is_self_signed}",
                                            "severity": "info",
                                            "category": "Certificates",
                                            "protocol": "TLS",
                                            "src": src_str,
                                            "dst": dst_str,
                                        })

                # 3. HTTP Extraction
                if (is_http_port or (len(payload) > 4 and payload[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD"))):
                    http_info = parse_http_payload(payload)
                    if http_info:
                        flow_applications[canonical_key] = "HTTP"
                        if http_info.is_request:
                            summary = f"HTTP {http_info.method} {http_info.path or ''}"
                            flow_summaries[canonical_key] = summary
                            if http_info.host and dst_ip:
                                hostnames[dst_ip] = http_info.host

                            http_requests.append({
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

                            timeline_events.append({
                                "canonical_key": canonical_key,
                                "event_time": packet.timestamp,
                                "event_type": "http_request",
                                "title": f"HTTP {http_info.method} {http_info.path or ''}",
                                "description": f"URL: {http_info.url}, Host: {http_info.host or 'Unknown'}",
                                "severity": "info",
                                "category": "HTTP",
                                "protocol": "HTTP",
                                "src": src_str,
                                "dst": dst_str,
                            })
                        else:
                            summary = f"HTTP Response: {http_info.status_code} {http_info.response_phrase or ''}"
                            flow_summaries[canonical_key] = summary

                            http_requests.append({
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

                            timeline_events.append({
                                "canonical_key": canonical_key,
                                "event_time": packet.timestamp,
                                "event_type": "http_response",
                                "title": f"HTTP Response {http_info.status_code}",
                                "description": summary,
                                "severity": "info",
                                "category": "HTTP",
                                "protocol": "HTTP",
                                "src": src_str,
                                "dst": dst_str,
                            })
    except ProtocolExtractionCancelled:
        raise
    except Exception:
        pass

    return {
        "dns_records": dns_records,
        "http_requests": http_requests,
        "tls_records": tls_records,
        "certificates": certificates,
        "hostnames": hostnames,
        "flow_applications": flow_applications,
        "flow_summaries": flow_summaries,
        "timeline_events": timeline_events,
    }
