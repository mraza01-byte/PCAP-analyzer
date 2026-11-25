from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.search import contains_pattern
from app.database.session import get_db
from app.models.certificate import Certificate
from app.models.dns_record import DnsRecord
from app.models.flow import Flow
from app.models.http_request import HttpRequest
from app.models.tls_record import TlsRecord
from app.schemas.entities import (
    CertificateOut,
    CertificateStats,
    DnsRecordOut,
    DnsStats,
    HttpStats,
    HttpRequestOut,
    ProtocolDistributionItem,
    ProtocolStatsOut,
    TlsRecordOut,
    TlsStats,
)

router = APIRouter(tags=["protocols"])


@router.get("/dns", response_model=list[DnsRecordOut])
@router.get("/protocols/dns", response_model=list[DnsRecordOut])
def list_dns_records(
    capture_id: str | None = None,
    query_type: str | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(DnsRecord)
    if capture_id:
        query = query.where(DnsRecord.capture_id == capture_id)
    if query_type:
        query = query.where(func.upper(DnsRecord.query_type) == query_type.upper())
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                DnsRecord.query_name.like(pattern, escape="\\"),
                DnsRecord.answers.like(pattern, escape="\\"),
                DnsRecord.response_code.like(pattern, escape="\\"),
            )
        )
    return db.scalars(query.order_by(DnsRecord.timestamp.asc()).limit(limit)).all()


@router.get("/http", response_model=list[HttpRequestOut])
@router.get("/protocols/http", response_model=list[HttpRequestOut])
def list_http_requests(
    capture_id: str | None = None,
    method: str | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(HttpRequest)
    if capture_id:
        query = query.where(HttpRequest.capture_id == capture_id)
    if method:
        query = query.where(func.upper(HttpRequest.method) == method.upper())
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                HttpRequest.url.like(pattern, escape="\\"),
                HttpRequest.host.like(pattern, escape="\\"),
                HttpRequest.user_agent.like(pattern, escape="\\"),
                HttpRequest.method.like(pattern, escape="\\"),
                HttpRequest.content_type.like(pattern, escape="\\"),
            )
        )
    return db.scalars(query.order_by(HttpRequest.timestamp.asc()).limit(limit)).all()


@router.get("/tls", response_model=list[TlsRecordOut])
@router.get("/protocols/tls", response_model=list[TlsRecordOut])
def list_tls_records(
    capture_id: str | None = None,
    version: str | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(TlsRecord)
    if capture_id:
        query = query.where(TlsRecord.capture_id == capture_id)
    if version:
        query = query.where(func.upper(TlsRecord.version) == version.upper())
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                TlsRecord.sni.like(pattern, escape="\\"),
                TlsRecord.cipher_suite.like(pattern, escape="\\"),
                TlsRecord.version.like(pattern, escape="\\"),
                TlsRecord.alpn.like(pattern, escape="\\"),
            )
        )
    return db.scalars(query.order_by(TlsRecord.timestamp.asc()).limit(limit)).all()


@router.get("/certificates", response_model=list[CertificateOut])
@router.get("/protocols/certificates", response_model=list[CertificateOut])
def list_certificates(
    capture_id: str | None = None,
    self_signed: bool | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(Certificate)
    if capture_id:
        query = query.where(Certificate.capture_id == capture_id)
    if self_signed is not None:
        query = query.where(Certificate.is_self_signed == self_signed)
    if search:
        pattern = contains_pattern(search)
        query = query.where(
            or_(
                Certificate.subject_cn.like(pattern, escape="\\"),
                Certificate.subject_org.like(pattern, escape="\\"),
                Certificate.issuer_cn.like(pattern, escape="\\"),
                Certificate.issuer_org.like(pattern, escape="\\"),
                Certificate.fingerprint_sha256.like(pattern, escape="\\"),
                Certificate.san_list.like(pattern, escape="\\"),
            )
        )
    return db.scalars(query.order_by(Certificate.created_at.asc()).limit(limit)).all()


@router.get("/protocols/stats", response_model=ProtocolStatsOut)
@router.get("/protocols/overview", response_model=ProtocolStatsOut)
def get_protocol_stats(
    capture_id: str | None = None,
    db: Session = Depends(get_db),
) -> ProtocolStatsOut:
    """Aggregated protocol intelligence and categorization statistics."""
    # 1. DNS Stats
    dns_query = select(DnsRecord)
    if capture_id:
        dns_query = dns_query.where(DnsRecord.capture_id == capture_id)
    dns_records = db.scalars(dns_query).all()
    total_dns = len(dns_records)
    type_counts = Counter(r.query_type for r in dns_records if r.query_type)
    rcode_counts = Counter(r.response_code for r in dns_records if r.response_code)
    domain_counts = Counter(r.query_name for r in dns_records if r.query_name)
    top_domains = [{"name": dom, "count": cnt} for dom, cnt in domain_counts.most_common(10)]
    total_queries = sum(1 for r in dns_records if not r.response_code)
    total_responses = sum(1 for r in dns_records if r.response_code)

    # 2. HTTP Stats
    http_query = select(HttpRequest)
    if capture_id:
        http_query = http_query.where(HttpRequest.capture_id == capture_id)
    http_records = db.scalars(http_query).all()
    total_http = len(http_records)
    method_counts = Counter(r.method for r in http_records if r.method)
    status_counts = Counter(str(r.status_code) for r in http_records if r.status_code is not None)
    host_counts = Counter(r.host for r in http_records if r.host)
    ua_counts = Counter(r.user_agent for r in http_records if r.user_agent)
    ct_counts = Counter(r.content_type.split(";")[0].strip() for r in http_records if r.content_type)
    top_hosts = [{"host": h, "count": cnt} for h, cnt in host_counts.most_common(10)]
    top_uas = [{"user_agent": ua, "count": cnt} for ua, cnt in ua_counts.most_common(10)]

    # 3. TLS Stats
    tls_query = select(TlsRecord)
    if capture_id:
        tls_query = tls_query.where(TlsRecord.capture_id == capture_id)
    tls_records = db.scalars(tls_query).all()
    total_tls = len(tls_records)
    ver_counts = Counter(r.version for r in tls_records if r.version)
    sni_counts = Counter(r.sni for r in tls_records if r.sni)
    cipher_counts = Counter(r.cipher_suite for r in tls_records if r.cipher_suite)
    alpn_counts = Counter(r.alpn for r in tls_records if r.alpn)
    top_sni = [{"sni": s, "count": cnt} for s, cnt in sni_counts.most_common(10)]
    top_ciphers = [{"cipher": c, "count": cnt} for c, cnt in cipher_counts.most_common(10)]
    top_alpn = [{"alpn": a, "count": cnt} for a, cnt in alpn_counts.most_common(10)]

    # 4. Certificates Stats
    cert_query = select(Certificate)
    if capture_id:
        cert_query = cert_query.where(Certificate.capture_id == capture_id)
    cert_records = db.scalars(cert_query).all()
    total_certs = len(cert_records)
    self_signed_count = sum(1 for c in cert_records if c.is_self_signed)
    now = datetime.now(timezone.utc)

    def is_expired(c: Certificate) -> bool:
        if not c.valid_to:
            return False
        vt = c.valid_to if c.valid_to.tzinfo else c.valid_to.replace(tzinfo=timezone.utc)
        return vt < now

    expired_count = sum(1 for c in cert_records if is_expired(c))
    valid_count = total_certs - expired_count
    issuer_counts = Counter(c.issuer_cn or c.issuer_org or "Unknown" for c in cert_records)
    top_issuers = [{"issuer": iss, "count": cnt} for iss, cnt in issuer_counts.most_common(10)]

    # 5. Protocol Categorization across Flows
    flow_query = select(Flow)
    if capture_id:
        flow_query = flow_query.where(Flow.capture_id == capture_id)
    flows = db.scalars(flow_query).all()
    total_flows = len(flows)
    total_bytes_all = sum(f.byte_count for f in flows) or 1

    def categorize(app: str, proto: str) -> tuple[str, str]:
        app_upper = (app or "").upper()
        proto_upper = (proto or "").upper()
        if app_upper in ("DNS", "MDNS", "LLMNR"):
            return "DNS & Resolution", app_upper or "DNS"
        elif app_upper in ("HTTP", "REST", "API"):
            return "Web (Cleartext)", "HTTP"
        elif app_upper in ("TLS", "HTTPS", "SSL"):
            return "Encrypted Web / TLS", "TLS"
        elif app_upper in ("SMB", "NBNS", "SAMBA", "NETBIOS"):
            return "File Sharing", app_upper
        elif app_upper in ("SSH", "TELNET", "RDP"):
            return "Remote Administration", app_upper
        elif proto_upper in ("ICMP", "ICMPV6"):
            return "Network Diagnostics", proto_upper
        elif proto_upper == "TCP":
            return "General TCP", app_upper or "TCP"
        elif proto_upper == "UDP":
            return "General UDP", app_upper or "UDP"
        else:
            return "Other Protocols", proto_upper or "OTHER"

    group_stats: dict[str, dict[str, Any]] = {}
    for f in flows:
        category, key = categorize(f.application, f.protocol)
        dict_key = f"{category}::{key}"
        if dict_key not in group_stats:
            group_stats[dict_key] = {
                "category": category,
                "protocol": f.protocol,
                "application": key,
                "flow_count": 0,
                "packet_count": 0,
                "byte_count": 0,
            }
        group_stats[dict_key]["flow_count"] += 1
        group_stats[dict_key]["packet_count"] += f.packet_count
        group_stats[dict_key]["byte_count"] += f.byte_count

    distribution_items = []
    for item in sorted(group_stats.values(), key=lambda x: x["byte_count"], reverse=True):
        pct = round((item["byte_count"] / total_bytes_all) * 100.0, 2)
        distribution_items.append(
            ProtocolDistributionItem(
                category=item["category"],
                protocol=item["protocol"],
                application=item["application"],
                flow_count=item["flow_count"],
                packet_count=item["packet_count"],
                byte_count=item["byte_count"],
                percentage=pct,
            )
        )

    return ProtocolStatsOut(
        total_dns=total_dns,
        total_http=total_http,
        total_tls=total_tls,
        total_certificates=total_certs,
        total_flows=total_flows,
        protocol_distribution=distribution_items,
        dns_stats=DnsStats(
            total_queries=total_queries,
            total_responses=total_responses,
            by_type=dict(type_counts),
            by_response_code=dict(rcode_counts),
            top_domains=top_domains,
        ),
        http_stats=HttpStats(
            by_method=dict(method_counts),
            by_status=dict(status_counts),
            top_hosts=top_hosts,
            top_user_agents=top_uas,
            content_types=dict(ct_counts),
        ),
        tls_stats=TlsStats(
            by_version=dict(ver_counts),
            top_sni=top_sni,
            top_ciphers=top_ciphers,
            top_alpn=top_alpn,
        ),
        certificate_stats=CertificateStats(
            total_certs=total_certs,
            self_signed_count=self_signed_count,
            expired_count=expired_count,
            valid_count=valid_count,
            top_issuers=top_issuers,
        ),
    )
