from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.certificate import Certificate
from app.models.dns_record import DnsRecord
from app.models.http_request import HttpRequest
from app.models.tls_record import TlsRecord
from app.schemas.entities import (
    CertificateOut,
    DnsRecordOut,
    HttpRequestOut,
    TlsRecordOut,
)

router = APIRouter(tags=["protocols"])


@router.get("/dns", response_model=list[DnsRecordOut])
def list_dns_records(
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(DnsRecord)
    if capture_id:
        query = query.where(DnsRecord.capture_id == capture_id)
    return db.scalars(query.order_by(DnsRecord.timestamp.asc()).limit(limit)).all()


@router.get("/http", response_model=list[HttpRequestOut])
def list_http_requests(
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(HttpRequest)
    if capture_id:
        query = query.where(HttpRequest.capture_id == capture_id)
    return db.scalars(query.order_by(HttpRequest.timestamp.asc()).limit(limit)).all()


@router.get("/tls", response_model=list[TlsRecordOut])
def list_tls_records(
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(TlsRecord)
    if capture_id:
        query = query.where(TlsRecord.capture_id == capture_id)
    return db.scalars(query.order_by(TlsRecord.timestamp.asc()).limit(limit)).all()


@router.get("/certificates", response_model=list[CertificateOut])
def list_certificates(
    capture_id: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    query = select(Certificate)
    if capture_id:
        query = query.where(Certificate.capture_id == capture_id)
    return db.scalars(query.order_by(Certificate.created_at.asc()).limit(limit)).all()
