from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from starlette.concurrency import run_in_threadpool

from engine.services.analyzer import (
    CaptureAnalysisCancelled,
    CaptureAnalysisError,
    analyze_capture,
    detect_capture_format,
)
from app.core.config import get_settings
from app.database.session import get_db, get_session_factory
from app.models.capture import Capture, CaptureFormat, CaptureStatus
from app.models.dns_record import DnsRecord
from app.models.flow import Flow
from app.models.host import Host
from app.schemas.entities import CaptureOut, FlowOut, HostOut, NetworkMapOut
from app.services.capture_processing import CaptureLeaseLost, persist_analysis

router = APIRouter(prefix="/captures", tags=["captures"])
logger = logging.getLogger(__name__)
PROCESSING_LEASE_SECONDS = 120
PROCESSING_HEARTBEAT_SECONDS = 30


class ProcessingLease:
    def __init__(self) -> None:
        self.lost = Event()
        self._lock = Lock()

    def renew(self, capture_id: str, processing_token: str) -> bool:
        with self._lock:
            if self.lost.is_set():
                return False
            if not _renew_processing_lease(capture_id, processing_token):
                self.lost.set()
                return False
            return True

    def mark_failed(self, db: Session, capture_id: str, processing_token: str, message: str) -> bool:
        with self._lock:
            if self.lost.is_set():
                return False
            return _mark_capture_failed(db, capture_id, processing_token, message)

    def persist(self, db: Session, capture: Capture, analysis: dict, processing_token: str) -> None:
        with self._lock:
            if self.lost.is_set():
                raise CaptureLeaseLost(f"Processing lease was lost for capture {capture.id}")
            persist_analysis(db, capture, analysis, processing_token)


@router.get("", response_model=list[CaptureOut])
@router.get("/", response_model=list[CaptureOut], include_in_schema=False)
def list_captures(db: Session = Depends(get_db)):
    captures = db.scalars(select(Capture).order_by(Capture.created_at.desc())).all()
    return [_serialize_capture(db, capture) for capture in captures]


@router.post("", response_model=CaptureOut, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=CaptureOut, status_code=status.HTTP_201_CREATED, include_in_schema=False)
@router.post("/upload", response_model=CaptureOut, status_code=status.HTTP_201_CREATED)
async def upload_capture(
    response: Response,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    capture_id = str(uuid.uuid4())
    evidence_path: Path | None = None
    evidence_persisted = False
    size = 0
    digest = hashlib.sha256()

    try:
        first_chunk = await file.read(1024 * 1024)
        if not first_chunk:
            raise HTTPException(status_code=400, detail="The uploaded capture is empty")
        size += len(first_chunk)
        if size > settings.max_upload_size_bytes:
            raise HTTPException(status_code=413, detail="Capture exceeds the configured upload limit")

        settings.evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = settings.evidence_dir / f"{capture_id}.capture"

        descriptor = os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            chunk = first_chunk
            while chunk:
                if size > settings.max_upload_size_bytes:
                    raise HTTPException(status_code=413, detail="Capture exceeds the configured upload limit")
                digest.update(chunk)
                destination.write(chunk)
                chunk = await file.read(1024 * 1024)
                size += len(chunk)

        try:
            file_format = detect_capture_format(evidence_path)
        except CaptureAnalysisError as error:
            raise HTTPException(status_code=415, detail=str(error)) from error

        sha256 = digest.hexdigest()
        _begin_upload_claim(db)
        existing = db.scalar(select(Capture).where(Capture.sha256 == sha256))
        now = datetime.now(timezone.utc)
        claimable = or_(
            Capture.status == CaptureStatus.FAILED,
            and_(
                Capture.status == CaptureStatus.PROCESSING,
                or_(
                    Capture.processing_lease_expires_at.is_(None),
                    Capture.processing_lease_expires_at <= now,
                ),
            ),
        )
        can_claim_existing = existing and (
            existing.status == CaptureStatus.FAILED
            or (
                existing.status == CaptureStatus.PROCESSING
                and (
                    existing.processing_lease_expires_at is None
                    or existing.processing_lease_expires_at <= now
                )
            )
        )
        if existing and not can_claim_existing:
            existing_id = existing.id
            db.rollback()
            existing = db.get(Capture, existing_id)
            if existing is None:
                raise HTTPException(status_code=500, detail="Duplicate capture disappeared during upload")
            evidence_path.unlink(missing_ok=True)
            response.status_code = 200
            return _serialize_capture(db, existing)

        filename = _safe_filename(file.filename)
        processing_token = str(uuid.uuid4())
        lease_expires_at = now + timedelta(seconds=PROCESSING_LEASE_SECONDS)
        previous_evidence_path = None
        if existing:
            capture_id = existing.id
            previous_evidence_path = Path(existing.file_path).resolve()
            claim = db.execute(
                update(Capture)
                .where(
                    Capture.id == capture_id,
                    Capture.sha256 == sha256,
                    claimable,
                )
                .values(
                    original_filename=filename,
                    file_path=str(evidence_path.resolve()),
                    file_size_bytes=size,
                    file_format=CaptureFormat(file_format),
                    status=CaptureStatus.PROCESSING,
                    error_message=None,
                    processing_token=processing_token,
                    processing_lease_expires_at=lease_expires_at,
                )
                .execution_options(synchronize_session=False)
            )
            if claim.rowcount != 1:
                db.rollback()
                existing = db.scalar(select(Capture).where(Capture.sha256 == sha256))
                if existing is None:
                    raise HTTPException(status_code=500, detail="Failed capture disappeared during retry")
                _remove_unpersisted_evidence(evidence_path, capture_id)
                response.status_code = 200
                return _serialize_capture(db, existing)
            try:
                db.commit()
            except Exception as error:
                db.rollback()
                logger.exception("Could not claim failed capture for retry", extra={"capture_id": capture_id})
                raise HTTPException(status_code=500, detail="Could not claim failed capture for retry") from error
            db.expire(existing)
            capture = db.get(Capture, capture_id)
            if capture is None:
                raise HTTPException(status_code=500, detail="Failed capture disappeared after retry claim")
            response.status_code = 200
        else:
            capture = Capture(
                id=capture_id,
                original_filename=filename,
                file_path=str(evidence_path.resolve()),
                file_size_bytes=size,
                sha256=sha256,
                file_format=CaptureFormat(file_format),
                status=CaptureStatus.PROCESSING,
                processing_token=processing_token,
                processing_lease_expires_at=lease_expires_at,
            )
        db.add(capture)
        if existing is None:
            try:
                db.commit()
            except IntegrityError as error:
                db.rollback()
                duplicate = db.scalar(select(Capture).where(Capture.sha256 == sha256))
                if duplicate:
                    _remove_unpersisted_evidence(evidence_path, capture_id)
                    response.status_code = 200
                    return _serialize_capture(db, duplicate)
                logger.exception("Could not save uploaded capture metadata", extra={"capture_id": capture_id})
                raise HTTPException(status_code=500, detail="Could not save uploaded capture metadata") from error
            except Exception as error:
                db.rollback()
                logger.exception("Could not save uploaded capture metadata", extra={"capture_id": capture_id})
                raise HTTPException(status_code=500, detail="Could not save uploaded capture metadata") from error
        evidence_persisted = True
        if (
            previous_evidence_path
            and previous_evidence_path != evidence_path.resolve()
            and previous_evidence_path.parent == settings.evidence_dir.resolve()
        ):
            _remove_previous_evidence(previous_evidence_path, capture_id)

        async with _processing_lease_heartbeat(capture_id, processing_token) as lease:
            try:
                analysis = await run_in_threadpool(analyze_capture, evidence_path, lease.lost.is_set)
            except CaptureAnalysisCancelled as error:
                raise HTTPException(
                    status_code=409,
                    detail="Capture processing ownership expired; retry the upload",
                ) from error
            except CaptureAnalysisError as error:
                if not lease.mark_failed(db, capture_id, processing_token, str(error)):
                    raise HTTPException(
                        status_code=409,
                        detail="Capture processing ownership expired; retry the upload",
                    ) from error
                raise HTTPException(
                    status_code=422,
                    detail={"capture_id": capture_id, "message": str(error)[:2000]},
                ) from error
            except Exception as error:
                if not lease.mark_failed(
                    db, capture_id, processing_token, f"Unable to analyze capture: {error}"
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Capture processing ownership expired; retry the upload",
                    ) from error
                logger.exception("Unexpected capture analyzer error", extra={"capture_id": capture_id})
                raise HTTPException(
                    status_code=500,
                    detail={"capture_id": capture_id, "message": "Capture analysis failed"},
                ) from error

            try:
                lease.persist(db, capture, analysis, processing_token)
            except CaptureLeaseLost as error:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Capture processing ownership expired; retry the upload",
                ) from error
            except Exception as error:
                db.rollback()
                if not lease.mark_failed(
                    db,
                    capture_id,
                    processing_token,
                    f"Analysis results could not be saved: {error}",
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Capture processing ownership expired; retry the upload",
                    ) from error
                logger.exception("Could not persist capture analysis", extra={"capture_id": capture_id})
                raise HTTPException(
                    status_code=500,
                    detail="Capture was stored but analysis results could not be saved",
                ) from error

            capture = db.get(Capture, capture_id)
            if capture is None:
                raise HTTPException(status_code=404, detail="Capture not found after analysis")
            return _serialize_capture(db, capture)
    except HTTPException:
        if evidence_path and not evidence_persisted:
            _remove_unpersisted_evidence(evidence_path, capture_id)
        raise
    except OSError as error:
        if evidence_path and not evidence_persisted:
            _remove_unpersisted_evidence(evidence_path, capture_id)
        raise HTTPException(status_code=500, detail="Could not safely store uploaded capture") from error
    except Exception as error:
        if evidence_path and not evidence_persisted:
            _remove_unpersisted_evidence(evidence_path, capture_id)
        logger.exception("Unexpected capture upload error", extra={"capture_id": capture_id})
        raise HTTPException(status_code=500, detail="Could not process uploaded capture") from error
    finally:
        await file.close()


def _begin_upload_claim(db: Session) -> None:
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def _mark_capture_failed(db: Session, capture_id: str, processing_token: str, message: str) -> bool:
    try:
        result = db.execute(
            update(Capture)
            .where(
                Capture.id == capture_id,
                Capture.status == CaptureStatus.PROCESSING,
                Capture.processing_token == processing_token,
                Capture.processing_lease_expires_at > datetime.now(timezone.utc),
            )
            .values(
                status=CaptureStatus.FAILED,
                error_message=message[:2000],
                processing_token=None,
                processing_lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            db.rollback()
            return False
        db.commit()
        return True
    except Exception:
        db.rollback()
        logger.exception("Could not persist failed capture status", extra={"capture_id": capture_id})
        raise


def _renew_processing_lease(capture_id: str, processing_token: str) -> bool:
    lease_db = get_session_factory()()
    now = datetime.now(timezone.utc)
    try:
        result = lease_db.execute(
            update(Capture)
            .where(
                Capture.id == capture_id,
                Capture.status == CaptureStatus.PROCESSING,
                Capture.processing_token == processing_token,
                Capture.processing_lease_expires_at > now,
            )
            .values(
                processing_lease_expires_at=now + timedelta(seconds=PROCESSING_LEASE_SECONDS)
            )
            .execution_options(synchronize_session=False)
        )
        lease_db.commit()
        return result.rowcount == 1
    except Exception:
        lease_db.rollback()
        logger.exception("Could not renew capture processing lease", extra={"capture_id": capture_id})
        return False
    finally:
        lease_db.close()


@asynccontextmanager
async def _processing_lease_heartbeat(capture_id: str, processing_token: str):
    lease = ProcessingLease()

    async def renew_until_cancelled() -> None:
        while True:
            await asyncio.sleep(PROCESSING_HEARTBEAT_SECONDS)
            if not await run_in_threadpool(lease.renew, capture_id, processing_token):
                logger.warning("Capture processing lease is no longer owned", extra={"capture_id": capture_id})
                return

    heartbeat = asyncio.create_task(renew_until_cancelled())
    try:
        yield lease
    finally:
        heartbeat.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat


def _remove_unpersisted_evidence(evidence_path: Path, capture_id: str) -> None:
    try:
        evidence_path.unlink(missing_ok=True)
    except OSError:
        logger.exception("Could not remove unpersisted evidence file", extra={"capture_id": capture_id})


def _remove_previous_evidence(evidence_path: Path, capture_id: str) -> None:
    try:
        evidence_path.unlink(missing_ok=True)
    except OSError:
        logger.exception("Could not remove replaced evidence file", extra={"capture_id": capture_id})


@router.get("/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return _serialize_capture(db, capture)


@router.delete("/{capture_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    stored_path = Path(capture.file_path).resolve()
    evidence_dir = get_settings().evidence_dir.resolve()
    db.delete(capture)
    db.commit()
    if stored_path.parent == evidence_dir:
        stored_path.unlink(missing_ok=True)


@router.get("/{capture_id}/network", response_model=NetworkMapOut)
def get_network_map(capture_id: str, db: Session = Depends(get_db)):
    """Returns a holistic representation of the network discovered in this capture."""
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    hosts = db.scalars(select(Host).where(Host.capture_id == capture_id)).all()
    flows = db.scalars(
        select(Flow)
        .options(joinedload(Flow.src_host), joinedload(Flow.dst_host), joinedload(Flow.capture))
        .where(Flow.capture_id == capture_id)
    ).all()

    # Protocols distribution
    proto_counts: dict[str, int] = {}
    app_counts: dict[str, int] = {}
    for f in flows:
        proto_counts[f.protocol] = proto_counts.get(f.protocol, 0) + 1
        app_name = f.application or "Unknown"
        app_counts[app_name] = app_counts.get(app_name, 0) + 1

    # Top domains from DNS
    dns_records = db.scalars(select(DnsRecord.query_name).where(DnsRecord.capture_id == capture_id).distinct()).all()

    flow_outs = [FlowOut.model_validate(f) for f in flows]

    return NetworkMapOut(
        capture_id=capture_id,
        total_hosts=len(hosts),
        total_flows=len(flows),
        protocols=proto_counts,
        applications=app_counts,
        hosts=[HostOut.model_validate(h) for h in hosts],
        flows=flow_outs,
        top_domains=list(dns_records)[:20],
    )


def _safe_filename(filename: str | None) -> str:
    name = Path((filename or "capture.pcap").replace("\\", "/")).name
    name = "".join(character for character in name if character.isprintable() and character not in "\r\n\0")
    return (name or "capture.pcap")[:255]


def _serialize_capture(db: Session, capture: Capture) -> dict:
    flow_count = db.scalar(select(func.count()).select_from(Flow).where(Flow.capture_id == capture.id)) or 0
    duration = 0.0
    if capture.first_packet_at and capture.last_packet_at:
        duration = max(0.0, (capture.last_packet_at - capture.first_packet_at).total_seconds())
    fmt_val = capture.file_format.value if hasattr(capture.file_format, "value") else str(capture.file_format)
    status_map = {
        CaptureStatus.IMPORTED: "registered",
        CaptureStatus.PROCESSING: "processing",
        CaptureStatus.COMPLETED: "analyzed",
        CaptureStatus.FAILED: "failed",
    }
    status_str = status_map.get(capture.status, str(capture.status.value if hasattr(capture.status, "value") else capture.status))
    return {
        "id": capture.id,
        "original_filename": capture.original_filename,
        "filename": capture.original_filename,
        "file_size_bytes": capture.file_size_bytes,
        "sha256": capture.sha256,
        "file_format": fmt_val,
        "file_type": fmt_val,
        "status": status_str,
        "packet_count": capture.packet_count or 0,
        "first_packet_at": capture.first_packet_at,
        "last_packet_at": capture.last_packet_at,
        "flow_count": flow_count,
        "duration_seconds": duration,
        "notes": capture.error_message,
        "tshark_processed": 0,
        "created_at": capture.created_at,
        "updated_at": capture.updated_at,
    }
