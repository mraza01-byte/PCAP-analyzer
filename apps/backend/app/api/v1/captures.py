import hashlib
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from engine.services.analyzer import CaptureAnalysisError, analyze_capture, detect_capture_format
from app.core.config import get_settings
from app.database.session import get_db
from app.models import Capture, CaptureFormat, CaptureStatus, Flow
from app.schemas.entities import CaptureOut
from app.services.capture_processing import persist_analysis

router = APIRouter(prefix="/captures", tags=["captures"])


@router.get("", response_model=list[CaptureOut])
def list_captures(db: Session = Depends(get_db)):
    captures = db.scalars(select(Capture).order_by(Capture.created_at.desc())).all()
    return [_serialize_capture(db, capture) for capture in captures]


@router.post("/upload", response_model=CaptureOut, status_code=201)
async def upload_capture(file: UploadFile = File(...), db: Session = Depends(get_db)):
    settings = get_settings()
    capture_id = str(uuid.uuid4())
    evidence_path: Path | None = None
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
        existing = db.scalar(select(Capture).where(Capture.sha256 == sha256))
        if existing:
            evidence_path.unlink(missing_ok=True)
            return _serialize_capture(db, existing)

        filename = _safe_filename(file.filename)
        capture = Capture(
            id=capture_id,
            original_filename=filename,
            file_path=str(evidence_path.resolve()),
            file_size_bytes=size,
            sha256=sha256,
            file_format=CaptureFormat(file_format),
            status=CaptureStatus.PROCESSING,
        )
        db.add(capture)
        db.commit()

        try:
            analysis = await run_in_threadpool(analyze_capture, evidence_path)
        except CaptureAnalysisError as error:
            capture.status = CaptureStatus.FAILED
            capture.error_message = str(error)[:2000]
            db.commit()
            raise HTTPException(status_code=422, detail={"capture_id": capture.id, "message": capture.error_message}) from error

        try:
            persist_analysis(db, capture, analysis)
        except Exception as error:
            db.rollback()
            capture = db.get(Capture, capture_id)
            if capture:
                capture.status = CaptureStatus.FAILED
                capture.error_message = f"Analysis results could not be saved: {error}"[:2000]
                db.commit()
            raise HTTPException(status_code=500, detail="Capture was stored but analysis results could not be saved") from error

        return _serialize_capture(db, capture)
    except HTTPException:
        if evidence_path and db.get(Capture, capture_id) is None:
            evidence_path.unlink(missing_ok=True)
        raise
    except OSError as error:
        if evidence_path:
            evidence_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Could not safely store uploaded capture") from error
    finally:
        await file.close()


@router.get("/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return _serialize_capture(db, capture)


@router.delete("/{capture_id}", status_code=204)
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


def _safe_filename(filename: str | None) -> str:
    name = Path((filename or "capture.pcap").replace("\\", "/")).name
    name = "".join(character for character in name if character.isprintable() and character not in "\r\n\0")
    return (name or "capture.pcap")[:255]


def _serialize_capture(db: Session, capture: Capture) -> dict:
    flow_count = db.scalar(select(func.count()).select_from(Flow).where(Flow.capture_id == capture.id)) or 0
    duration = 0.0
    if capture.first_packet_at and capture.last_packet_at:
        duration = max(0.0, (capture.last_packet_at - capture.first_packet_at).total_seconds())
    return {
        "id": capture.id,
        "filename": capture.original_filename,
        "file_size_bytes": capture.file_size_bytes,
        "sha256": capture.sha256,
        "file_type": capture.file_format.value,
        "status": {CaptureStatus.IMPORTED: "registered", CaptureStatus.PROCESSING: "processing",
                   CaptureStatus.COMPLETED: "analyzed", CaptureStatus.FAILED: "failed"}[capture.status],
        "packet_count": capture.packet_count or 0,
        "first_packet_at": capture.first_packet_at,
        "last_packet_at": capture.last_packet_at,
        "flow_count": flow_count,
        "duration_seconds": duration,
        "notes": capture.error_message,
        "created_at": capture.created_at,
        "updated_at": capture.updated_at,
    }
