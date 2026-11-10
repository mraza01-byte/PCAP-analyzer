from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture, CaptureStatus, Flow, Host, Investigation

router = APIRouter(prefix="/briefings", tags=["briefings"])


@router.get("/generate")
def generate_briefing(case_id: str | None = None, db: Session = Depends(get_db)):
    case = db.get(Investigation, case_id) if case_id else None
    if case_id and not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    captures = case.captures if case else db.scalars(
        select(Capture).where(Capture.status == CaptureStatus.COMPLETED).order_by(Capture.created_at.desc())
    ).all()
    capture_ids = [capture.id for capture in captures]
    flows = db.scalars(select(Flow).where(Flow.capture_id.in_(capture_ids)).order_by(Flow.start_time)).all() if capture_ids else []
    hosts = db.scalars(select(Host).where(Host.capture_id.in_(capture_ids)).order_by(Host.ip_address)).all() if capture_ids else []
    endpoints = sorted({host.ip_address for host in hosts})
    packet_count = sum(capture.packet_count or 0 for capture in captures)
    case_title = case.title if case else "Capture analysis summary"
    findings = case.findings if case and case.findings else (
        f"Analysis covers {len(captures)} completed capture(s), {packet_count} packet(s), "
        f"{len(hosts)} observed host record(s), and {len(flows)} flow(s)."
    )
    iocs = [{"type": "Observed IP address", "value": address, "attribution": "Not assessed", "reputation": "Not assessed"}
            for address in endpoints]
    evidence = [{
        "filename": capture.original_filename,
        "sha256": capture.sha256,
        "packet_count": capture.packet_count or 0,
        "size_kb": round(capture.file_size_bytes / 1024, 2),
    } for capture in captures]
    return {
        "report_id": f"IR-{uuid4().hex[:12].upper()}",
        "classification": "PCAP-MAN Analysis Report",
        "generated_at": datetime.now(timezone.utc),
        "case_number": f"CASE-{case.id[:8].upper()}" if case else "UNASSIGNED",
        "case_title": case_title,
        "lead_analyst": case.lead_analyst if case and case.lead_analyst else "Unassigned",
        "organization": "Unspecified",
        "executive_summary": f"Processed evidence contains {packet_count} packets across {len(captures)} completed capture(s) and {len(flows)} observed network flow(s).",
        "case_findings": findings,
        "kill_chain": [],
        "iocs": iocs,
        "evidence_records": evidence,
        "recommendations": [],
    }