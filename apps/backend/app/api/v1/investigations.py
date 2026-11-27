from datetime import datetime, timezone

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture, Flow, Investigation, InvestigationStatus, TimelineEvent
from app.schemas.entities import CaptureOut, FlowOut, TimelineEventOut, TimelineList

router = APIRouter(prefix="/investigations", tags=["investigations"])


class InvestigationCreate(BaseModel):
    title: str
    severity: str = "medium"
    lead_analyst: str = ""
    description: str | None = None
    findings: str | None = None
    ioc_list: str | None = None
    linked_capture_ids: list[str] = []


class InvestigationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = None
    severity: str | None = None
    lead_analyst: str | None = None
    description: str | None = None
    findings: str | None = None
    ioc_list: str | None = None
    status: str | None = None


@router.get("")
def list_investigations(db: Session = Depends(get_db)):
    rows = db.scalars(select(Investigation).order_by(Investigation.created_at.desc())).all()
    return [_serialize_investigation(case) for case in rows]


@router.post("", status_code=201)
def create_investigation(body: InvestigationCreate, db: Session = Depends(get_db)):
    captures = []
    if body.linked_capture_ids:
        captures = db.scalars(select(Capture).where(Capture.id.in_(body.linked_capture_ids))).all()
        if len(captures) != len(set(body.linked_capture_ids)):
            raise HTTPException(status_code=404, detail="One or more linked captures were not found")
    case = Investigation(
        title=body.title,
        description=body.description,
        severity=_validate_severity(body.severity),
        lead_analyst=body.lead_analyst,
        findings=body.findings,
        ioc_list=body.ioc_list,
        captures=captures,
    )
    db.add(case)
    db.commit()
    return _serialize_investigation(case)


@router.patch("/{case_id}")
def update_investigation(case_id: str, body: InvestigationPatch, db: Session = Depends(get_db)):
    case = db.get(Investigation, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    values = body.model_dump(exclude_unset=True)
    if "severity" in values:
        values["severity"] = _validate_severity(values["severity"])
    if "status" in values:
        values["status"] = _status_to_model(values.pop("status"))
        case.closed_at = datetime.now(timezone.utc) if values["status"] == InvestigationStatus.CLOSED else None
    for key, value in values.items():
        setattr(case, key, value)
    db.commit()
    return _serialize_investigation(case)


@router.delete("/{case_id}", status_code=204)
def delete_investigation(case_id: str, db: Session = Depends(get_db)):
    case = db.get(Investigation, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    db.delete(case)
    db.commit()


class EvidenceLink(BaseModel):
    capture_ids: list[str] = []
    flow_ids: list[str] = []
    event_ids: list[str] = []


class InvestigationEvidence(BaseModel):
    captures: list[CaptureOut]
    flows: list[FlowOut]
    events: list[TimelineEventOut]


def _get_case(db: Session, case_id: str) -> Investigation:
    case = db.get(Investigation, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return case


def _require_open(case: Investigation) -> None:
    if case.status == InvestigationStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Investigation is closed; reopen it before changing evidence")


def _load_all(db: Session, model, ids: list[str], label: str) -> list:
    wanted = set(ids)
    rows = db.scalars(select(model).where(model.id.in_(wanted))).all() if wanted else []
    if len(rows) != len(wanted):
        raise HTTPException(status_code=404, detail=f"One or more {label} were not found")
    return rows


@router.get("/{case_id}")
def get_investigation(case_id: str, db: Session = Depends(get_db)):
    return _serialize_investigation(_get_case(db, case_id))


@router.get("/{case_id}/evidence", response_model=InvestigationEvidence)
def get_evidence(case_id: str, db: Session = Depends(get_db)):
    """Everything linked to this case: captures, flows and individually linked timeline events."""
    case = _get_case(db, case_id)
    return InvestigationEvidence(captures=case.captures, flows=case.flows, events=case.timeline_events)


@router.post("/{case_id}/evidence")
def link_evidence(case_id: str, body: EvidenceLink, db: Session = Depends(get_db)):
    """Attach captures, flows and timeline events to the case. Safe to repeat."""
    case = _get_case(db, case_id)
    _require_open(case)
    captures = _load_all(db, Capture, body.capture_ids, "captures")
    flows = _load_all(db, Flow, body.flow_ids, "flows")
    events = _load_all(db, TimelineEvent, body.event_ids, "timeline events")
    for event in events:
        if event.investigation_id not in (None, case.id):
            raise HTTPException(status_code=409, detail="A timeline event is already linked to another investigation")
    for capture in captures:
        if capture not in case.captures:
            case.captures.append(capture)
    for flow in flows:
        if flow not in case.flows:
            case.flows.append(flow)
    for event in events:
        event.investigation_id = case.id
    db.commit()
    return _serialize_investigation(case)


@router.delete("/{case_id}/evidence/captures/{capture_id}", status_code=204)
def unlink_capture(case_id: str, capture_id: str, db: Session = Depends(get_db)):
    case = _get_case(db, case_id)
    _require_open(case)
    capture = next((c for c in case.captures if c.id == capture_id), None)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture is not linked to this investigation")
    case.captures.remove(capture)
    db.commit()


@router.delete("/{case_id}/evidence/flows/{flow_id}", status_code=204)
def unlink_flow(case_id: str, flow_id: str, db: Session = Depends(get_db)):
    case = _get_case(db, case_id)
    _require_open(case)
    flow = next((f for f in case.flows if f.id == flow_id), None)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow is not linked to this investigation")
    case.flows.remove(flow)
    db.commit()


@router.delete("/{case_id}/evidence/events/{event_id}", status_code=204)
def unlink_event(case_id: str, event_id: str, db: Session = Depends(get_db)):
    case = _get_case(db, case_id)
    _require_open(case)
    event = db.get(TimelineEvent, event_id)
    if not event or event.investigation_id != case.id:
        raise HTTPException(status_code=404, detail="Timeline event is not linked to this investigation")
    event.investigation_id = None
    db.commit()


@router.get("/{case_id}/timeline", response_model=TimelineList)
def case_timeline(case_id: str, include_captures: bool = False,
                  limit: int = Query(1000, ge=1, le=5000), db: Session = Depends(get_db)):
    """The case's own timeline: events linked directly, plus events of linked flows.

    Add include_captures=true to also include every event of the linked captures.
    """
    case = _get_case(db, case_id)
    conditions = [TimelineEvent.investigation_id == case.id]
    flow_ids = [flow.id for flow in case.flows]
    if flow_ids:
        conditions.append(TimelineEvent.flow_id.in_(flow_ids))
    if include_captures and case.captures:
        conditions.append(TimelineEvent.capture_id.in_([capture.id for capture in case.captures]))
    query = select(TimelineEvent).where(or_(*conditions))
    events = db.scalars(query.order_by(TimelineEvent.event_time).limit(limit)).all()
    total = len(db.scalars(select(TimelineEvent.id).where(or_(*conditions))).all())
    return TimelineList(total=total, events=events)


def _validate_severity(value: str) -> str:
    if value not in {"critical", "high", "medium", "low"}:
        raise HTTPException(status_code=422, detail="Severity must be critical, high, medium, or low")
    return value


def _status_to_model(value: str) -> InvestigationStatus:
    values = {"active": InvestigationStatus.OPEN, "open": InvestigationStatus.OPEN,
              "under_review": InvestigationStatus.IN_PROGRESS, "escalated": InvestigationStatus.ESCALATED,
              "in_progress": InvestigationStatus.IN_PROGRESS, "closed": InvestigationStatus.CLOSED}
    if value not in values:
        raise HTTPException(status_code=422, detail="Unsupported investigation status")
    return values[value]


def _serialize_investigation(case: Investigation) -> dict:
    status = {InvestigationStatus.OPEN: "active", InvestigationStatus.IN_PROGRESS: "under_review",
              InvestigationStatus.ESCALATED: "escalated",
              InvestigationStatus.CLOSED: "closed"}[case.status]
    return {
        "id": case.id,
        "title": case.title,
        "case_number": f"CASE-{case.id[:8].upper()}",
        "severity": case.severity,
        "status": status,
        "lead_analyst": case.lead_analyst,
        "description": case.description,
        "findings": case.findings,
        "ioc_list": case.ioc_list,
        "linked_capture_ids": ",".join(capture.id for capture in case.captures),
        "capture_count": len(case.captures),
        "flow_count": len(case.flows),
        "event_count": len(case.timeline_events),
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }
