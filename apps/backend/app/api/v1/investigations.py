from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture, Investigation, InvestigationStatus

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
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }
