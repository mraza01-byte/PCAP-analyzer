from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture
from app.schemas.entities import CaptureOut

router = APIRouter(prefix="/captures", tags=["captures"])


@router.get("", response_model=list[CaptureOut])
def list_captures(db: Session = Depends(get_db)):
    return db.scalars(select(Capture).order_by(Capture.created_at.desc())).all()
