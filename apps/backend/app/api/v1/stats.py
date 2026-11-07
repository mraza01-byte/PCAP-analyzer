from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Capture, Flow, Host, Investigation
from app.schemas.stats import StatsResponse

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    """Real row counts straight from the database."""
    def count(model) -> int:
        return db.scalar(select(func.count()).select_from(model)) or 0

    return StatsResponse(
        captures=count(Capture), hosts=count(Host), flows=count(Flow), investigations=count(Investigation)
    )
