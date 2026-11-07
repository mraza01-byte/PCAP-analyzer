import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ServiceUnavailableError
from app.database.session import get_db
from app.schemas.health import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    """Tells the desktop app the backend is alive AND can reach its database."""
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.error("Health check failed: database unreachable", exc_info=True)
        raise ServiceUnavailableError("Database is not reachable.")
    return HealthResponse(status="healthy", application=get_settings().app_name)
