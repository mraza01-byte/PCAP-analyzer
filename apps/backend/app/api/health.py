from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Tells the desktop app that the backend is alive."""
    return HealthResponse(status="healthy", application=get_settings().app_name)
