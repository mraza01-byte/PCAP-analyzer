import os
import platform
from pathlib import Path

from fastapi import APIRouter
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.schemas.settings import PlatformSettings

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=PlatformSettings)
def get_platform_settings() -> PlatformSettings:
    """Real diagnostics about this running backend."""
    settings = get_settings()
    db_file = make_url(settings.resolved_database_url).database or ""
    size = Path(db_file).stat().st_size if db_file and Path(db_file).is_file() else 0
    return PlatformSettings(
        app_name=settings.app_name,
        app_version=settings.app_version,
        environment=settings.environment,
        host=settings.host,
        port=settings.port,
        database_path=db_file,
        database_size_bytes=size,
        python_version=platform.python_version(),
        os_platform=platform.platform(),
        cpu_count=os.cpu_count() or 1,
        tshark_detected=False,
        tshark_binary_path="",
        evidence_directory=str(settings.evidence_dir),
    )
