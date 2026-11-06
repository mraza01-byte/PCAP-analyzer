import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import health
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import setup_logging

settings = get_settings()
setup_logging(settings.log_level, settings.log_format)
logger = logging.getLogger("pcapman")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info(
        "Backend starting",
        extra={"version": settings.app_version, "environment": settings.environment},
    )
    yield
    logger.info("Backend stopped")


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Give every request an ID and log how it went."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = request_id
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # The error handler turns this into a 500 reply; log timing here and pass it on.
        logger.info(
            "request failed",
            extra={"request_id": request_id, "method": request.method, "path": request.url.path,
                   "duration_ms": round((time.perf_counter() - start) * 1000, 2)},
        )
        raise
    response.headers["x-request-id"] = request_id
    logger.info(
        "request",
        extra={"request_id": request_id, "method": request.method, "path": request.url.path,
               "status": response.status_code,
               "duration_ms": round((time.perf_counter() - start) * 1000, 2)},
    )
    return response


register_error_handlers(app)
app.include_router(health.router)
