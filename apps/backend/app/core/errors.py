"""One consistent error format for the whole API.

Every error reply looks like:
  {"error": {"code": "...", "message": "...", "request_id": "..."}}
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base class for errors we raise on purpose. Subclass it for specific cases."""

    status_code = 400
    code = "app_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


def _error_response(request: Request, status_code: int, code: str, message: str, details=None):
    body = {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", None),
        }
    }
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError):
        return _error_response(request, exc.status_code, exc.code, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException):
        return _error_response(request, exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError):
        details = [
            {"field": ".".join(str(p) for p in e["loc"]), "problem": e["msg"]}
            for e in exc.errors()
        ]
        return _error_response(request, 422, "validation_error", "Invalid request data.", details)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception):
        # Full details go to the log; the caller only gets a safe, generic message.
        logger.error(
            "Unhandled error",
            exc_info=exc,
            extra={"request_id": getattr(request.state, "request_id", None), "path": request.url.path},
        )
        return _error_response(request, 500, "internal_error", "Something went wrong on our side.")
