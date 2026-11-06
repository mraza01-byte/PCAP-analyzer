"""Structured logging.

"json" format prints one JSON object per line (easy for tools to read).
"console" format prints a readable line (easy for humans to read).
Extra fields passed with  logger.info("msg", extra={"key": "value"})  are included.
"""
import json
import logging
import sys
from datetime import datetime, timezone

# Attributes every LogRecord has; anything else was added through "extra".
_STANDARD_ATTRS = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "color_message"}


def _extra_fields(record: logging.LogRecord) -> dict:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **_extra_fields(record),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        time = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        line = f"{time} {record.levelname:<8} {record.name}: {record.getMessage()}"
        extras = _extra_fields(record)
        if extras:
            line += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(level: str = "INFO", log_format: str = "console") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if log_format == "json" else ConsoleFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Let uvicorn's own loggers use our handler so all logs look the same.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
    # We log every request ourselves (with timing + request id), so silence uvicorn's copy.
    logging.getLogger("uvicorn.access").disabled = True
