from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Optional


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


@dataclass
class HttpParsed:
    is_request: bool
    method: Optional[str] = None
    url: str = ""
    path: Optional[str] = None
    host: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    response_phrase: Optional[str] = None
    content_type: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)


def parse_http_payload(payload: bytes) -> Optional[HttpParsed]:
    """Detects and parses an HTTP request or response header block."""
    if not payload or len(payload) < 8:
        return None

    # Check for HTTP text
    try:
        # Only inspect the header portion (up to \r\n\r\n or \n\n)
        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = payload.find(b"\n\n")
            if header_end == -1:
                # May be a partial or small HTTP header
                header_end = min(len(payload), 4096)
        
        raw_header = payload[:header_end].decode("iso-8859-1")
    except Exception:
        return None

    lines = [line.strip("\r") for line in raw_header.split("\n") if line.strip("\r")]
    if not lines:
        return None

    first_line = lines[0].strip()
    tokens = first_line.split(" ")

    # Check for HTTP Request: METHOD URI HTTP/X.X
    if len(tokens) >= 3 and tokens[0] in HTTP_METHODS and "HTTP/" in tokens[2]:
        method = tokens[0]
        uri = tokens[1]
        headers: dict[str, str] = {}

        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        host = headers.get("host")
        user_agent = headers.get("user-agent")
        content_type = headers.get("content-type")

        # Normalize URL
        if uri.startswith("http://") or uri.startswith("https://"):
            full_url = uri
        elif host:
            full_url = f"http://{host}{uri}"
        else:
            full_url = uri

        return HttpParsed(
            is_request=True,
            method=method,
            url=full_url,
            path=uri,
            host=host,
            user_agent=user_agent,
            content_type=content_type,
            headers=headers,
        )

    # Check for HTTP Response: HTTP/X.X STATUS_CODE PHRASE
    if len(tokens) >= 2 and tokens[0].startswith("HTTP/"):
        try:
            status_code = int(tokens[1])
        except ValueError:
            return None

        phrase = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        content_type = headers.get("content-type")

        return HttpParsed(
            is_request=False,
            status_code=status_code,
            response_phrase=phrase,
            content_type=content_type,
            headers=headers,
        )

    return None

