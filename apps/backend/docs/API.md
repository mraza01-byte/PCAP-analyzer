# PCAP-MAN Backend API

Base address: `http://localhost:8000` (the backend listens only on this computer).
Interactive docs while the backend runs: `http://localhost:8000/docs`.

## Startup behaviour

When the backend starts it creates or updates the SQLite database to the latest structure
(Alembic migrations run automatically). Nobody needs to run `alembic upgrade head` by hand.
Set `PCAPMAN_AUTO_MIGRATE=false` to turn this off.

## Endpoints

Endpoints return persisted data from the local SQLite database. Capture uploads are analyzed by
the existing Scapy-based engine; the API does not provide synthetic analysis results.

| Method and path | Reply |
| --- | --- |
| `GET /health` | `{"status":"healthy","application":"PCAP-MAN"}`. Returns **503** if the database cannot be reached. |
| `GET /api/v1/stats` | `{"captures":n,"hosts":n,"flows":n,"investigations":n}` (real row counts) |
| `GET /api/v1/captures` | `[CaptureRecord, ...]` |
| `POST /api/v1/captures/upload` | Multipart field `file`; streams and validates PCAP/PCAPNG, stores evidence, analyzes it, and returns metadata and analysis status |
| `GET /api/v1/captures/{id}` | Capture metadata and current status |
| `DELETE /api/v1/captures/{id}` | Deletes a capture, its derived rows, and its stored evidence |
| `GET /api/v1/hosts?search=&limit=` | `{"total":n,"hosts":[HostOut, ...]}` |
| `GET /api/v1/flows?protocol=&search=&limit=` | `{"total":n,"flows":[FlowOut, ...]}` |
| `GET /api/v1/flows/{id}` | One persisted flow with endpoint and byte-count details |
| `GET /api/v1/timeline?search=&severity=&category=&limit=` | `{"total":n,"events":[TimelineEventOut, ...]}` |
| `GET /api/v1/investigations` | `[InvestigationOut, ...]` |
| `POST /api/v1/investigations` | Create a case and optionally link capture UUIDs |
| `PATCH /api/v1/investigations/{id}` | Update case metadata, notes, or status |
| `DELETE /api/v1/investigations/{id}` | Delete a case |
| `GET /api/v1/briefings/generate?case_id=` | Build a report from a case's linked captures, or all completed captures when omitted |
| `GET /api/v1/settings` | Real diagnostics: version, port, database/evidence paths, Python, OS, and CPU count |

Capture, host, flow, timeline, and investigation response shapes match the desktop service types.
Database storage names and relationships are documented in `DATABASE.md`.

## Upload behaviour

Uploads are limited to 1 GiB by default (`PCAPMAN_MAX_UPLOAD_SIZE_BYTES`), written in chunks under
`apps/backend/data/evidence/` with generated UUID filenames and owner-only permissions. The
original basename is metadata only. Content is checked by capture magic bytes, not browser MIME
type or filename. Duplicate SHA-256 evidence reuses the existing record. A malformed capture that
passes the header check is retained with `failed` status and an error note; unsupported file types
are rejected without a database record.

The engine streams packets and currently extracts IP/IPv6 endpoints, Ethernet MAC addresses,
TCP/UDP and common IP protocols, ports, packet/byte counts, TCP flags, capture bounds, and
flow-start/last-seen timeline events. It does not currently decode DNS names, TLS SNI, HTTP
payloads, reputation, or threat severity; reports do not claim those findings.

## Errors

Every error has the same shape: `{"error":{"code":"...","message":"...","request_id":"..."}}`.
Unknown routes return 404 in this format.

## CORS

Allowed origins: `http://localhost:1420` and `http://127.0.0.1:1420` (Vite dev server),
`tauri://localhost` and `http://tauri.localhost` (the packaged Tauri app). Any other website is refused.

All entity IDs are UUID strings. Upload errors use the backend error envelope; parser failures
include the persisted capture UUID and parser message so the client can refresh the evidence list.
