# PCAP-MAN Backend API (Phase 1)

Base address: `http://localhost:8000` (the backend listens only on this computer).
Interactive docs while the backend runs: `http://localhost:8000/docs`.

## Startup behaviour

When the backend starts it creates or updates the SQLite database to the latest structure
(Alembic migrations run automatically). Nobody needs to run `alembic upgrade head` by hand.
Set `PCAPMAN_AUTO_MIGRATE=false` to turn this off.

## Endpoints

All Phase 1 endpoints are **read-only** and return **real database content**. A fresh install
returns zeros and empty lists, never sample data.

| Method and path | Reply |
|---|---|
| `GET /health` | `{"status":"healthy","application":"PCAP-MAN"}`. Returns **503** if the database cannot be reached. |
| `GET /api/v1/stats` | `{"captures":n,"hosts":n,"flows":n,"investigations":n}` (real row counts) |
| `GET /api/v1/captures` | `[CaptureOut, ...]` |
| `GET /api/v1/hosts?search=&limit=` | `{"total":n,"hosts":[HostOut, ...]}` |
| `GET /api/v1/flows?protocol=&limit=` | `{"total":n,"flows":[FlowOut, ...]}` |
| `GET /api/v1/timeline?search=&limit=` | `{"total":n,"events":[TimelineEventOut, ...]}` |
| `GET /api/v1/investigations` | `[InvestigationOut, ...]` |
| `GET /api/v1/settings` | Real diagnostics: version, port, database path/size, Python, OS, CPU count. `tshark_detected` is `false` and the TShark and evidence paths are empty because Phase 1 has neither. |

Field names of each `*Out` object follow the database models (see `DATABASE.md`).

## Errors

Every error has the same shape: `{"error":{"code":"...","message":"...","request_id":"..."}}`.
Unknown routes return 404 in this format.

## Not implemented yet (later phases)

PCAP upload, deleting captures, creating/updating/deleting investigations, flow detail,
briefing generation, saving settings. These URLs return 404/405 on purpose. The backend never
pretends they work.

## CORS

Allowed origins: `http://localhost:1420` and `http://127.0.0.1:1420` (Vite dev server),
`tauri://localhost` and `http://tauri.localhost` (the packaged Tauri app). Any other website is refused.

## Frontend contract notes (to agree with the frontend owners)

The database uses **UUID string ids** and the field names in `DATABASE.md`. The frontend types in
`apps/desktop/src/services/api.ts` currently describe different shapes (numeric `id`, `filename`,
`file_type`, `flow_key`, `src_ip`, ...). Lists are empty today so nothing breaks, but the moment real
rows exist the two sides must match. Either the frontend types follow the backend, or the backend
schemas in `app/schemas/entities.py` are changed. Decide once, then both sides use it.
