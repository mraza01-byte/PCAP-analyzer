# PCAP-MAN Backend

FastAPI service for PCAP-MAN. It runs on its own, separate from the desktop app.

## Setup (once)

From the repository root, run:

```
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# Mac / Linux:         source .venv/bin/activate
python apps/backend/install.py
```

The installer resolves the backend and engine paths itself, so it can also be run
from another working directory. To install manually, change to `apps/backend`
before running `pip install -r requirements-dev.txt`.

## Run

Starting the backend also creates/updates the SQLite database automatically (no separate Alembic step needed).

```
cd apps/backend
python -m app --reload
```

The server reads `PCAPMAN_HOST` and `PCAPMAN_PORT` from the environment or `.env`.
Then open http://127.0.0.1:8000/health  (API docs: http://127.0.0.1:8000/docs)

Expected reply: `{"status":"healthy","application":"PCAP-MAN"}`

The desktop app (`apps/desktop`) talks to this service at `http://localhost:8000`. Start the backend first, then `npm run tauri dev` (or `npm run dev`) in `apps/desktop`. See `docs/API.md` for every endpoint.

## Database

Create or update the database structure (see `docs/DATABASE.md`):

```
alembic upgrade head
```

## Test

```
python -m pytest
```

## Settings

All optional. Copy `.env.example` to `.env` to change them. See `app/core/config.py`.

## Folder map

| Folder | Purpose |
|---|---|
| `app/api` | URL endpoints |
| `app/core` | settings, logging, error handling |
| `app/database` | database connection |
| `app/models` | database tables (SQLAlchemy) |
| `app/schemas` | request/reply shapes (Pydantic) |
| `app/services` | business logic (later) |
| `alembic` | database migrations |
| `docs` | database design/ERD (`DATABASE.md`) and API reference (`API.md`) |
