# PCAP-MAN Backend

FastAPI service for PCAP-MAN. It runs on its own, separate from the desktop app.

## Setup (once)

From this folder (`apps/backend`):

```
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# Mac / Linux:         source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Run

```
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000/health  (API docs: http://127.0.0.1:8000/docs)

Expected reply: `{"status":"healthy","application":"PCAP-MAN"}`

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
| `docs` | database design and ERD |
