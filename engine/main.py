import hashlib
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from database import conn
from services.analyzer import CaptureAnalysisError, detect_capture_format
from services.host_discovery import discover_hosts

app = FastAPI(title="PCAP-MAN Engine")

BASE_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = BASE_DIR / "data" / "evidence"
MAX_UPLOAD_SIZE_BYTES = 1_073_741_824
CHUNK_SIZE_BYTES = 1024 * 1024
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _safe_filename(filename: str | None) -> str:
    name = Path((filename or "capture.pcap").replace("\\", "/")).name
    name = "".join(char for char in name if char.isprintable() and char not in "\r\n\0")
    return (name or "capture.pcap")[:255]


@app.get("/")
def root():
    return {"engine": "online"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    original_filename = _safe_filename(file.filename)
    file_path = EVIDENCE_DIR / f"{uuid.uuid4().hex}.capture"
    digest = hashlib.sha256()
    filesize = 0
    persisted = False

    try:
        descriptor = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            while chunk := await file.read(CHUNK_SIZE_BYTES):
                filesize += len(chunk)
                if filesize > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail="Capture exceeds the 1 GiB upload limit")
                digest.update(chunk)
                destination.write(chunk)

        if filesize == 0:
            raise HTTPException(status_code=400, detail="The uploaded capture is empty")

        try:
            file_format = detect_capture_format(file_path)
        except CaptureAnalysisError as error:
            raise HTTPException(status_code=415, detail=str(error)) from error

        sha256 = digest.hexdigest()
        existing = conn.execute(
            "SELECT id FROM captures WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if existing:
            return {
                "error": "duplicate_capture",
                "filename": original_filename,
                "sha256": sha256,
            }

        try:
            discover_hosts(file_path, commit=False)
        except Exception as error:
            conn.rollback()
            raise HTTPException(status_code=422, detail="Capture packets could not be parsed") from error

        try:
            cursor = conn.execute(
                """
                INSERT INTO captures (filename, filesize, sha256)
                VALUES (?, ?, ?)
                """,
                (original_filename, filesize, sha256),
            )
            conn.commit()
        except Exception as error:
            conn.rollback()
            raise HTTPException(status_code=500, detail="Could not save capture metadata") from error

        persisted = True
        return {
            "id": cursor.lastrowid,
            "filename": original_filename,
            "filesize": filesize,
            "sha256": sha256,
            "file_format": file_format,
        }
    except HTTPException:
        raise
    except OSError as error:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Could not safely store uploaded capture") from error
    finally:
        await file.close()
        if not persisted:
            file_path.unlink(missing_ok=True)


@app.get("/captures")
def get_captures():
    cursor = conn.execute(
        """
        SELECT id, filename, filesize, sha256
        FROM captures
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    return [
        {
            "id": row[0],
            "filename": row[1],
            "filesize": row[2],
            "sha256": row[3],
        }
        for row in rows
    ]


@app.get("/hosts")
def get_hosts():
    cursor = conn.execute(
        """
        SELECT
            id,
            ip,
            packet_count,
            first_seen,
            last_seen
        FROM hosts
        ORDER BY packet_count DESC
        """
    )

    rows = cursor.fetchall()

    return [
        {
            "id": row[0],
            "ip": row[1],
            "packet_count": row[2],
            "first_seen": row[3],
            "last_seen": row[4],
        }
        for row in rows
    ]


@app.get("/hosts/{ip}")
def get_host(ip: str):
    cursor = conn.execute(
        """
        SELECT
            id,
            ip,
            packet_count,
            first_seen,
            last_seen
        FROM hosts
        WHERE ip = ?
        """,
        (ip,),
    )

    row = cursor.fetchone()

    if not row:
        return {"error": "host_not_found"}

    return {
        "id": row[0],
        "ip": row[1],
        "packet_count": row[2],
        "first_seen": row[3],
        "last_seen": row[4],
    }
