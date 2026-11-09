from pathlib import Path

from fastapi import FastAPI, UploadFile, File

from database import conn
from services.hashing import sha256_file

app = FastAPI(title="PCAP-MAN Engine")

EVIDENCE_DIR = Path("evidence")
EVIDENCE_DIR.mkdir(exist_ok=True)


@app.get("/")
def root():
    return {"engine": "online"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    file_path = EVIDENCE_DIR / file.filename

    with open(file_path, "wb") as f:
        f.write(await file.read())

    sha256 = sha256_file(str(file_path))
    filesize = file_path.stat().st_size

    cursor = conn.execute(
        "SELECT id FROM captures WHERE sha256 = ?",
        (sha256,),
    )

    existing = cursor.fetchone()

    if existing:
        return {
            "error": "duplicate_capture",
            "filename": file.filename,
            "sha256": sha256,
        }

    cursor = conn.execute(
        """
        INSERT INTO captures
        (filename, filesize, sha256)
        VALUES (?, ?, ?)
        """,
        (
            file.filename,
            filesize,
            sha256,
        ),
    )

    conn.commit()

    return {
        "id": cursor.lastrowid,
        "filename": file.filename,
        "filesize": filesize,
        "sha256": sha256,
    }


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