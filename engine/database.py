from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "pcapman.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(DB_PATH.as_posix(), check_same_thread=False)

conn.execute("""
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    sha256 TEXT NOT NULL
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ip TEXT UNIQUE NOT NULL,

    hostname TEXT DEFAULT 'Unknown',
    mac TEXT DEFAULT 'Unknown',
    role TEXT DEFAULT 'Discovered Host',

    packet_count INTEGER DEFAULT 0,

    bytes_total INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,

    first_seen TEXT,
    last_seen TEXT
)
""")

conn.commit()
