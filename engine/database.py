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

conn.execute("""
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    application TEXT DEFAULT '',
    packet_count INTEGER DEFAULT 0,
    bytes_total INTEGER DEFAULT 0,
    bytes_forward INTEGER DEFAULT 0,
    bytes_reverse INTEGER DEFAULT 0,
    start_time TEXT,
    end_time TEXT,
    tcp_flags TEXT DEFAULT '-',
    summary TEXT
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER,
    timestamp TEXT,
    query_name TEXT,
    query_type TEXT,
    response_code TEXT,
    answers TEXT,
    ttl INTEGER
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS http_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER,
    timestamp TEXT,
    method TEXT,
    host TEXT,
    url TEXT,
    path TEXT,
    user_agent TEXT,
    status_code INTEGER,
    response_phrase TEXT,
    content_type TEXT
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS tls_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER,
    timestamp TEXT,
    version TEXT,
    sni TEXT,
    cipher_suite TEXT,
    alpn TEXT
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER,
    fingerprint_sha256 TEXT,
    subject_cn TEXT,
    subject_org TEXT,
    issuer_cn TEXT,
    issuer_org TEXT,
    valid_from TEXT,
    valid_to TEXT,
    serial_number TEXT,
    san_list TEXT,
    is_self_signed INTEGER DEFAULT 0
)
""")

conn.commit()
