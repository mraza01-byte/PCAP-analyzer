import sqlite3

conn = sqlite3.connect("pcapman.db", check_same_thread=False)

conn.execute("""
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    sha256 TEXT NOT NULL
)
""")

conn.commit()