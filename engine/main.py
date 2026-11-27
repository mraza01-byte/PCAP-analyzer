import hashlib
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from database import conn
from services.analyzer import CaptureAnalysisError, analyze_capture, detect_capture_format
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
            analysis = analyze_capture(file_path)
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
            capture_id = cursor.lastrowid
            for flow in analysis.get("flows", []):
                conn.execute(
                    """
                    INSERT INTO flows
                    (capture_id, src_ip, src_port, dst_ip, dst_port, protocol, application,
                     packet_count, bytes_total, bytes_forward, bytes_reverse, start_time,
                     end_time, tcp_flags, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        capture_id,
                        flow["src_ip"],
                        flow["src_port"],
                        flow["dst_ip"],
                        flow["dst_port"],
                        flow["protocol"],
                        flow.get("application", ""),
                        flow["packet_count"],
                        flow["bytes_total"],
                        flow["bytes_forward"],
                        flow["bytes_reverse"],
                        flow["start_time"].isoformat(),
                        flow["end_time"].isoformat(),
                        flow["tcp_flags"],
                        flow["summary"],
                    ),
                )
            conn.commit()
        except Exception as error:
            conn.rollback()
            raise HTTPException(status_code=500, detail="Could not save capture analysis") from error

        persisted = True
        return {
            "id": capture_id,
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


@app.get("/flows")
def get_flows(protocol: str | None = None, search: str | None = None, capture_id: int | None = None):
    query = "SELECT id, capture_id, src_ip, src_port, dst_ip, dst_port, protocol, application, packet_count, bytes_total, bytes_forward, bytes_reverse, start_time, end_time, tcp_flags, summary FROM flows WHERE 1=1"
    params = []
    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    if protocol:
        query += " AND (UPPER(protocol) = ? OR UPPER(application) = ?)"
        params.extend([protocol.upper(), protocol.upper()])
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR summary LIKE ? OR application LIKE ?)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern, pattern])
    query += " ORDER BY id DESC"
    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    return [
        {
            "id": r[0],
            "capture_id": r[1],
            "flow_key": f"{r[2]}:{r[3] or '-'}<->{r[4]}:{r[5] or '-'}/{r[6]}",
            "src_ip": r[2],
            "src_port": r[3],
            "dst_ip": r[4],
            "dst_port": r[5],
            "protocol": r[6],
            "application": r[7],
            "packet_count": r[8],
            "byte_count": r[9],
            "bytes_total": r[9],
            "bytes_forward": r[10],
            "bytes_reverse": r[11],
            "start_time": r[12],
            "end_time": r[13],
            "tcp_flags": r[14],
            "summary": r[15],
        }
        for r in rows
    ]


@app.get("/flows/{flow_id}")
def get_flow(flow_id: int):
    cursor = conn.execute(
        "SELECT id, capture_id, src_ip, src_port, dst_ip, dst_port, protocol, application, packet_count, bytes_total, bytes_forward, bytes_reverse, start_time, end_time, tcp_flags, summary FROM flows WHERE id = ?",
        (flow_id,),
    )
    r = cursor.fetchone()
    if not r:
        return {"error": "flow_not_found"}
    return {
        "id": r[0],
        "capture_id": r[1],
        "flow_key": f"{r[2]}:{r[3] or '-'}<->{r[4]}:{r[5] or '-'}/{r[6]}",
        "src_ip": r[2],
        "src_port": r[3],
        "dst_ip": r[4],
        "dst_port": r[5],
        "protocol": r[6],
        "application": r[7],
        "packet_count": r[8],
        "byte_count": r[9],
        "bytes_total": r[9],
        "bytes_forward": r[10],
        "bytes_reverse": r[11],
        "start_time": r[12],
        "end_time": r[13],
        "tcp_flags": r[14],
        "summary": r[15],
    }


@app.get("/dns")
def get_dns(capture_id: int | None = None):
    query = "SELECT id, capture_id, timestamp, query_name, query_type, response_code, answers, ttl FROM dns_records WHERE 1=1"
    params = []
    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    cursor = conn.execute(query, params)
    return [
        {
            "id": r[0],
            "capture_id": r[1],
            "timestamp": r[2],
            "query_name": r[3],
            "query_type": r[4],
            "response_code": r[5],
            "answers": r[6],
            "ttl": r[7],
        }
        for r in cursor.fetchall()
    ]


@app.get("/http")
def get_http(capture_id: int | None = None):
    query = "SELECT id, capture_id, timestamp, method, host, url, path, user_agent, status_code, response_phrase, content_type FROM http_requests WHERE 1=1"
    params = []
    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    cursor = conn.execute(query, params)
    return [
        {
            "id": r[0],
            "capture_id": r[1],
            "timestamp": r[2],
            "method": r[3],
            "host": r[4],
            "url": r[5],
            "path": r[6],
            "user_agent": r[7],
            "status_code": r[8],
            "response_phrase": r[9],
            "content_type": r[10],
        }
        for r in cursor.fetchall()
    ]


@app.get("/tls")
def get_tls(capture_id: int | None = None):
    query = "SELECT id, capture_id, timestamp, version, sni, cipher_suite, alpn FROM tls_records WHERE 1=1"
    params = []
    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    cursor = conn.execute(query, params)
    return [
        {
            "id": r[0],
            "capture_id": r[1],
            "timestamp": r[2],
            "version": r[3],
            "sni": r[4],
            "cipher_suite": r[5],
            "alpn": r[6],
        }
        for r in cursor.fetchall()
    ]


@app.get("/certificates")
def get_certificates(capture_id: int | None = None):
    query = "SELECT id, capture_id, fingerprint_sha256, subject_cn, subject_org, issuer_cn, issuer_org, valid_from, valid_to, serial_number, san_list, is_self_signed FROM certificates WHERE 1=1"
    params = []
    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    cursor = conn.execute(query, params)
    return [
        {
            "id": r[0],
            "capture_id": r[1],
            "fingerprint_sha256": r[2],
            "subject_cn": r[3],
            "subject_org": r[4],
            "issuer_cn": r[5],
            "issuer_org": r[6],
            "valid_from": r[7],
            "valid_to": r[8],
            "serial_number": r[9],
            "san_list": r[10],
            "is_self_signed": bool(r[11]),
        }
        for r in cursor.fetchall()
    ]


@app.get("/protocols/stats")
def get_engine_protocol_stats(capture_id: int | None = None):
    flows = get_flows(capture_id=capture_id)
    dns = get_dns(capture_id=capture_id)
    http = get_http(capture_id=capture_id)
    tls = get_tls(capture_id=capture_id)
    certs = get_certificates(capture_id=capture_id)
    return {
        "total_dns": len(dns),
        "total_http": len(http),
        "total_tls": len(tls),
        "total_certificates": len(certs),
        "total_flows": len(flows),
    }
