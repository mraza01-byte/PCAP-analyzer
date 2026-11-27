import sqlite3

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

import engine.main as engine_api
import services.host_discovery as host_discovery


def test_upload_persists_discovered_hosts_and_flows(tmp_path, monkeypatch):
    connection = sqlite3.connect(tmp_path / "engine.db", check_same_thread=False)
    connection.executescript("""
        CREATE TABLE captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filesize INTEGER NOT NULL,
            sha256 TEXT NOT NULL
        );
        CREATE TABLE hosts (
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
        );
        CREATE TABLE flows (
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
        );
    """)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    monkeypatch.setattr(engine_api, "conn", connection)
    monkeypatch.setattr(engine_api, "EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(host_discovery, "conn", connection)

    capture = tmp_path / "sample.pcap"
    request = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.10", dst="198.51.100.20"
    ) / TCP(sport=49152, dport=443, flags="S")
    response_packet = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(
        src="198.51.100.20", dst="192.0.2.10"
    ) / TCP(sport=443, dport=49152, flags="SA")
    request.time = 1_800_000_000
    response_packet.time = 1_800_000_001
    wrpcap(str(capture), [request, response_packet])

    try:
        with TestClient(engine_api.app) as client, capture.open("rb") as capture_file:
            upload_response = client.post(
                "/upload",
                files={"file": (capture.name, capture_file, "application/octet-stream")},
            )

            assert upload_response.status_code == 200
            capture_id = upload_response.json()["id"]
            hosts = client.get("/hosts").json()
            assert {host["ip"] for host in hosts} == {"192.0.2.10", "198.51.100.20"}
            flows = client.get("/flows", params={"capture_id": capture_id}).json()
            assert len(flows) == 1
            assert flows[0]["protocol"] == "TCP"
            assert flows[0]["packet_count"] == 2
            assert flows[0]["bytes_total"] == len(request) + len(response_packet)
    finally:
        connection.close()
