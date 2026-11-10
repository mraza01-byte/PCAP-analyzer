"""End-to-end API tests: the app starts, migrates a fresh database, and serves real data."""
import os
import platform
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, PcapNgWriter, wrpcap
from fastapi.testclient import TestClient

from app.database.session import get_session_factory
from app.core.config import get_settings
from app.main import app
from app.models import Capture, CaptureFormat, CaptureStatus, Flow, Host, Investigation, TimelineEvent


@pytest.fixture
def client():
    # "with" runs the startup logic, including the automatic database setup.
    with TestClient(app) as c:
        yield c


def test_startup_creates_the_database_structure(client):
    # If startup had not migrated, this would fail with "no such table".
    assert client.get("/api/v1/stats").status_code == 200


def test_stats_are_real_zeros_on_a_fresh_database(client):
    assert client.get("/api/v1/stats").json() == {"captures": 0, "hosts": 0, "flows": 0, "investigations": 0}


def test_stats_follow_the_database(client):
    with get_session_factory()() as db:
        db.add(Capture(original_filename="a.pcap", file_path="x", file_size_bytes=1, sha256="a" * 64,
                       file_format=CaptureFormat.PCAP))
        db.add(Investigation(title="Case 1"))
        db.commit()
    assert client.get("/api/v1/stats").json() == {"captures": 1, "hosts": 0, "flows": 0, "investigations": 1}


def test_lists_are_empty_not_faked(client):
    assert client.get("/api/v1/captures").json() == []
    assert client.get("/api/v1/investigations").json() == []
    assert client.get("/api/v1/hosts").json() == {"total": 0, "hosts": []}
    assert client.get("/api/v1/flows").json() == {"total": 0, "flows": []}
    assert client.get("/api/v1/timeline").json() == {"total": 0, "events": []}


def test_list_returns_stored_rows_with_uuid_ids(client):
    with get_session_factory()() as db:
        db.add(Investigation(title="Beaconing case"))
        db.commit()
    rows = client.get("/api/v1/investigations").json()
    assert [r["title"] for r in rows] == ["Beaconing case"]
    assert len(rows[0]["id"]) == 36 and rows[0]["status"] == "active"


def test_settings_report_real_values(client):
    data = client.get("/api/v1/settings").json()
    assert data["python_version"] == platform.python_version()
    assert data["cpu_count"] == (os.cpu_count() or 1)
    assert data["tshark_detected"] is False
    assert data["database_path"].endswith("app.db") and data["database_size_bytes"] > 0


def test_health_stays_exactly_the_agreed_contract(client):
    assert client.get("/health").json() == {"status": "healthy", "application": "PCAP-MAN"}


def _write_test_capture(path):
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=49152, dport=443, flags="S")
    packet.time = 1_800_000_000
    wrpcap(str(path), [packet])


def test_upload_runs_engine_and_persists_capture_hosts_flows_and_timeline(client, tmp_path):
    capture_path = tmp_path / "evidence.pcap"
    _write_test_capture(capture_path)

    with capture_path.open("rb") as capture_file:
        response = client.post("/api/v1/captures/upload", files={"file": ("../evidence.pcap", capture_file, "application/octet-stream")})

    assert response.status_code == 201
    result = response.json()
    assert result["filename"] == "evidence.pcap"
    assert result["status"] == "analyzed" and result["packet_count"] == 1
    assert result["flow_count"] == 1 and len(result["sha256"]) == 64
    with get_session_factory()() as db:
        saved = db.get(Capture, result["id"])
        assert saved and Path(saved.file_path).is_file()
        assert db.query(Host).filter_by(capture_id=saved.id).count() == 2
        assert db.query(Flow).filter_by(capture_id=saved.id).one().byte_count > 0
        assert db.query(TimelineEvent).filter_by(capture_id=saved.id).count() == 1

    hosts = client.get("/api/v1/hosts").json()
    assert hosts["total"] == 2
    assert {host["ip"] for host in hosts["hosts"]} == {"192.0.2.10", "198.51.100.20"}
    flows = client.get("/api/v1/flows?search=192.0.2.10").json()
    assert flows["total"] == 1
    assert flows["flows"][0]["dst_ip"] == "198.51.100.20"
    events = client.get("/api/v1/timeline?category=TCP&severity=info").json()
    assert events["total"] == 1 and events["events"][0]["timestamp"]


def test_upload_rejects_non_capture_without_creating_record(client):
    response = client.post("/api/v1/captures/upload", files={"file": ("notes.pcap", b"not a capture", "application/octet-stream")})

    assert response.status_code == 415
    assert client.get("/api/v1/captures").json() == []


def test_upload_accepts_pcapng_and_deduplicates_by_sha256(client, tmp_path):
    capture_path = tmp_path / "sample.pcapng"
    packet = Ether() / IP(src="203.0.113.1", dst="203.0.113.2") / TCP(sport=12000, dport=443)
    packet.time = 1_800_000_000
    writer = PcapNgWriter(str(capture_path))
    writer.write(packet)
    writer.close()

    with capture_path.open("rb") as capture_file:
        first = client.post("/api/v1/captures/upload", files={"file": ("sample.pcapng", capture_file)})
    with capture_path.open("rb") as capture_file:
        second = client.post("/api/v1/captures/upload", files={"file": ("copy.pcapng", capture_file)})

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["file_type"] == "pcapng"
    assert len(client.get("/api/v1/captures").json()) == 1


def test_upload_rejects_file_over_configured_limit(client):
    get_settings().max_upload_size_bytes = 16

    response = client.post("/api/v1/captures/upload", files={"file": ("large.pcap", b"x" * 32)})

    assert response.status_code == 413
    assert client.get("/api/v1/captures").json() == []


def test_corrupt_capture_is_recorded_as_failed(client):
    response = client.post("/api/v1/captures/upload", files={"file": ("broken.pcap", b"\xd4\xc3\xb2\xa1broken", "application/octet-stream")})

    assert response.status_code == 422
    assert response.json()["error"]["details"]["capture_id"]
    failed = client.get("/api/v1/captures").json()
    assert len(failed) == 1
    assert failed[0]["status"] == CaptureStatus.FAILED.value
    assert failed[0]["notes"]


def test_investigation_crud_and_briefing_use_stored_capture_data(client, tmp_path):
    capture_path = tmp_path / "evidence.pcap"
    _write_test_capture(capture_path)
    with capture_path.open("rb") as capture_file:
        upload = client.post("/api/v1/captures/upload", files={"file": ("evidence.pcap", capture_file)})
    capture_id = upload.json()["id"]

    created = client.post("/api/v1/investigations", json={
        "title": "Review observed traffic",
        "severity": "medium",
        "lead_analyst": "Analyst",
        "linked_capture_ids": [capture_id],
    })
    assert created.status_code == 201
    case = created.json()
    assert case["linked_capture_ids"] == capture_id
    updated = client.patch(f"/api/v1/investigations/{case['id']}", json={"findings": "One TCP flow observed", "status": "under_review"})
    assert updated.json()["findings"] == "One TCP flow observed"
    assert updated.json()["status"] == "under_review"

    report = client.get(f"/api/v1/briefings/generate?case_id={case['id']}")
    assert report.status_code == 200
    payload = report.json()
    assert payload["evidence_records"][0]["sha256"] == upload.json()["sha256"]
    assert {ioc["value"] for ioc in payload["iocs"]} == {"192.0.2.10", "198.51.100.20"}
    assert payload["recommendations"] == []

    assert client.delete(f"/api/v1/investigations/{case['id']}").status_code == 204


def test_health_reports_503_when_database_is_unreachable(monkeypatch):
    monkeypatch.setenv("PCAPMAN_DATABASE_URL", "sqlite:////this/folder/does/not/exist/x.db")
    from app.core.config import get_settings
    get_session_factory.cache_clear()
    from app.database.session import get_engine
    get_engine.cache_clear()
    get_settings.cache_clear()
    # No "with": skip startup so we test only the health check itself.
    response = TestClient(app, raise_server_exceptions=False).get("/health")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"


@pytest.mark.parametrize("origin", ["http://localhost:1420", "http://127.0.0.1:1420", "tauri://localhost", "http://tauri.localhost"])
def test_cors_allows_the_desktop_app(client, origin):
    response = client.options("/api/v1/stats", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin


def test_cors_blocks_other_websites(client):
    response = client.options("/api/v1/stats", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in response.headers


def test_upload_requires_a_file(client):
    assert client.post("/api/v1/captures/upload").status_code == 422
