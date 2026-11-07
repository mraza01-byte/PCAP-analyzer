"""End-to-end API tests: the app starts, migrates a fresh database, and serves real data."""
import os
import platform

import pytest
from fastapi.testclient import TestClient

from app.database.session import get_session_factory
from app.main import app
from app.models import Capture, CaptureFormat, Investigation


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
    assert len(rows[0]["id"]) == 36 and rows[0]["status"] == "open"


def test_settings_report_real_values(client):
    data = client.get("/api/v1/settings").json()
    assert data["python_version"] == platform.python_version()
    assert data["cpu_count"] == (os.cpu_count() or 1)
    assert data["tshark_detected"] is False
    assert data["database_path"].endswith("app.db") and data["database_size_bytes"] > 0


def test_health_stays_exactly_the_agreed_contract(client):
    assert client.get("/health").json() == {"status": "healthy", "application": "PCAP-MAN"}


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


def test_unbuilt_features_fail_honestly(client):
    # Upload and briefings belong to later phases: they must not pretend to work.
    assert client.post("/api/v1/captures/upload").status_code in (404, 405)
    assert client.get("/api/v1/briefings/generate").status_code == 404
