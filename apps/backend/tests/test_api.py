"""End-to-end API tests: the app starts, migrates a fresh database, and serves real data."""
import os
import platform
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock

import pytest
from scapy.all import Ether, IP, TCP, PcapNgWriter, wrpcap
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1 import captures as captures_api
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


def test_entity_lists_filter_by_capture_id(client, tmp_path):
    capture_ids = []
    for index, (source, destination) in enumerate((
        ("192.0.2.10", "198.51.100.20"),
        ("203.0.113.10", "203.0.113.20"),
    )):
        capture_path = tmp_path / f"capture-{index}.pcap"
        packet = Ether() / IP(src=source, dst=destination) / TCP(sport=41000 + index, dport=443, flags="S")
        packet.time = 1_800_000_000 + index
        wrpcap(str(capture_path), [packet])
        with capture_path.open("rb") as capture_file:
            response = client.post(
                "/api/v1/captures/upload",
                files={"file": (capture_path.name, capture_file, "application/octet-stream")},
            )
        assert response.status_code == 201
        capture_ids.append(response.json()["id"])

    for capture_id, expected_hosts, expected_flow, expected_event in (
        (capture_ids[0], {"192.0.2.10", "198.51.100.20"}, "192.0.2.10", "192.0.2.10:41000"),
        (capture_ids[1], {"203.0.113.10", "203.0.113.20"}, "203.0.113.10", "203.0.113.10:41001"),
    ):
        hosts = client.get("/api/v1/hosts", params={"capture_id": capture_id}).json()
        flows = client.get("/api/v1/flows", params={"capture_id": capture_id}).json()
        events = client.get("/api/v1/timeline", params={"capture_id": capture_id}).json()
        assert hosts["total"] == 2
        assert {host["ip"] for host in hosts["hosts"]} == expected_hosts
        assert flows["total"] == 1
        assert flows["flows"][0]["src_ip"] == expected_flow
        assert events["total"] == 1
        assert events["events"][0]["src"] == expected_event

    missing_capture = "00000000-0000-0000-0000-000000000000"
    assert client.get("/api/v1/hosts", params={"capture_id": missing_capture}).json()["total"] == 0
    assert client.get("/api/v1/flows", params={"capture_id": missing_capture}).json()["total"] == 0
    assert client.get("/api/v1/timeline", params={"capture_id": missing_capture}).json()["total"] == 0


def test_search_treats_sql_wildcards_as_literals(client, tmp_path):
    capture_path = tmp_path / "literal-search.pcap"
    _write_test_capture(capture_path)
    with capture_path.open("rb") as capture_file:
        uploaded = client.post(
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_file, "application/octet-stream")},
        )
    capture_id = uploaded.json()["id"]

    assert client.get("/api/v1/hosts", params={"search": "_", "capture_id": capture_id}).json()["total"] == 0
    assert client.get("/api/v1/flows", params={"search": "%", "capture_id": capture_id}).json()["total"] == 0
    assert client.get("/api/v1/timeline", params={"search": "_", "capture_id": capture_id}).json()["total"] == 0


def test_unexpected_analyzer_error_marks_capture_failed_and_allows_retry(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "retry.pcap"
    _write_test_capture(capture_path)
    actual_analyzer = captures_api.analyze_capture

    def fail_analysis(_path, _is_cancelled=None):
        raise RuntimeError("unexpected analyzer failure")

    monkeypatch.setattr(captures_api, "analyze_capture", fail_analysis)
    with capture_path.open("rb") as capture_file:
        failed = client.post(
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_file, "application/octet-stream")},
        )
    assert failed.status_code == 500
    capture_id = failed.json()["error"]["details"]["capture_id"]
    with get_session_factory()() as db:
        saved = db.get(Capture, capture_id)
        assert saved and saved.status == CaptureStatus.FAILED
        assert "unexpected analyzer failure" in saved.error_message

    monkeypatch.setattr(captures_api, "analyze_capture", actual_analyzer)
    with capture_path.open("rb") as capture_file:
        retried = client.post(
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_file, "application/octet-stream")},
        )
    assert retried.status_code == 200
    assert retried.json()["id"] == capture_id
    assert retried.json()["status"] == "analyzed"
    assert client.get("/api/v1/captures").json()[0]["id"] == capture_id


def test_concurrent_failed_capture_retry_is_processed_once(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "concurrent-retry.pcap"
    _write_test_capture(capture_path)
    capture_bytes = capture_path.read_bytes()
    actual_analyzer = captures_api.analyze_capture

    def fail_analysis(_path, _is_cancelled=None):
        raise RuntimeError("initial analyzer failure")

    monkeypatch.setattr(captures_api, "analyze_capture", fail_analysis)
    failed = client.post(
        "/api/v1/captures/upload",
        files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
    )
    assert failed.status_code == 500

    analyzer_started = Event()
    release_analyzer = Event()
    analyzer_calls = 0
    analyzer_calls_lock = Lock()

    def blocking_analysis(path, is_cancelled=None):
        nonlocal analyzer_calls
        with analyzer_calls_lock:
            analyzer_calls += 1
        analyzer_started.set()
        assert release_analyzer.wait(timeout=10)
        return actual_analyzer(path, is_cancelled)

    monkeypatch.setattr(captures_api, "analyze_capture", blocking_analysis)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first_retry = executor.submit(
            client.post,
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
        )
        try:
            assert analyzer_started.wait(timeout=10)
            competing_retry = client.post(
                "/api/v1/captures/upload",
                files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
            )
            assert competing_retry.status_code == 200
            assert competing_retry.json()["status"] == "processing"
        finally:
            release_analyzer.set()

        completed_retry = first_retry.result(timeout=15)

    assert completed_retry.status_code == 200
    assert completed_retry.json()["status"] == "analyzed"
    assert analyzer_calls == 1
    assert len(client.get("/api/v1/captures").json()) == 1


def test_abandoned_processing_capture_is_reclaimed_and_recovered(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "abandoned.pcap"
    _write_test_capture(capture_path)
    capture_bytes = capture_path.read_bytes()
    digest = hashlib.sha256(capture_bytes).hexdigest()
    old_evidence = get_settings().evidence_dir / "abandoned.capture"
    old_evidence.write_bytes(capture_bytes)
    old_capture_id = "00000000-0000-0000-0000-000000000123"
    with get_session_factory()() as db:
        db.add(Capture(
            id=old_capture_id,
            original_filename=capture_path.name,
            file_path=str(old_evidence.resolve()),
            file_size_bytes=len(capture_bytes),
            sha256=digest,
            file_format=CaptureFormat.PCAP,
            status=CaptureStatus.PROCESSING,
            processing_token="abandoned-worker",
            processing_lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ))
        db.commit()

    actual_analyzer = captures_api.analyze_capture
    analyzer_calls = 0

    def count_analysis(path, is_cancelled=None):
        nonlocal analyzer_calls
        analyzer_calls += 1
        return actual_analyzer(path, is_cancelled)

    monkeypatch.setattr(captures_api, "analyze_capture", count_analysis)
    response = client.post(
        "/api/v1/captures/upload",
        files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
    )

    assert response.status_code == 200
    assert response.json()["id"] == old_capture_id
    assert response.json()["status"] == "analyzed"
    assert analyzer_calls == 1
    assert not old_evidence.exists()
    with get_session_factory()() as db:
        recovered = db.get(Capture, old_capture_id)
        assert recovered and recovered.status == CaptureStatus.COMPLETED
        assert recovered.processing_token is None
        assert recovered.processing_lease_expires_at is None
        assert db.query(Host).filter_by(capture_id=old_capture_id).count() == 2


def test_active_processing_capture_lease_is_renewed_and_not_reclaimed(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "active.pcap"
    _write_test_capture(capture_path)
    capture_bytes = capture_path.read_bytes()
    digest = hashlib.sha256(capture_bytes).hexdigest()
    capture_id = "00000000-0000-0000-0000-000000000124"
    active_token = "active-worker"
    original_expiry = datetime.now(timezone.utc) + timedelta(seconds=60)
    with get_session_factory()() as db:
        db.add(Capture(
            id=capture_id,
            original_filename=capture_path.name,
            file_path="unused",
            file_size_bytes=len(capture_bytes),
            sha256=digest,
            file_format=CaptureFormat.PCAP,
            status=CaptureStatus.PROCESSING,
            processing_token=active_token,
            processing_lease_expires_at=original_expiry,
        ))
        db.commit()

    assert captures_api._renew_processing_lease(capture_id, active_token)
    with get_session_factory()() as db:
        renewed = db.get(Capture, capture_id)
        assert renewed and renewed.processing_lease_expires_at > original_expiry

    def must_not_analyze(_path, _is_cancelled=None):
        raise AssertionError("an active capture lease must not be reclaimed")

    monkeypatch.setattr(captures_api, "analyze_capture", must_not_analyze)
    response = client.post(
        "/api/v1/captures/upload",
        files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
    )

    assert response.status_code == 200
    assert response.json()["id"] == capture_id
    assert response.json()["status"] == "processing"
    with get_session_factory()() as db:
        active = db.get(Capture, capture_id)
        assert active and active.processing_token == active_token


def test_lease_renewal_failure_aborts_stale_worker_and_replacement_completes(
    client, tmp_path, monkeypatch
):
    capture_path = tmp_path / "lease-takeover.pcap"
    _write_test_capture(capture_path)
    capture_bytes = capture_path.read_bytes()
    digest = hashlib.sha256(capture_bytes).hexdigest()
    actual_analyzer = captures_api.analyze_capture
    actual_renewal = captures_api._renew_processing_lease
    monkeypatch.setattr(captures_api, "PROCESSING_HEARTBEAT_SECONDS", 0.01)

    renewal_failed = Event()
    stale_analysis_started = Event()
    stale_analysis_cancelled = Event()
    allow_stale_analyzer_exit = Event()
    replacement_analysis_started = Event()
    analyzer_lock = Lock()
    analyzer_calls = 0
    old_token = None

    def fail_old_worker_renewal(capture_id, processing_token):
        nonlocal old_token
        if old_token is None:
            old_token = processing_token
            with get_session_factory()() as db:
                capture = db.get(Capture, capture_id)
                assert capture and capture.processing_token == processing_token
                capture.processing_lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                db.commit()
            renewal_failed.set()
            return False
        if processing_token == old_token:
            return False
        return actual_renewal(capture_id, processing_token)

    def cancellation_aware_analysis(path, is_cancelled=None):
        nonlocal analyzer_calls
        with analyzer_lock:
            analyzer_calls += 1
            call_number = analyzer_calls
        if call_number == 1:
            stale_analysis_started.set()
            assert is_cancelled is not None
            deadline = time.monotonic() + 5
            while not is_cancelled() and time.monotonic() < deadline:
                time.sleep(0.001)
            assert is_cancelled()
            stale_analysis_cancelled.set()
            assert allow_stale_analyzer_exit.wait(timeout=10)
            raise captures_api.CaptureAnalysisCancelled("lease was lost")
        replacement_analysis_started.set()
        return actual_analyzer(path, is_cancelled)

    monkeypatch.setattr(captures_api, "_renew_processing_lease", fail_old_worker_renewal)
    monkeypatch.setattr(captures_api, "analyze_capture", cancellation_aware_analysis)

    with ThreadPoolExecutor(max_workers=2) as executor:
        stale_request = executor.submit(
            client.post,
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
        )
        assert stale_analysis_started.wait(timeout=10)
        assert renewal_failed.wait(timeout=10)
        assert stale_analysis_cancelled.wait(timeout=10)

        with get_session_factory()() as db:
            capture = db.query(Capture).filter_by(sha256=digest).one()
            stale_evidence_path = Path(capture.file_path)
            assert capture.status == CaptureStatus.PROCESSING
            assert capture.processing_token == old_token

        replacement_request = executor.submit(
            client.post,
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_bytes, "application/octet-stream")},
        )
        assert replacement_analysis_started.wait(timeout=10)
        with get_session_factory()() as db:
            claimed = db.query(Capture).filter_by(sha256=digest).one()
            assert claimed.processing_token != old_token
            replacement_evidence_path = Path(claimed.file_path)
            assert replacement_evidence_path != stale_evidence_path

        allow_stale_analyzer_exit.set()
        stale_response = stale_request.result(timeout=15)
        replacement_response = replacement_request.result(timeout=15)

    assert stale_response.status_code == 409
    assert replacement_response.status_code == 200
    assert replacement_response.json()["status"] == "analyzed"
    assert analyzer_calls == 2
    assert replacement_evidence_path.exists()
    with get_session_factory()() as db:
        completed = db.query(Capture).filter_by(sha256=digest).one()
        assert completed.status == CaptureStatus.COMPLETED
        assert completed.file_path == str(replacement_evidence_path)
        assert completed.processing_token is None
        assert db.query(Host).filter_by(capture_id=completed.id).count() == 2


def test_concurrent_independent_sessions_cannot_insert_same_capture_hash(client):
    digest = "f" * 64
    barrier = Barrier(2)

    def insert_duplicate():
        with get_session_factory()() as db:
            db.add(Capture(
                original_filename="concurrent.pcap",
                file_path="unused",
                file_size_bytes=1,
                sha256=digest,
                file_format=CaptureFormat.PCAP,
                status=CaptureStatus.PROCESSING,
            ))
            barrier.wait(timeout=10)
            try:
                db.commit()
                return "inserted"
            except IntegrityError:
                db.rollback()
                return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: insert_duplicate(), range(2)))

    assert sorted(outcomes) == ["duplicate", "inserted"]
    with get_session_factory()() as db:
        assert db.query(Capture).filter_by(sha256=digest).count() == 1


def test_failed_capture_duplicate_retries_analysis_instead_of_returning_old_failure(client):
    broken = b"\xd4\xc3\xb2\xa1broken"
    first = client.post(
        "/api/v1/captures/upload",
        files={"file": ("broken.pcap", broken, "application/octet-stream")},
    )
    second = client.post(
        "/api/v1/captures/upload",
        files={"file": ("broken.pcap", broken, "application/octet-stream")},
    )

    assert first.status_code == second.status_code == 422
    assert first.json()["error"]["details"]["capture_id"] == second.json()["error"]["details"]["capture_id"]
    assert len(client.get("/api/v1/captures").json()) == 1


def test_metadata_commit_failure_removes_unpersisted_evidence(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "commit-failure.pcap"
    _write_test_capture(capture_path)

    def fail_commit(_session):
        raise RuntimeError("simulated metadata commit failure")

    monkeypatch.setattr(Session, "commit", fail_commit)
    with capture_path.open("rb") as capture_file:
        response = client.post(
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_file, "application/octet-stream")},
        )

    assert response.status_code == 500
    assert client.get("/api/v1/captures").json() == []
    assert list(get_settings().evidence_dir.glob("*.capture")) == []


def test_analysis_persistence_failure_rolls_back_partial_entities(client, tmp_path, monkeypatch):
    capture_path = tmp_path / "partial-persistence.pcap"
    _write_test_capture(capture_path)

    def fail_after_host_flush(db, capture, _analysis, _processing_token):
        db.add(Host(capture_id=capture.id, ip_address="192.0.2.10"))
        db.flush()
        raise RuntimeError("simulated analysis persistence failure")

    monkeypatch.setattr(captures_api, "persist_analysis", fail_after_host_flush)
    with capture_path.open("rb") as capture_file:
        response = client.post(
            "/api/v1/captures/upload",
            files={"file": (capture_path.name, capture_file, "application/octet-stream")},
        )

    assert response.status_code == 500
    with get_session_factory()() as db:
        capture = db.query(Capture).one()
        assert capture.status == CaptureStatus.FAILED
        assert "simulated analysis persistence failure" in capture.error_message
        assert db.query(Host).count() == 0
        assert db.query(Flow).count() == 0
        assert db.query(TimelineEvent).count() == 0


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

    assert first.status_code == 201
    assert second.status_code == 200
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
    retry = client.post(
        "/api/v1/captures/upload",
        files={"file": ("broken.pcap", b"\xd4\xc3\xb2\xa1broken", "application/octet-stream")},
    )
    assert retry.status_code == 422
    assert retry.json()["error"]["details"]["capture_id"] == response.json()["error"]["details"]["capture_id"]


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
    escalated = client.patch(f"/api/v1/investigations/{case['id']}", json={"status": "escalated"})
    assert escalated.json()["status"] == "escalated"
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
