"""Person 4 tests: honest timeline data, correlation, and investigation evidence linking."""
from datetime import datetime, timedelta, timezone

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from app.database.session import get_session_factory
from app.models import Capture, CaptureFormat, Flow, Host, Investigation, TimelineEvent

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _seed():
    """A small, realistic set of rows: one capture, three hosts, two flows, five events."""
    with get_session_factory()() as db:
        capture = Capture(original_filename="seed.pcap", file_path="x", file_size_bytes=1, sha256="a" * 64,
                          file_format=CaptureFormat.PCAP)
        db.add(capture)
        db.flush()
        a, b, c = (Host(capture_id=capture.id, ip_address=ip) for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"))
        db.add_all([a, b, c])
        db.flush()
        tcp = Flow(capture_id=capture.id, src_host_id=a.id, dst_host_id=b.id, src_port=50000, dst_port=443, protocol="TCP")
        udp = Flow(capture_id=capture.id, src_host_id=c.id, dst_host_id=c.id, src_port=5353, dst_port=53, protocol="UDP")
        db.add_all([tcp, udp])
        db.flush()

        def event(offset, flow, etype, severity, category, protocol, title):
            return TimelineEvent(capture_id=capture.id, flow_id=flow.id if flow else None,
                                 event_time=T0 + timedelta(seconds=offset), event_type=etype, title=title,
                                 description=title, severity=severity, category=category, protocol=protocol,
                                 src="10.0.0.1:50000", dst="10.0.0.2:443")

        events = [
            event(0, tcp, "TLS_HANDSHAKE", "info", "Encryption", "TLS", "TLS handshake"),
            event(5, tcp, "TLS_CERTIFICATE", "warning", "Certificate", "TLS", "Self-signed certificate"),
            event(30, tcp, "HTTP_REQUEST", "critical", "C2 Traffic", "HTTP", "HTTP GET /beacon"),
            event(10, udp, "DNS_QUERY", "info", "Resolution", "DNS", "DNS A example.test"),
            event(4000, None, "NOTE", "info", "General", None, "Much later, no flow"),
        ]
        db.add_all(events)
        db.commit()
        return {"capture": capture.id, "tcp": tcp.id, "udp": udp.id, "events": [e.id for e in events]}


def test_timeline_returns_the_stored_severity_category_and_endpoints(client):
    _seed()
    events = {e["title"]: e for e in client.get("/api/v1/timeline").json()["events"]}
    assert events["HTTP GET /beacon"]["severity"] == "critical"
    assert events["HTTP GET /beacon"]["category"] == "C2 Traffic"
    assert events["Self-signed certificate"]["severity"] == "warning"
    assert events["TLS handshake"]["protocol"] == "TLS"
    assert events["TLS handshake"]["src"] == "10.0.0.1:50000" and events["TLS handshake"]["dst"] == "10.0.0.2:443"


def test_timeline_filters_use_real_values(client):
    _seed()
    titles = lambda **q: sorted(e["title"] for e in client.get("/api/v1/timeline", params=q).json()["events"])
    assert titles(severity="critical") == ["HTTP GET /beacon"]
    assert titles(severity="WARNING") == ["Self-signed certificate"]
    assert titles(category="certificate") == ["Self-signed certificate"]   # real stored category, any letter case
    assert titles(protocol="dns") == ["DNS A example.test"]
    assert titles(category="TCP") == ["HTTP GET /beacon", "Self-signed certificate", "TLS handshake"]  # old transport buttons still work
    assert titles(category="UDP") == ["DNS A example.test"]
    assert titles(search="beacon") == ["HTTP GET /beacon"]
    assert client.get("/api/v1/timeline", params={"severity": "bogus"}).status_code == 422


def test_timeline_summary_counts_are_real(client):
    _seed()
    summary = client.get("/api/v1/timeline/summary").json()
    assert summary["total"] == 5
    assert summary["by_severity"] == {"critical": 1, "high": 0, "warning": 1, "info": 3}
    assert {c["category"]: c["count"] for c in summary["by_category"]} == {
        "Encryption": 1, "Certificate": 1, "C2 Traffic": 1, "Resolution": 1, "General": 1}


def test_event_detail_and_unknown_event(client):
    ids = _seed()
    assert client.get(f"/api/v1/timeline/{ids['events'][2]}").json()["title"] == "HTTP GET /beacon"
    assert client.get("/api/v1/timeline/does-not-exist").status_code == 404
    assert client.get("/api/v1/timeline/does-not-exist/related").status_code == 404


def test_related_events_are_correlated_by_flow_then_host(client):
    ids = _seed()
    related = client.get(f"/api/v1/timeline/{ids['events'][1]}/related", params={"window_seconds": 60}).json()
    by_title = {r["event"]["title"]: r["relation"] for r in related["related"]}
    assert by_title == {"TLS handshake": "same_flow", "HTTP GET /beacon": "same_flow"}
    # The DNS event belongs to a different flow and different hosts: not related.
    # An event with no flow has nothing to correlate on.
    lone = client.get(f"/api/v1/timeline/{ids['events'][4]}/related").json()
    assert lone["related"] == [] and lone["total"] == 0


def test_related_events_respect_the_time_window(client):
    ids = _seed()
    with get_session_factory()() as db:
        capture = ids["capture"]
        tcp = db.get(Flow, ids["tcp"])
        other = Flow(capture_id=capture, src_host_id=tcp.src_host_id, dst_host_id=tcp.src_host_id, protocol="UDP")
        db.add(other)
        db.flush()
        for name, offset in (("near", 20), ("far", 5000)):
            db.add(TimelineEvent(capture_id=capture, flow_id=other.id, event_time=T0 + timedelta(seconds=offset),
                                 event_type="X", title=name, severity="info", category="General"))
        db.commit()
    related = client.get(f"/api/v1/timeline/{ids['events'][0]}/related", params={"window_seconds": 60}).json()
    relations = {r["event"]["title"]: r["relation"] for r in related["related"]}
    assert relations["near"] == "same_host" and "far" not in relations


def _case(client, **extra):
    return client.post("/api/v1/investigations", json={"title": "Beaconing", "severity": "high", **extra}).json()


def test_link_evidence_and_build_the_case_timeline(client):
    ids = _seed()
    case = _case(client)
    linked = client.post(f"/api/v1/investigations/{case['id']}/evidence", json={
        "flow_ids": [ids["tcp"]], "event_ids": [ids["events"][3]], "capture_ids": [ids["capture"]]})
    assert linked.status_code == 200
    body = linked.json()
    assert (body["capture_count"], body["flow_count"], body["event_count"]) == (1, 1, 1)
    # Linking again changes nothing.
    again = client.post(f"/api/v1/investigations/{case['id']}/evidence", json={"flow_ids": [ids["tcp"]]}).json()
    assert again["flow_count"] == 1

    evidence = client.get(f"/api/v1/investigations/{case['id']}/evidence").json()
    assert [f["id"] for f in evidence["flows"]] == [ids["tcp"]]
    assert [e["title"] for e in evidence["events"]] == ["DNS A example.test"]

    timeline = client.get(f"/api/v1/investigations/{case['id']}/timeline").json()
    assert [e["title"] for e in timeline["events"]] == [
        "TLS handshake", "Self-signed certificate", "DNS A example.test", "HTTP GET /beacon"]  # linked flow + linked event, by time
    everything = client.get(f"/api/v1/investigations/{case['id']}/timeline", params={"include_captures": True}).json()
    assert everything["total"] == 5
    only_case = client.get("/api/v1/timeline", params={"investigation_id": case["id"]}).json()
    assert [e["title"] for e in only_case["events"]] == ["DNS A example.test"]


def test_unlink_evidence(client):
    ids = _seed()
    case = _case(client)
    base = f"/api/v1/investigations/{case['id']}"
    client.post(f"{base}/evidence", json={"flow_ids": [ids["tcp"]], "event_ids": [ids["events"][0]], "capture_ids": [ids["capture"]]})
    assert client.delete(f"{base}/evidence/flows/{ids['tcp']}").status_code == 204
    assert client.delete(f"{base}/evidence/events/{ids['events'][0]}").status_code == 204
    assert client.delete(f"{base}/evidence/captures/{ids['capture']}").status_code == 204
    assert client.get(base).json()["flow_count"] == 0 and client.get(base).json()["event_count"] == 0
    assert client.delete(f"{base}/evidence/flows/{ids['tcp']}").status_code == 404   # not linked any more


def test_evidence_rules(client):
    ids = _seed()
    case, other = _case(client), _case(client, title="Another case")
    base = f"/api/v1/investigations/{case['id']}"
    assert client.post(f"{base}/evidence", json={"flow_ids": ["nope"]}).status_code == 404
    assert client.post("/api/v1/investigations/nope/evidence", json={}).status_code == 404
    client.post(f"{base}/evidence", json={"event_ids": [ids["events"][0]]})
    # one event belongs to one case only
    assert client.post(f"/api/v1/investigations/{other['id']}/evidence", json={"event_ids": [ids["events"][0]]}).status_code == 409
    # closed cases are read-only for evidence
    client.patch(base, json={"status": "closed"})
    assert client.post(f"{base}/evidence", json={"flow_ids": [ids["tcp"]]}).status_code == 409
    client.patch(base, json={"status": "active"})
    assert client.post(f"{base}/evidence", json={"flow_ids": [ids["tcp"]]}).status_code == 200


def test_deleting_a_case_keeps_the_timeline_events(client):
    ids = _seed()
    case = _case(client)
    client.post(f"/api/v1/investigations/{case['id']}/evidence", json={"event_ids": [ids["events"][0]]})
    assert client.delete(f"/api/v1/investigations/{case['id']}").status_code == 204
    event = client.get(f"/api/v1/timeline/{ids['events'][0]}").json()
    assert event["investigation_id"] is None


def test_real_upload_end_to_end(client, tmp_path):
    """Upload a real capture, then confirm the API reports exactly what was stored."""
    packets = [Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=40000, dport=80, flags="S"),
               Ether() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=80, dport=40000, flags="SA")]
    for i, packet in enumerate(packets):
        packet.time = 1_700_000_000 + i
    path = tmp_path / "real.pcap"
    wrpcap(str(path), packets)
    with path.open("rb") as handle:
        upload = client.post("/api/v1/captures/upload", files={"file": ("real.pcap", handle)})
    assert upload.status_code == 201
    api_events = client.get("/api/v1/timeline", params={"limit": 5000}).json()["events"]
    assert api_events, "the upload should have produced timeline events"
    with get_session_factory()() as db:
        stored = {e.id: e for e in db.query(TimelineEvent).all()}
    assert {e["id"] for e in api_events} == set(stored)
    for e in api_events:
        assert (e["severity"], e["category"]) == (stored[e["id"]].severity, stored[e["id"]].category)
    summary = client.get("/api/v1/timeline/summary").json()
    assert summary["total"] == len(stored) == sum(c["count"] for c in summary["by_category"])
