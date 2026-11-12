from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app


# Helper to create a tiny PCAP file (minimal Ethernet+IP+TCP header, no payload)
def create_dummy_pcap() -> bytes:
    # PCAP global header (24 bytes) for little-endian, microsecond resolution, LINKTYPE_ETHERNET
    global_header = (
        b"\xd4\xc3\xb2\xa1"  # magic number (little-endian)
        b"\x02\x00"  # version major = 2
        b"\x04\x00"  # version minor = 4
        b"\x00\x00\x00\x00"  # thiszone
        b"\x00\x00\x00\x00"  # sigfigs
        b"\xff\xff\x00\x00"  # snaplen (65535)
        b"\x01\x00\x00\x00"  # network = LINKTYPE_ETHERNET (1)
    )
    # One packet record header (16 bytes) + minimal Ethernet+IP+TCP (54 bytes)
    packet_header = (
        b"\x00\x00\x00\x00"  # ts_sec (placeholder)
        b"\x00\x00\x00\x00"  # ts_usec
        b"\x36\x00\x00\x00"  # incl_len = 54
        b"\x36\x00\x00\x00"  # orig_len = 54
    )
    # Ethernet (14) + IP (20) + TCP (20) = 54 bytes, filled with zeros for simplicity
    packet_data = b"\x00" * 54
    return global_header + packet_header + packet_data


def test_ingest_dummy_pcap(client, tmp_path):
    # Write dummy pcap to a temporary file
    pcap_path = tmp_path / "dummy.pcap"
    pcap_path.write_bytes(create_dummy_pcap())

    # Upload the file via the API
    with open(pcap_path, "rb") as f:
        response = client.post(
            "/api/v1/captures/upload",
            files={"file": ("dummy.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert response.status_code in (200, 201), f"Upload failed: {response.text}"
    capture = response.json()
    capture_id = capture["id"]

    # Verify that the capture appears in the list
    list_resp = client.get("/api/v1/captures/")
    assert list_resp.status_code == 200
    assert any(c["id"] == capture_id for c in list_resp.json())

    # Check that hosts, flows, and protocol tables have been populated
    host_resp = client.get(f"/api/v1/hosts?capture_id={capture_id}")
    assert host_resp.status_code == 200
    # At least one host (the src/dst of the dummy packet)
    assert len(host_resp.json()) >= 1

    flow_resp = client.get(f"/api/v1/flows?capture_id={capture_id}")
    assert flow_resp.status_code == 200
    assert len(flow_resp.json()) >= 1

    # DNS, HTTP, TLS, and certificates should be empty for this minimal packet
    for endpoint in ["dns", "http", "tls", "certificates"]:
        resp = client.get(f"/api/v1/{endpoint}?capture_id={capture_id}")
        assert resp.status_code == 200
        assert resp.json() == []


def test_ingest_pcap_with_dns_and_tls_extracts_protocols(client):
    pcap_path = Path(__file__).resolve().parents[3] / "engine" / "evidence" / "eg.pcapng"
    if not pcap_path.exists():
        pcap_path = Path("engine/evidence/eg.pcapng").resolve()
    assert pcap_path.exists(), f"Sample pcap missing at {pcap_path}"

    with open(pcap_path, "rb") as f:
        response = client.post(
            "/api/v1/captures/upload",
            files={"file": ("eg.pcapng", f, "application/vnd.tcpdump.pcap")},
        )
    assert response.status_code in (200, 201), f"Upload failed: {response.text}"
    capture = response.json()
    capture_id = capture["id"]

    # Verify DNS extraction
    dns_resp = client.get(f"/api/v1/dns?capture_id={capture_id}")
    assert dns_resp.status_code == 200
    dns_records = dns_resp.json()
    assert len(dns_records) == 6
    query_names = {r["query_name"] for r in dns_records}
    assert any("githubcopilot.com" in name for name in query_names)
    assert any("exp-tas.com" in name for name in query_names)

    # Verify all DNS records have valid timestamps and types
    for record in dns_records:
        assert record["capture_id"] == capture_id
        assert record["query_type"] in ("A", "AAAA", "PTR", "CNAME")
        assert record["timestamp"] is not None

    # Verify TLS extraction
    tls_resp = client.get(f"/api/v1/tls?capture_id={capture_id}")
    assert tls_resp.status_code == 200
    tls_records = tls_resp.json()
    assert len(tls_records) == 5

    # Verify Network Map top domains
    net_resp = client.get(f"/api/v1/captures/{capture_id}/network")
    assert net_resp.status_code == 200
    net_map = net_resp.json()
    assert len(net_map["top_domains"]) > 0
    assert any("githubcopilot.com" in d for d in net_map["top_domains"])

    # Verify Hostnames populated on Hosts
    hosts_resp = client.get(f"/api/v1/hosts?capture_id={capture_id}")
    assert hosts_resp.status_code == 200
    hosts = hosts_resp.json()["hosts"]
    named_hosts = [h for h in hosts if h.get("hostname")]
    assert len(named_hosts) > 0
    assert any("githubcopilot.com" in h["hostname"] or "exp-tas.com" in h["hostname"] for h in named_hosts)
