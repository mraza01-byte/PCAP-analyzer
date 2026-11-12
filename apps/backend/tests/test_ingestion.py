import io
import os
import json
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

