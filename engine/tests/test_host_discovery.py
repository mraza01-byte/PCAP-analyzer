from datetime import datetime, timezone
import sqlite3

import pytest
from scapy.all import Ether, IP, IPv6, TCP, wrpcap

import services.host_discovery as host_discovery


@pytest.fixture
def host_database(tmp_path, monkeypatch):
    connection = sqlite3.connect(tmp_path / "test.db")
    connection.execute("""
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
        )
    """)
    connection.commit()
    monkeypatch.setattr(host_discovery, "conn", connection)
    yield connection
    connection.close()


def _packet(timestamp, source="192.0.2.10", destination="198.51.100.20"):
    packet = Ether() / IP(src=source, dst=destination) / TCP(sport=49152, dport=443)
    packet.time = timestamp
    return packet


def test_streams_capture_and_upserts_host_totals_without_overwriting_metadata(
    tmp_path, host_database
):
    capture = tmp_path / "sample.pcap"
    packets = [_packet(1_800_000_001), _packet(1_800_000_000)]
    wrpcap(str(capture), packets)

    first_counts = host_discovery.discover_hosts(capture)
    host_database.execute("UPDATE hosts SET hostname = ? WHERE ip = ?", ("preserved", "192.0.2.10"))
    host_database.commit()
    second_counts = host_discovery.discover_hosts(capture)

    assert first_counts == second_counts == {"192.0.2.10": 2, "198.51.100.20": 2}
    source = host_database.execute(
        "SELECT hostname, packet_count, bytes_sent, first_seen, last_seen FROM hosts WHERE ip = ?",
        ("192.0.2.10",),
    ).fetchone()
    assert source[0] == "preserved"
    assert source[1] == 4
    assert source[2] == sum(len(packet) for packet in packets) * 2
    assert source[3] == datetime.fromtimestamp(1_800_000_000, timezone.utc).isoformat(timespec="microseconds")
    assert source[4] == datetime.fromtimestamp(1_800_000_001, timezone.utc).isoformat(timespec="microseconds")


def test_discovers_ipv6_endpoints(tmp_path, host_database):
    capture = tmp_path / "ipv6.pcap"
    packet = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1234, dport=443)
    packet.time = 1_800_000_000
    wrpcap(str(capture), [packet])

    counts = host_discovery.discover_hosts(capture)

    assert counts == {"2001:db8::1": 1, "2001:db8::2": 1}


def test_commit_false_keeps_host_updates_in_callers_transaction(tmp_path, host_database):
    capture = tmp_path / "sample.pcap"
    wrpcap(str(capture), [_packet(1_800_000_000)])

    host_discovery.discover_hosts(capture, commit=False)
    assert host_database.in_transaction
    assert host_database.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
    host_database.rollback()
    assert host_database.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


def test_malformed_capture_does_not_write_hosts(tmp_path, host_database):
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(b"not a capture")

    with pytest.raises(Exception):
        host_discovery.discover_hosts(capture)

    assert host_database.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0
