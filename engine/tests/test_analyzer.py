from datetime import datetime, timezone

import pytest
from scapy.all import Ether, IP, TCP, PcapNgWriter, wrpcap

from engine.services.analyzer import CaptureAnalysisCancelled, analyze_capture


def _packet(timestamp):
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=49152, dport=443, flags="SA")
    packet.time = timestamp
    return packet


def test_streams_pcap_into_hosts_flows_and_packet_time_events(tmp_path):
    capture = tmp_path / "sample.pcap"
    wrpcap(str(capture), [_packet(1_800_000_000), _packet(1_800_000_001)])

    result = analyze_capture(capture)

    assert result["file_format"] == "pcap"
    assert result["packet_count"] == 2
    assert {host["ip_address"] for host in result["hosts"]} == {"192.0.2.10", "198.51.100.20"}
    flow = result["flows"][0]
    assert (flow["src_ip"], flow["dst_ip"], flow["protocol"]) == ("192.0.2.10", "198.51.100.20", "TCP")
    assert flow["packet_count"] == 2 and flow["bytes_forward"] == flow["bytes_total"]
    assert flow["tcp_flags"] == "SYN/ACK"
    assert result["timeline_events"][0]["event_time"] == datetime.fromtimestamp(1_800_000_000, timezone.utc)


def test_reads_pcapng_without_loading_file_as_a_blob(tmp_path):
    capture = tmp_path / "sample.pcapng"
    writer = PcapNgWriter(str(capture))
    writer.write(_packet(1_800_000_000))
    writer.close()

    result = analyze_capture(capture)

    assert result["file_format"] == "pcapng"
    assert result["packet_count"] == 1
    assert len(result["flows"]) == 1


def test_stops_streaming_when_processing_ownership_is_lost(tmp_path):
    capture = tmp_path / "cancelled.pcap"
    wrpcap(str(capture), [_packet(1_800_000_000 + index) for index in range(10)])
    checks = 0

    def ownership_lost():
        nonlocal checks
        checks += 1
        return checks >= 3

    with pytest.raises(CaptureAnalysisCancelled):
        analyze_capture(capture, ownership_lost)

    assert checks == 3