from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, IP, IPv6, TCP, UDP, PcapReader


class CaptureAnalysisError(ValueError):
    pass


def detect_capture_format(path: str | Path) -> str:
    with open(path, "rb") as capture:
        magic = capture.read(4)
    if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return "pcap"
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    raise CaptureAnalysisError("File header is not a PCAP or PCAPNG capture")


def analyze_capture(path: str | Path) -> dict:
    """Stream a capture and return normalized hosts, flows, and packet-time events."""
    file_format = detect_capture_format(path)
    hosts: dict[str, dict] = {}
    flows: dict[tuple, dict] = {}
    packet_count = 0

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packet_count += 1
                if packet.haslayer(IP):
                    network = packet[IP]
                    source, destination = network.src, network.dst
                    protocol_number = int(network.proto)
                elif packet.haslayer(IPv6):
                    network = packet[IPv6]
                    source, destination = network.src, network.dst
                    protocol_number = int(network.nh)
                else:
                    continue

                timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc)
                source_mac = packet[Ether].src if packet.haslayer(Ether) else None
                destination_mac = packet[Ether].dst if packet.haslayer(Ether) else None
                transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
                protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else {
                    1: "ICMP", 58: "ICMPv6", 47: "GRE", 50: "ESP", 51: "AH",
                }.get(protocol_number, f"IP-{protocol_number}")
                source_port = int(transport.sport) if transport else None
                destination_port = int(transport.dport) if transport else None
                packet_bytes = len(packet)

                for address, mac in ((source, source_mac), (destination, destination_mac)):
                    host = hosts.setdefault(address, {
                        "ip_address": address,
                        "mac_address": mac,
                        "first_seen_at": timestamp,
                        "last_seen_at": timestamp,
                        "packet_count": 0,
                        "bytes_sent": 0,
                        "bytes_received": 0,
                        "open_ports": set(),
                    })
                    host["first_seen_at"] = min(host["first_seen_at"], timestamp)
                    host["last_seen_at"] = max(host["last_seen_at"], timestamp)
                    if not host["mac_address"]:
                        host["mac_address"] = mac
                hosts[source]["packet_count"] += 1
                hosts[source]["bytes_sent"] += packet_bytes
                hosts[destination]["packet_count"] += 1
                hosts[destination]["bytes_received"] += packet_bytes
                if destination_port is not None:
                    hosts[destination]["open_ports"].add(destination_port)

                source_endpoint = (source, source_port)
                destination_endpoint = (destination, destination_port)
                endpoints = tuple(sorted((source_endpoint, destination_endpoint)))
                flow_key = (protocol, *endpoints)
                flow = flows.get(flow_key)
                if flow is None:
                    flow = flows[flow_key] = {
                        "src_ip": source,
                        "src_port": source_port,
                        "dst_ip": destination,
                        "dst_port": destination_port,
                        "protocol": protocol,
                        "application": _application(protocol, source_port, destination_port),
                        "packet_count": 0,
                        "bytes_total": 0,
                        "bytes_forward": 0,
                        "bytes_reverse": 0,
                        "start_time": timestamp,
                        "end_time": timestamp,
                        "tcp_flags": set(),
                    }
                flow["packet_count"] += 1
                flow["bytes_total"] += packet_bytes
                flow["end_time"] = max(flow["end_time"], timestamp)
                if source == flow["src_ip"] and source_port == flow["src_port"]:
                    flow["bytes_forward"] += packet_bytes
                else:
                    flow["bytes_reverse"] += packet_bytes
                if packet.haslayer(TCP):
                    flow["tcp_flags"].update(_tcp_flag_names(int(packet[TCP].flags)))
    except CaptureAnalysisError:
        raise
    except Exception as error:
        raise CaptureAnalysisError(f"Unable to parse capture: {error}") from error

    normalized_flows = []
    timeline = []
    for flow in flows.values():
        flag_order = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
        flow["tcp_flags"] = "/".join(flag for flag in flag_order if flag in flow["tcp_flags"]) or "-"
        flow["flow_key"] = (
            f"{flow['src_ip']}:{flow['src_port'] or '-'}<->"
            f"{flow['dst_ip']}:{flow['dst_port'] or '-'}/{flow['protocol']}"
        )
        flow["summary"] = f"{flow['protocol']} flow, {flow['packet_count']} packets, {flow['bytes_total']} bytes"
        normalized_flows.append(flow)
        timeline.append({
            "event_time": flow["start_time"],
            "event_type": f"{flow['protocol'].lower()}_flow_started",
            "title": f"{flow['protocol']} flow started",
            "description": f"{flow['src_ip']}:{flow['src_port'] or '-'} to {flow['dst_ip']}:{flow['dst_port'] or '-'}",
            "flow_key": flow["flow_key"],
        })
        if flow["end_time"] != flow["start_time"]:
            timeline.append({
                "event_time": flow["end_time"],
                "event_type": f"{flow['protocol'].lower()}_flow_last_seen",
                "title": f"{flow['protocol']} flow last seen",
                "description": f"{flow['packet_count']} packets observed; {flow['bytes_total']} bytes",
                "flow_key": flow["flow_key"],
            })

    for host in hosts.values():
        host["open_ports"] = sorted(host["open_ports"])

    return {
        "file_format": file_format,
        "packet_count": packet_count,
        "first_packet_at": min((host["first_seen_at"] for host in hosts.values()), default=None),
        "last_packet_at": max((host["last_seen_at"] for host in hosts.values()), default=None),
        "hosts": list(hosts.values()),
        "flows": normalized_flows,
        "timeline_events": timeline,
    }


def _application(protocol: str, *ports: int | None) -> str:
    if protocol not in {"TCP", "UDP"}:
        return protocol
    services = {53: "DNS", 80: "HTTP", 443: "TLS", 445: "SMB", 123: "NTP"}
    return next((services[port] for port in ports if port in services), protocol)


def _tcp_flag_names(flags: int) -> list[str]:
    names = ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG"), (64, "ECE"), (128, "CWR"))
    return [name for mask, name in names if flags & mask]