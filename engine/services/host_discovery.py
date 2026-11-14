from datetime import datetime, timezone
from pathlib import Path

from scapy.all import PcapReader
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from database import conn


def discover_hosts(filepath: str | Path, *, commit: bool = True) -> dict[str, int]:
    """Stream a capture and upsert endpoint counters without loading all packets.

    Counts are accumulated across captures while preserving existing host metadata.
    Set ``commit=False`` when the caller needs to include these changes in a larger
    SQLite transaction.
    """
    hosts: dict[str, dict] = {}

    with PcapReader(str(filepath)) as packets:
        for packet in packets:
            if packet.haslayer(IP):
                network = packet[IP]
            elif packet.haslayer(IPv6):
                network = packet[IPv6]
            else:
                continue

            source = network.src
            destination = network.dst
            packet_bytes = len(packet)
            timestamp = datetime.fromtimestamp(
                float(packet.time), timezone.utc
            ).isoformat(timespec="microseconds")

            for address in (source, destination):
                host = hosts.setdefault(address, {
                    "packet_count": 0,
                    "bytes_total": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                })
                host["packet_count"] += 1
                host["bytes_total"] += packet_bytes
                host["first_seen"] = min(host["first_seen"], timestamp)
                host["last_seen"] = max(host["last_seen"], timestamp)

            hosts[source]["bytes_sent"] += packet_bytes
            hosts[destination]["bytes_received"] += packet_bytes

    try:
        for ip, data in hosts.items():
            conn.execute(
                """
                INSERT INTO hosts (
                    ip, hostname, mac, role, packet_count, bytes_total,
                    bytes_sent, bytes_received, first_seen, last_seen
                )
                VALUES (?, 'Unknown', 'Unknown', 'Discovered Host', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    packet_count = hosts.packet_count + excluded.packet_count,
                    bytes_total = hosts.bytes_total + excluded.bytes_total,
                    bytes_sent = hosts.bytes_sent + excluded.bytes_sent,
                    bytes_received = hosts.bytes_received + excluded.bytes_received,
                    first_seen = CASE
                        WHEN hosts.first_seen IS NULL OR excluded.first_seen < hosts.first_seen
                        THEN excluded.first_seen ELSE hosts.first_seen END,
                    last_seen = CASE
                        WHEN hosts.last_seen IS NULL OR excluded.last_seen > hosts.last_seen
                        THEN excluded.last_seen ELSE hosts.last_seen END
                """,
                (
                    ip,
                    data["packet_count"],
                    data["bytes_total"],
                    data["bytes_sent"],
                    data["bytes_received"],
                    data["first_seen"],
                    data["last_seen"],
                ),
            )
        if commit:
            conn.commit()
    except Exception:
        if commit:
            conn.rollback()
        raise

    return {ip: data["packet_count"] for ip, data in hosts.items()}
