from scapy.all import rdpcap
from scapy.layers.inet import IP

from database import conn


def discover_hosts(filepath: str):
    packets = rdpcap(filepath)

    hosts = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            hosts[src] = hosts.get(src, 0) + 1
            hosts[dst] = hosts.get(dst, 0) + 1

    for ip, count in hosts.items():
        conn.execute(
            """
            INSERT OR REPLACE INTO hosts
            (
                ip,
                hostname,
                mac,
                role,
                packet_count,
                bytes_total,
                bytes_sent,
                bytes_received,
                first_seen,
                last_seen
            )
            VALUES
            (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                datetime('now'),
                datetime('now')
            )
            """,
            (
                ip,
                "Unknown",
                "Unknown",
                "Discovered Host",
                count,
                0,
                0,
                0,
            ),
        )

    conn.commit()

    return hosts