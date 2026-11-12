from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import json
import uuid
from typing import Optional

from app.services.pcap.parser import ParsedPacket


@dataclass
class HostTrackerItem:
    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    open_ports: set[int] = field(default_factory=set)
    contacted_remote_ports: set[int] = field(default_factory=set)
    role: Optional[str] = None
    risk_score: int = 0
    is_internal: bool = False

    def to_open_ports_json(self) -> str:
        return json.dumps(sorted(list(self.open_ports)))


class HostTracker:
    """Discovers and profiles network endpoints from traffic."""

    def __init__(self):
        self.hosts: dict[str, HostTrackerItem] = {}

    def get_or_create_host(self, ip: str, timestamp: datetime, mac: Optional[str] = None) -> HostTrackerItem:
        host = self.hosts.get(ip)
        if host is None:
            is_internal = False
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_internal = ip_obj.is_private
            except ValueError:
                pass

            host = HostTrackerItem(
                id=str(uuid.uuid4()),
                ip_address=ip,
                mac_address=mac,
                first_seen_at=timestamp,
                last_seen_at=timestamp,
                is_internal=is_internal,
            )
            self.hosts[ip] = host
        else:
            host.last_seen_at = timestamp
            if mac and not host.mac_address:
                host.mac_address = mac

        return host

    def process_packet(self, packet: ParsedPacket) -> None:
        if not packet.src_ip or not packet.dst_ip:
            return

        # Source host
        src_host = self.get_or_create_host(packet.src_ip, packet.timestamp, packet.src_mac)
        src_host.packet_count += 1
        src_host.bytes_sent += packet.raw_length
        if packet.dst_port:
            src_host.contacted_remote_ports.add(packet.dst_port)

        # Destination host
        dst_host = self.get_or_create_host(packet.dst_ip, packet.timestamp, packet.dst_mac)
        dst_host.packet_count += 1
        dst_host.bytes_received += packet.raw_length
        if packet.dst_port:
            dst_host.open_ports.add(packet.dst_port)

    def associate_hostname(self, ip: str, hostname: str) -> None:
        if not ip or not hostname:
            return
        host = self.hosts.get(ip)
        if host and not host.hostname:
            host.hostname = hostname

    def finalize_profiles(self) -> None:
        """Determines roles and risk scores after all packets have been parsed."""
        for host in self.hosts.values():
            ports = host.open_ports
            role = "Generic Host"
            risk = 0

            # Internal vs External
            if host.is_internal:
                if 53 in ports:
                    role = "Internal DNS Server"
                    risk = 5
                elif 445 in ports or 139 in ports or 88 in ports:
                    role = "Domain Controller / File Server"
                    risk = 10
                elif 80 in ports or 443 in ports or 8080 in ports:
                    role = "Internal Web Server"
                    risk = 10
                elif host.ip_address.endswith(".1") or host.ip_address.endswith(".254"):
                    role = "Default Gateway"
                    risk = 5
                else:
                    role = "Internal Workstation"
                    risk = 10
            else:
                if 53 in ports:
                    role = "Public DNS Resolver"
                    risk = 5
                elif 443 in ports:
                    role = "External Cloud Node (TLS)"
                    risk = 5
                elif 80 in ports:
                    role = "External Web Server"
                    risk = 10
                else:
                    role = "External Host"
                    risk = 15

            # Suspicious port or activity risk bumps
            suspicious_ports = {4444, 1337, 31337, 6667, 8080, 9001}
            matched_sus = suspicious_ports.intersection(host.contacted_remote_ports | host.open_ports)
            if matched_sus:
                risk += 35
                if not host.is_internal:
                    role = "External Suspicious Node (C2 Relay)"
                else:
                    role = "Compromised Asset (Beaconing)"

            host.role = role
            host.risk_score = min(risk, 100)

