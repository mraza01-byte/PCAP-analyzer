from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import uuid
from typing import Optional

from app.services.pcap.parser import ParsedPacket


def format_hex_preview(data: bytes, max_len: int = 64) -> str:
    """Formats bytes into a readable hex and ASCII preview."""
    if not data:
        return ""
    chunk = data[:max_len]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
    return f"{hex_part}  |{ascii_part}|"


@dataclass
class FlowTrackerItem:
    id: str
    canonical_key: tuple
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    application: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    packet_count: int = 0
    byte_count: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    seen_flags: set[str] = field(default_factory=set)
    summary: Optional[str] = None
    payload_preview: Optional[str] = None

    @property
    def tcp_flags_str(self) -> str:
        if not self.seen_flags:
            return "-"
        order = ["SYN", "ACK", "PSH", "FIN", "RST", "URG"]
        present = [f for f in order if f in self.seen_flags]
        return "/".join(present) if present else "-"


class FlowTracker:
    """Tracks and correlates packets into bidirectional conversation flows."""

    def __init__(self):
        self.flows: dict[tuple, FlowTrackerItem] = {}

    def get_flow(self, canonical_key: tuple) -> Optional[FlowTrackerItem]:
        return self.flows.get(canonical_key)

    def process_packet(
        self,
        packet: ParsedPacket,
        detected_app: Optional[str] = None,
        summary_hint: Optional[str] = None,
    ) -> FlowTrackerItem:
        src_endpoint = (packet.src_ip or "", packet.src_port or 0)
        dst_endpoint = (packet.dst_ip or "", packet.dst_port or 0)

        # Canonical key independent of direction
        canonical_key = tuple(sorted([src_endpoint, dst_endpoint])) + (packet.protocol,)

        flow = self.flows.get(canonical_key)
        is_forward = True

        if flow is None:
            flow_id = str(uuid.uuid4())
            flow = FlowTrackerItem(
                id=flow_id,
                canonical_key=canonical_key,
                src_ip=packet.src_ip or "",
                dst_ip=packet.dst_ip or "",
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            )
            self.flows[canonical_key] = flow
            is_forward = True
        else:
            flow.end_time = packet.timestamp
            is_forward = (packet.src_ip == flow.src_ip and packet.src_port == flow.src_port)

        flow.packet_count += 1
        flow.byte_count += packet.raw_length

        if is_forward:
            flow.bytes_forward += packet.raw_length
        else:
            flow.bytes_reverse += packet.raw_length

        # Update TCP flags
        for flag_name, is_set in packet.tcp_flags.items():
            if is_set:
                flow.seen_flags.add(flag_name)

        # Application classification
        if detected_app:
            flow.application = detected_app
        elif not flow.application:
            # Common port heuristics
            ports = {packet.src_port, packet.dst_port}
            if 53 in ports:
                flow.application = "DNS"
            elif 80 in ports or 8080 in ports:
                flow.application = "HTTP"
            elif 443 in ports or 8443 in ports:
                flow.application = "TLS"
            elif 445 in ports or 139 in ports:
                flow.application = "SMB"
            elif 22 in ports:
                flow.application = "SSH"

        if summary_hint and not flow.summary:
            flow.summary = summary_hint

        # Capture first payload preview if available
        if packet.payload and not flow.payload_preview:
            flow.payload_preview = format_hex_preview(packet.payload)

        return flow

