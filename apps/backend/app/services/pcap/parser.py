from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import socket
import struct
from typing import BinaryIO, Iterator, Optional


LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 12
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


@dataclass
class RawPacket:
    timestamp: datetime
    data: bytes
    wire_length: int


@dataclass
class ParsedPacket:
    timestamp: datetime
    raw_length: int
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: dict[str, bool] = field(default_factory=dict)
    payload: bytes = b""


def _format_mac(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes[:6])


class PCAPParser:
    """Reads classic PCAP and PCAPNG files, decoding Ethernet, IP, TCP, and UDP layers."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream

    @classmethod
    def from_file(cls, file_path: str) -> PCAPParser:
        return cls(open(file_path, "rb"))

    def iter_raw_packets(self) -> Iterator[RawPacket]:
        header = self.stream.read(4)
        if len(header) < 4:
            return

        magic = struct.unpack(">I", header)[0]
        self.stream.seek(0)

        # Standard PCAP magics
        if magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            yield from self._iter_pcap_packets()
        elif magic == 0x0A0D0D0A:
            # PCAPNG Section Header Block
            yield from self._iter_pcapng_packets()
        else:
            # Attempt standard PCAP fallback
            yield from self._iter_pcap_packets()

    def _iter_pcap_packets(self) -> Iterator[RawPacket]:
        global_header = self.stream.read(24)
        if len(global_header) < 24:
            return

        magic = struct.unpack(">I", global_header[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = ">"
            is_nano = (magic == 0xA1B23C4D)
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = "<"
            is_nano = (magic == 0x4D3CB2A1)
        else:
            endian = "<"
            is_nano = False

        _, _, _, _, snaplen, network = struct.unpack(f"{endian}HHIIII", global_header[4:24])

        while True:
            pkt_hdr = self.stream.read(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            pkt_data = self.stream.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            micros = ts_sub // 1000 if is_nano else ts_sub
            if micros >= 1_000_000:
                micros = 999_999
            try:
                dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc).replace(microsecond=micros)
            except (ValueError, OverflowError, OSError):
                dt = datetime.now(timezone.utc)

            yield RawPacket(timestamp=dt, data=pkt_data, wire_length=orig_len)

    def _iter_pcapng_packets(self) -> Iterator[RawPacket]:
        endian = "<"
        ts_resol = 1_000_000  # Default microsecond resolution

        while True:
            hdr = self.stream.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack(f"{endian}II", hdr)
            if block_len < 12:
                break

            body_len = block_len - 12
            body = self.stream.read(body_len)
            trailer = self.stream.read(4)

            # Section Header Block (SHB)
            if block_type == 0x0A0D0D0A:
                if len(body) >= 4:
                    bom = struct.unpack("<I", body[:4])[0]
                    if bom == 0x1A2B3C4D:
                        endian = "<"
                    elif bom == 0x4D3C2B1A:
                        endian = ">"

            # Interface Description Block (IDB)
            elif block_type == 0x00000001:
                # Default is microsecond unless options specify otherwise
                ts_resol = 1_000_000

            # Enhanced Packet Block (EPB)
            elif block_type == 0x00000006:
                if len(body) >= 20:
                    _, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[:20])
                    pkt_data = body[20 : 20 + cap_len]
                    raw_ts = (ts_high << 32) | ts_low
                    ts_sec = raw_ts // ts_resol
                    ts_sub = raw_ts % ts_resol
                    micros = int((ts_sub / ts_resol) * 1_000_000)
                    if micros >= 1_000_000:
                        micros = 999_999
                    try:
                        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc).replace(microsecond=micros)
                    except (ValueError, OverflowError, OSError):
                        dt = datetime.now(timezone.utc)
                    yield RawPacket(timestamp=dt, data=pkt_data, wire_length=orig_len)

            # Simple Packet Block (SPB)
            elif block_type == 0x00000003:
                if len(body) >= 4:
                    orig_len = struct.unpack(f"{endian}I", body[:4])[0]
                    pkt_data = body[4 : 4 + (block_len - 16)]
                    dt = datetime.now(timezone.utc)
                    yield RawPacket(timestamp=dt, data=pkt_data, wire_length=orig_len)

    def iter_parsed_packets(self) -> Iterator[ParsedPacket]:
        """Iterates over decoded network packets."""
        for raw in self.iter_raw_packets():
            parsed = self.decode_packet(raw)
            if parsed is not None:
                yield parsed

    @staticmethod
    def decode_packet(raw: RawPacket) -> Optional[ParsedPacket]:
        data = raw.data
        if len(data) < 14:
            return None

        src_mac = None
        dst_mac = None
        ip_payload_offset = 0
        ethertype = 0

        # Try Ethernet frame
        dst_mac = _format_mac(data[0:6])
        src_mac = _format_mac(data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        ip_payload_offset = 14

        # Handle 802.1Q VLAN Tag
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype = struct.unpack("!H", data[16:18])[0]
            ip_payload_offset = 18

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        protocol = "OTHER"
        l4_payload = b""
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        flags: dict[str, bool] = {}

        ip_data = data[ip_payload_offset:]

        if ethertype == 0x0800 or (ethertype not in (0x86DD, 0x0806) and (len(ip_data) > 0 and (ip_data[0] >> 4) == 4)):
            # IPv4
            if len(ip_data) < 20:
                return None
            ihl = (ip_data[0] & 0x0F) * 4
            if len(ip_data) < ihl:
                return None
            proto_num = ip_data[9]
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])
            transport_data = ip_data[ihl:]

            if proto_num == 6:  # TCP
                protocol = "TCP"
                if len(transport_data) >= 20:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    data_offset = (transport_data[12] >> 4) * 4
                    flag_byte = transport_data[13]
                    flags = {
                        "FIN": bool(flag_byte & 0x01),
                        "SYN": bool(flag_byte & 0x02),
                        "RST": bool(flag_byte & 0x04),
                        "PSH": bool(flag_byte & 0x08),
                        "ACK": bool(flag_byte & 0x10),
                        "URG": bool(flag_byte & 0x20),
                    }
                    l4_payload = transport_data[data_offset:]
            elif proto_num == 17:  # UDP
                protocol = "UDP"
                if len(transport_data) >= 8:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    l4_payload = transport_data[8:]
            elif proto_num == 1:  # ICMP
                protocol = "ICMP"
                l4_payload = transport_data
            else:
                protocol = f"IP_{proto_num}"
                l4_payload = transport_data

        elif ethertype == 0x86DD or (len(ip_data) > 0 and (ip_data[0] >> 4) == 6):
            # IPv6
            if len(ip_data) < 40:
                return None
            next_header = ip_data[6]
            try:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
            except (ValueError, OSError):
                return None

            transport_data = ip_data[40:]
            if next_header == 6:  # TCP
                protocol = "TCP"
                if len(transport_data) >= 20:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    data_offset = (transport_data[12] >> 4) * 4
                    flag_byte = transport_data[13]
                    flags = {
                        "FIN": bool(flag_byte & 0x01),
                        "SYN": bool(flag_byte & 0x02),
                        "RST": bool(flag_byte & 0x04),
                        "PSH": bool(flag_byte & 0x08),
                        "ACK": bool(flag_byte & 0x10),
                        "URG": bool(flag_byte & 0x20),
                    }
                    l4_payload = transport_data[data_offset:]
            elif next_header == 17:  # UDP
                protocol = "UDP"
                if len(transport_data) >= 8:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    l4_payload = transport_data[8:]
            elif next_header == 58:  # ICMPv6
                protocol = "ICMPv6"
                l4_payload = transport_data
            else:
                protocol = f"IPV6_{next_header}"
                l4_payload = transport_data
        else:
            return None

        if not src_ip or not dst_ip:
            return None

        return ParsedPacket(
            timestamp=raw.timestamp,
            raw_length=raw.wire_length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=flags,
            payload=l4_payload,
        )

