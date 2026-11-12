from __future__ import annotations

from dataclasses import dataclass, field
import socket
import struct
from typing import Optional


QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class DnsAnswer:
    name: str
    type: str
    ttl: int
    data: str


@dataclass
class DnsParsed:
    transaction_id: int
    is_response: bool
    response_code: str
    query_name: str
    query_type: str
    answers: list[DnsAnswer] = field(default_factory=list)


def _decode_name(payload: bytes, offset: int, max_jumps: int = 10) -> tuple[str, int]:
    """Decodes a domain name from DNS payload, resolving compression pointers."""
    labels: list[str] = []
    original_offset = offset
    stepped_past_pointer = False
    jumps = 0

    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            if not stepped_past_pointer:
                original_offset = offset + 1
            break

        # Compression pointer check (top 2 bits set: 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer_offset = ((length & 0x3F) << 8) | payload[offset + 1]
            if not stepped_past_pointer:
                original_offset = offset + 2
                stepped_past_pointer = True

            jumps += 1
            if jumps > max_jumps or pointer_offset >= len(payload):
                break
            offset = pointer_offset
            continue

        offset += 1
        label = payload[offset : offset + length]
        labels.append(label.decode("utf-8", errors="replace"))
        offset += length
        if not stepped_past_pointer:
            original_offset = offset

    domain = ".".join(labels)
    return domain, original_offset


def parse_dns_payload(payload: bytes) -> Optional[DnsParsed]:
    """Parses a DNS request or response packet."""
    if len(payload) < 12:
        return None

    try:
        tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
        is_response = bool(flags & 0x8000)
        rcode_num = flags & 0x000F
        rcode = RCODE_MAP.get(rcode_num, f"RCODE_{rcode_num}")

        offset = 12
        primary_query_name = ""
        primary_query_type = "UNKNOWN"

        # Decode Question section
        for i in range(qdcount):
            if offset >= len(payload):
                break
            qname, offset = _decode_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype_num, _ = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4
            qtype = QTYPE_MAP.get(qtype_num, f"TYPE_{qtype_num}")
            if i == 0:
                primary_query_name = qname
                primary_query_type = qtype

        answers: list[DnsAnswer] = []

        # Decode Answer section if present
        if is_response and ancount > 0:
            for _ in range(ancount):
                if offset >= len(payload):
                    break
                aname, offset = _decode_name(payload, offset)
                if offset + 10 > len(payload):
                    break
                atype_num, aclass, attl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
                offset += 10
                atype = QTYPE_MAP.get(atype_num, f"TYPE_{atype_num}")

                if offset + rdlength > len(payload):
                    break
                rdata = payload[offset : offset + rdlength]

                answer_str = ""
                if atype == "A" and rdlength == 4:
                    answer_str = socket.inet_ntoa(rdata)
                elif atype == "AAAA" and rdlength == 16:
                    answer_str = socket.inet_ntop(socket.AF_INET6, rdata)
                elif atype in ("CNAME", "PTR", "NS"):
                    answer_str, _ = _decode_name(payload, offset)
                elif atype == "TXT" and rdlength > 1:
                    txt_len = rdata[0]
                    answer_str = rdata[1 : 1 + txt_len].decode("utf-8", errors="replace")
                else:
                    answer_str = rdata.hex()

                answers.append(DnsAnswer(name=aname, type=atype, ttl=attl, data=answer_str))
                offset += rdlength

        if not primary_query_name and not answers:
            return None

        return DnsParsed(
            transaction_id=tx_id,
            is_response=is_response,
            response_code=rcode,
            query_name=primary_query_name or (answers[0].name if answers else ""),
            query_type=primary_query_type or (answers[0].type if answers else "A"),
            answers=answers,
        )

    except Exception:
        return None

