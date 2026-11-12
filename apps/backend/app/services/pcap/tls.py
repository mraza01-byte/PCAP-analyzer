from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Optional


TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

POPULAR_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}


@dataclass
class TlsHandshakeParsed:
    version: str
    sni: Optional[str] = None
    cipher_suite: Optional[str] = None
    alpn: Optional[str] = None
    is_client_hello: bool = False
    is_server_hello: bool = False
    raw_certificates: list[bytes] = field(default_factory=list)


def parse_tls_payload(payload: bytes) -> list[TlsHandshakeParsed]:
    """Inspects a TCP payload for TLS Record layer and Handshake messages."""
    results: list[TlsHandshakeParsed] = []
    if len(payload) < 5:
        return results

    offset = 0
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        # Only parse Handshake records (0x16)
        if content_type != 0x16:
            break

        rec_version = struct.unpack("!H", payload[offset + 1 : offset + 3])[0]
        rec_len = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
        offset += 5

        if offset + rec_len > len(payload):
            # Partial or fragmented record; inspect available payload
            record_bytes = payload[offset:]
        else:
            record_bytes = payload[offset : offset + rec_len]
        offset += rec_len

        # Parse handshake messages inside the record
        hs_offset = 0
        while hs_offset + 4 <= len(record_bytes):
            hs_type = record_bytes[hs_offset]
            # Handshake length is 24-bit unsigned int
            hs_len = (record_bytes[hs_offset + 1] << 16) | (record_bytes[hs_offset + 2] << 8) | record_bytes[hs_offset + 3]
            hs_data = record_bytes[hs_offset + 4 : hs_offset + 4 + hs_len]
            hs_offset += 4 + hs_len

            # Client Hello (0x01)
            if hs_type == 0x01 and len(hs_data) >= 34:
                client_ver = struct.unpack("!H", hs_data[:2])[0]
                version_str = TLS_VERSIONS.get(client_ver, f"TLS (0x{client_ver:04x})")

                # Skip Random (32 bytes)
                p = 2 + 32

                # Session ID
                if p < len(hs_data):
                    sess_len = hs_data[p]
                    p += 1 + sess_len

                # Cipher Suites
                selected_cipher = None
                if p + 2 <= len(hs_data):
                    cs_len = struct.unpack("!H", hs_data[p : p + 2])[0]
                    p += 2
                    if p + 2 <= len(hs_data):
                        first_cs = struct.unpack("!H", hs_data[p : p + 2])[0]
                        selected_cipher = POPULAR_CIPHER_SUITES.get(first_cs, f"0x{first_cs:04x}")
                    p += cs_len

                # Compression Methods
                if p < len(hs_data):
                    comp_len = hs_data[p]
                    p += 1 + comp_len

                sni: Optional[str] = None
                alpn: Optional[str] = None

                # Extensions
                if p + 2 <= len(hs_data):
                    ext_len = struct.unpack("!H", hs_data[p : p + 2])[0]
                    p += 2
                    ext_end = min(p + ext_len, len(hs_data))

                    while p + 4 <= ext_end:
                        ext_type, ext_data_len = struct.unpack("!HH", hs_data[p : p + 4])
                        ext_data = hs_data[p + 4 : p + 4 + ext_data_len]
                        p += 4 + ext_data_len

                        # SNI extension: 0x0000
                        if ext_type == 0x0000 and len(ext_data) >= 5:
                            # Server Name List
                            name_type = ext_data[2]
                            if name_type == 0:  # host_name
                                name_len = struct.unpack("!H", ext_data[3:5])[0]
                                if 5 + name_len <= len(ext_data):
                                    sni = ext_data[5 : 5 + name_len].decode("utf-8", errors="replace")

                        # ALPN extension: 0x0010
                        elif ext_type == 0x0010 and len(ext_data) >= 3:
                            alpn_len = ext_data[2]
                            if 3 + alpn_len <= len(ext_data):
                                alpn = ext_data[3 : 3 + alpn_len].decode("utf-8", errors="replace")

                        # Supported Versions extension: 0x002B
                        elif ext_type == 0x002B and len(ext_data) >= 3:
                            sup_versions = []
                            sup_len = ext_data[0]
                            for sv_idx in range(1, min(1 + sup_len, len(ext_data)), 2):
                                if sv_idx + 1 < len(ext_data):
                                    sv = struct.unpack("!H", ext_data[sv_idx : sv_idx + 2])[0]
                                    sup_versions.append(sv)
                            if 0x0304 in sup_versions:
                                version_str = "TLS 1.3"

                results.append(
                    TlsHandshakeParsed(
                        version=version_str,
                        sni=sni,
                        cipher_suite=selected_cipher,
                        alpn=alpn,
                        is_client_hello=True,
                    )
                )

            # Server Hello (0x02)
            elif hs_type == 0x02 and len(hs_data) >= 34:
                server_ver = struct.unpack("!H", hs_data[:2])[0]
                version_str = TLS_VERSIONS.get(server_ver, f"TLS (0x{server_ver:04x})")

                # Skip Random (32 bytes)
                p = 2 + 32
                if p < len(hs_data):
                    sess_len = hs_data[p]
                    p += 1 + sess_len

                selected_cipher = None
                if p + 2 <= len(hs_data):
                    cs_val = struct.unpack("!H", hs_data[p : p + 2])[0]
                    selected_cipher = POPULAR_CIPHER_SUITES.get(cs_val, f"0x{cs_val:04x}")
                    p += 2

                # Compression (1 byte)
                if p < len(hs_data):
                    p += 1

                # Check extensions for TLS 1.3 negotiated version (0x002B)
                alpn = None
                if p + 2 <= len(hs_data):
                    ext_len = struct.unpack("!H", hs_data[p : p + 2])[0]
                    p += 2
                    ext_end = min(p + ext_len, len(hs_data))
                    while p + 4 <= ext_end:
                        ext_type, ext_data_len = struct.unpack("!HH", hs_data[p : p + 4])
                        ext_data = hs_data[p + 4 : p + 4 + ext_data_len]
                        p += 4 + ext_data_len
                        if ext_type == 0x002B and len(ext_data) >= 2:
                            neg_ver = struct.unpack("!H", ext_data[:2])[0]
                            if neg_ver == 0x0304:
                                version_str = "TLS 1.3"
                            elif neg_ver in TLS_VERSIONS:
                                version_str = TLS_VERSIONS[neg_ver]
                        elif ext_type == 0x0010 and len(ext_data) >= 3:
                            alpn_len = ext_data[2]
                            alpn = ext_data[3 : 3 + alpn_len].decode("utf-8", errors="replace")

                results.append(
                    TlsHandshakeParsed(
                        version=version_str,
                        cipher_suite=selected_cipher,
                        alpn=alpn,
                        is_server_hello=True,
                    )
                )

            # Certificate (0x0B)
            elif hs_type == 0x0B and len(hs_data) >= 3:
                certs_len = (hs_data[0] << 16) | (hs_data[1] << 8) | hs_data[2]
                cp = 3
                raw_certs: list[bytes] = []
                while cp + 3 <= len(hs_data) and cp < 3 + certs_len:
                    cert_item_len = (hs_data[cp] << 16) | (hs_data[cp + 1] << 8) | hs_data[cp + 2]
                    cp += 3
                    if cp + cert_item_len <= len(hs_data):
                        raw_certs.append(hs_data[cp : cp + cert_item_len])
                    cp += cert_item_len

                if raw_certs:
                    results.append(
                        TlsHandshakeParsed(
                            version="TLS Certificate",
                            raw_certificates=raw_certs,
                        )
                    )

    return results

