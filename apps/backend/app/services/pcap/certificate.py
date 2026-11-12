from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class CertificateParsed:
    fingerprint_sha256: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    serial_number: Optional[str] = None
    san_list: list[str] = field(default_factory=list)
    is_self_signed: bool = False


def _get_name_attr(name: x509.Name, oid) -> Optional[str]:
    attrs = name.get_attributes_for_oid(oid)
    if attrs:
        return attrs[0].value
    return None


def _format_serial(serial_int: int) -> str:
    hex_str = f"{serial_int:x}"
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2)).upper()


def parse_x509_certificate(der_bytes: bytes) -> Optional[CertificateParsed]:
    """Parses a raw DER-encoded X.509 certificate."""
    if not der_bytes:
        return None

    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return None

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().lower()
        subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
        subject_org = _get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
        issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
        issuer_org = _get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

        # Dates (support both newer not_valid_before_utc and legacy not_valid_before)
        if hasattr(cert, "not_valid_before_utc"):
            valid_from = cert.not_valid_before_utc
        else:
            valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)

        if hasattr(cert, "not_valid_after_utc"):
            valid_to = cert.not_valid_after_utc
        else:
            valid_to = cert.not_valid_after.replace(tzinfo=timezone.utc)

        serial_str = _format_serial(cert.serial_number)

        # Subject Alternative Names (SANs)
        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_list.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        is_self_signed = cert.issuer == cert.subject

        return CertificateParsed(
            fingerprint_sha256=fingerprint,
            subject_cn=subject_cn,
            subject_org=subject_org,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            valid_from=valid_from,
            valid_to=valid_to,
            serial_number=serial_str,
            san_list=san_list,
            is_self_signed=is_self_signed,
        )

    except Exception:
        return None

