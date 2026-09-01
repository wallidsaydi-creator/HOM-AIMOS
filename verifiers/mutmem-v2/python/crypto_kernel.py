"""Independent MutMem V2 byte and cryptographic kernel.

This module has no HOM-AIMOS import, database, filesystem, network, signer,
route, policy, or mutable configuration authority.

Protocol authorities: MutMem V1 Sections 5-7; RFC 6962 Section 2.1;
RFC 8032; RFC 8785; Boneh/Shoup domain separation; Cryptography
Engineering's Horton principle and unique-parsing requirement.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.serialization import load_der_public_key


MAXIMUM_DEPTH = 32
MAXIMUM_ARRAY_ITEMS = 1_000_000
MAXIMUM_OBJECT_KEYS = 1_000_000
MAXIMUM_CANONICAL_BYTES = 64 * 1024 * 1024
MAXIMUM_SAFE_INTEGER = 9_007_199_254_740_991

HEX32 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
OCCURRENCE_DOMAIN = b"hom.aimos.memory-occurrence/v3\x00"
OCCURRENCE_SIGNATURE_DOMAIN = b"hom.aimos.memory-occurrence-signature/v3\x00"


@dataclass(frozen=True)
class MutMemKernelError(ValueError):
    reason: str

    def __str__(self) -> str:
        return f"mutmem_v2_kernel:{self.reason}"


def fail(reason: str) -> None:
    raise MutMemKernelError(reason)


def _quote_string(value: str) -> str:
    pieces: list[str] = ['"']
    short = {
        0x08: "\\b",
        0x09: "\\t",
        0x0A: "\\n",
        0x0C: "\\f",
        0x0D: "\\r",
        0x22: '\\"',
        0x5C: "\\\\",
    }
    for character in value:
        code = ord(character)
        if code in short:
            pieces.append(short[code])
        elif code <= 0x1F or 0xD800 <= code <= 0xDFFF:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _normalize_exponent(text: str) -> str:
    mantissa, exponent_text = text.lower().split("e", 1)
    exponent = int(exponent_text)
    if mantissa.endswith(".0"):
        mantissa = mantissa[:-2]
    sign = "+" if exponent >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exponent)}" if exponent >= 0 else f"{mantissa}e-{abs(exponent)}"


def _expand_scientific(text: str) -> str:
    mantissa, exponent_text = text.lower().split("e", 1)
    exponent = int(exponent_text)
    negative = mantissa.startswith("-")
    if negative:
        mantissa = mantissa[1:]
    whole, dot, fraction = mantissa.partition(".")
    digits = whole + (fraction if dot else "")
    decimal_index = len(whole) + exponent
    if decimal_index <= 0:
        output = "0." + ("0" * (-decimal_index)) + digits
    elif decimal_index >= len(digits):
        output = digits + ("0" * (decimal_index - len(digits)))
    else:
        output = digits[:decimal_index] + "." + digits[decimal_index:]
    if "." in output:
        output = output.rstrip("0").rstrip(".")
    return ("-" if negative else "") + output


def _serialize_number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > MAXIMUM_SAFE_INTEGER:
            fail("CANONICAL_NUMBER_INVALID")
        return str(value)
    if not math.isfinite(value):
        fail("CANONICAL_NUMBER_INVALID")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) <= MAXIMUM_SAFE_INTEGER:
        return str(int(value))
    text = repr(value).lower()
    absolute = abs(value)
    if 1e-6 <= absolute < 1e21:
        return _expand_scientific(text) if "e" in text else text
    if "e" not in text:
        # Python's shortest-roundtrip form uses exponent notation at these
        # magnitudes, so reaching this branch would signal an unsupported
        # interpreter serialization change.
        fail("CANONICAL_NUMBER_SERIALIZATION_INVALID")
    return _normalize_exponent(text)


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="surrogatepass")


def canonical_json(value: Any, depth: int = 0) -> str:
    if depth > MAXIMUM_DEPTH:
        fail("CANONICAL_DEPTH_INVALID")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, str):
        return _quote_string(value)
    if isinstance(value, list):
        if len(value) > MAXIMUM_ARRAY_ITEMS:
            fail("CANONICAL_ARRAY_TOO_LARGE")
        return "[" + ",".join(canonical_json(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        if len(value) > MAXIMUM_OBJECT_KEYS or any(not isinstance(key, str) for key in value):
            fail("CANONICAL_OBJECT_INVALID")
        keys = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(
            f"{_quote_string(key)}:{canonical_json(value[key], depth + 1)}" for key in keys
        ) + "}"
    fail("CANONICAL_TYPE_INVALID")


def canonical_bytes(value: Any) -> bytes:
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > MAXIMUM_CANONICAL_BYTES:
        fail("CANONICAL_BYTES_TOO_LARGE")
    return encoded


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_hex(value: bytes) -> str:
    return sha256(value).hex()


def exact_base64url(value: str, reason: str = "BASE64URL_INVALID") -> bytes:
    if not isinstance(value, str) or not value or BASE64URL.fullmatch(value) is None:
        fail(reason)
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except Exception:
        fail(reason)
    encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if not decoded or encoded != value:
        fail(reason)
    return decoded


def exact_hash_bytes(value: str, reason: str = "HASH_INVALID") -> bytes:
    normalized = str(value or "").lower()
    if HEX32.fullmatch(normalized) is None:
        fail(reason)
    return bytes.fromhex(normalized)


def uuid_bytes(value: str, reason: str = "UUID_INVALID") -> bytes:
    normalized = str(value or "").lower()
    if UUID.fullmatch(normalized) is None:
        fail(reason)
    return bytes.fromhex(normalized.replace("-", ""))


def u16(value: int, reason: str = "U16_INVALID") -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 0xFFFF:
        fail(reason)
    return struct.pack(">H", value)


def u32(value: int, reason: str = "U32_INVALID") -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 0xFFFFFFFF:
        fail(reason)
    return struct.pack(">I", value)


def i64(value: int, reason: str = "I64_INVALID") -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or abs(value) > MAXIMUM_SAFE_INTEGER:
        fail(reason)
    try:
        return struct.pack(">q", value)
    except struct.error:
        fail(reason)


def u64(value: int, reason: str = "U64_INVALID") -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAXIMUM_SAFE_INTEGER:
        fail(reason)
    try:
        return struct.pack(">Q", value)
    except struct.error:
        fail(reason)


def framed_utf8(value: str, reason: str = "FRAME_INVALID") -> bytes:
    encoded = str(value if value is not None else "").encode("utf-8")
    if not encoded or len(encoded) > 0xFFFFFFFF:
        fail(reason)
    return u32(len(encoded), reason) + encoded


def recall_merkle_root(entries: list[Any]) -> bytes:
    if not isinstance(entries, list):
        fail("MERKLE_INPUT_INVALID")
    peaks: list[tuple[int, bytes]] = []
    for entry in entries:
        node = sha256(b"\x00" + canonical_bytes(entry))
        height = 0
        while peaks and peaks[-1][0] == height:
            left = peaks.pop()[1]
            node = sha256(b"\x01" + left + node)
            height += 1
        peaks.append((height, node))
    if not peaks:
        return sha256(b"")
    result = peaks[-1][1]
    for _, left in reversed(peaks[:-1]):
        result = sha256(b"\x01" + left + result)
    return result


def verify_ed25519(public_key_base64url: str, message: bytes, signature_base64url: str) -> bool:
    try:
        public_key = load_der_public_key(exact_base64url(public_key_base64url, "PUBLIC_KEY_INVALID"))
        signature = exact_base64url(signature_base64url, "SIGNATURE_INVALID")
        if len(signature) != 64:
            return False
        public_key.verify(signature, bytes(message))
        return True
    except Exception:
        return False


def payload_message(body: Any, nonce: str, signed_ts: int) -> bytes:
    if not isinstance(nonce, str) or not nonce or not isinstance(signed_ts, int):
        fail("PAYLOAD_CONTEXT_INVALID")
    return f"{canonical_json(body)}\n{nonce}\n{signed_ts}".encode("utf-8")


def request_context_message(
    body: Any, method: str, path: str, nonce: str, signed_ts: int
) -> bytes:
    if not isinstance(nonce, str) or not nonce or not isinstance(signed_ts, int):
        fail("REQUEST_CONTEXT_INVALID")
    normalized_method = str(method or "").upper()
    normalized_path = str(path or "").split("?", 1)[0]
    if not normalized_method or not normalized_path:
        fail("REQUEST_CONTEXT_INVALID")
    return (
        f"{canonical_json(body)}\n{normalized_method}\n{normalized_path}\n{nonce}\n{signed_ts}"
    ).encode("utf-8")


def verify_payload_signature(
    public_key: str, body: Any, nonce: str, signed_ts: int, signature: str
) -> bool:
    try:
        return verify_ed25519(public_key, payload_message(body, nonce, signed_ts), signature)
    except Exception:
        return False


def verify_request_context_signature(
    public_key: str,
    body: Any,
    method: str,
    path: str,
    nonce: str,
    signed_ts: int,
    signature: str,
) -> bool:
    try:
        return verify_ed25519(
            public_key,
            request_context_message(body, method, path, nonce, signed_ts),
            signature,
        )
    except Exception:
        return False


def decode_certificate(certificate: str) -> dict[str, Any]:
    try:
        import json

        envelope = json.loads(exact_base64url(certificate, "CERTIFICATE_INVALID").decode("utf-8"))
    except Exception:
        fail("CERTIFICATE_INVALID")
    if (
        not isinstance(envelope, dict)
        or not isinstance(envelope.get("body"), dict)
        or not isinstance(envelope.get("sig"), str)
    ):
        fail("CERTIFICATE_INVALID")
    return envelope


def verify_certificate(
    *,
    certificate: str,
    authority_public_key: str,
    expected_agent_id: str,
    expected_subject_public_key: str,
    at_unix_seconds: int,
) -> dict[str, Any]:
    try:
        if not isinstance(at_unix_seconds, int):
            return {"valid": False, "reason": "CERTIFICATE_TIME_INVALID"}
        envelope = decode_certificate(certificate)
        body = envelope["body"]
        required = {
            "v", "agent_id", "pubkey", "device_fp",
            "valid_from", "valid_until", "issuer", "issued_at",
        }
        if (
            not required.issubset(body)
            or body["v"] != 1
            or not isinstance(body["valid_from"], int)
            or not isinstance(body["valid_until"], int)
            or body["valid_until"] <= body["valid_from"]
            or body["agent_id"] != expected_agent_id
            or body["pubkey"] != expected_subject_public_key
        ):
            return {"valid": False, "reason": "CERTIFICATE_BODY_INVALID"}
        if not verify_ed25519(authority_public_key, canonical_bytes(body), envelope["sig"]):
            return {"valid": False, "reason": "CERTIFICATE_SIGNATURE_INVALID"}
        if at_unix_seconds < body["valid_from"] or at_unix_seconds > body["valid_until"]:
            return {"valid": False, "reason": "CERTIFICATE_EPOCH_INVALID"}
        return {"valid": True, "reason": None, "body": body}
    except Exception:
        return {"valid": False, "reason": "CERTIFICATE_MALFORMED"}


def _tlv(tag: int, value: bytes) -> bytes:
    return u16(tag) + u32(len(value)) + value


def _occurrence_text(value: Any, *, empty: bool = False, uppercase: bool = False) -> bytes:
    normalized = str(value if value is not None else "")
    if (not empty and not normalized) or (uppercase and normalized != normalized.upper()):
        fail("OCCURRENCE_ENCODING_INVALID")
    return normalized.encode("utf-8")


def _presence(flag: Any, value: Any, decoder: Any) -> tuple[bytes, bytes]:
    if int(flag) == 0 and str(value or "") == "":
        return b"\x00", b""
    if int(flag) == 1:
        return b"\x01", decoder(value)
    fail("OCCURRENCE_ENCODING_INVALID")


def encode_occurrence_v3(record: dict[str, Any]) -> bytes:
    predecessor_flag, predecessor = _presence(
        record.get("predecessor_present"),
        record.get("predecessor_commitment_hex"),
        lambda value: exact_hash_bytes(value, "OCCURRENCE_ENCODING_INVALID"),
    )
    receipt_flag, receipt = _presence(
        record.get("request_receipt_present"),
        record.get("request_receipt_mutation_hash_hex"),
        lambda value: exact_hash_bytes(value, "OCCURRENCE_ENCODING_INVALID"),
    )
    authorization_flag, authorization = _presence(
        record.get("authorization_event_present"),
        record.get("authorization_event_id"),
        lambda value: uuid_bytes(value, "OCCURRENCE_ENCODING_INVALID"),
    )
    nonce_hex = str(record.get("nonce_hex") or "").lower()
    if re.fullmatch(r"[0-9a-f]+", nonce_hex) is None or len(nonce_hex) % 2:
        fail("OCCURRENCE_ENCODING_INVALID")
    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) < 16 or len(nonce) > 32:
        fail("OCCURRENCE_ENCODING_INVALID")
    event_type = str(record.get("event_type") or "")
    method = str(record.get("signed_method") or "")
    path = str(record.get("signed_path") or "")
    identity_tier = str(record.get("identity_tier") or "")
    if (
        int(record.get("sig_form_version") or 0) != 3
        or event_type != event_type.upper()
        or identity_tier != identity_tier.upper()
        or method != method.upper()
    ):
        fail("OCCURRENCE_ENCODING_INVALID")
    if (not method or not path) and not (
        not method and not path and event_type.startswith("INTERNAL_")
    ):
        fail("OCCURRENCE_ENCODING_INVALID")
    fields = [
        _occurrence_text(record.get("company_id")),
        uuid_bytes(record.get("occurrence_event_id"), "OCCURRENCE_ENCODING_INVALID"),
        uuid_bytes(record.get("memory_id"), "OCCURRENCE_ENCODING_INVALID"),
        _occurrence_text(event_type, uppercase=True),
        exact_hash_bytes(record.get("live_content_hash_hex"), "OCCURRENCE_ENCODING_INVALID"),
        predecessor_flag,
        predecessor,
        _occurrence_text(record.get("agent_id")),
        i64(int(record.get("signer_valid_from_unix_ms")), "OCCURRENCE_ENCODING_INVALID"),
        exact_hash_bytes(record.get("cert_fingerprint_hex"), "OCCURRENCE_ENCODING_INVALID"),
        _occurrence_text(identity_tier, uppercase=True),
        u16(int(record.get("sig_form_version")), "OCCURRENCE_ENCODING_INVALID"),
        nonce,
        u64(int(record.get("ts_signed_unix_seconds")), "OCCURRENCE_ENCODING_INVALID"),
        _occurrence_text(method, empty=True, uppercase=True),
        _occurrence_text(path, empty=True),
        exact_hash_bytes(record.get("request_body_hash_hex"), "OCCURRENCE_ENCODING_INVALID"),
        receipt_flag,
        receipt,
        authorization_flag,
        authorization,
    ]
    return OCCURRENCE_DOMAIN + b"".join(
        _tlv(index + 1, value) for index, value in enumerate(fields)
    )


def occurrence_commitment_v3(record: dict[str, Any]) -> str:
    return sha256_hex(encode_occurrence_v3(record))


def occurrence_signature_message_v3(commitment_hex: str) -> bytes:
    return OCCURRENCE_SIGNATURE_DOMAIN + exact_hash_bytes(
        commitment_hex, "OCCURRENCE_ENCODING_INVALID"
    )


def verify_occurrence_signature_v3(
    record: dict[str, Any], signature: str, public_key: str
) -> bool:
    try:
        commitment = occurrence_commitment_v3(record)
        return verify_ed25519(
            public_key, occurrence_signature_message_v3(commitment), signature
        )
    except Exception:
        return False

