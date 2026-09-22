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
import json
import math
import re
import struct
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_to_bytes

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


def parse_json_wire(raw: str | bytes) -> Any:
    def members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("JSON_DUPLICATE_MEMBER")
            result[key] = value
        return result

    def invalid_constant(_value):
        fail("JSON_WIRE_INVALID")

    return json.loads(raw, object_pairs_hook=members, parse_constant=invalid_constant)


def signed_json_bytes_commitment_v1(schema: str, wire: bytes) -> bytes:
    if (not isinstance(schema, str) or len(schema) > 200
            or re.fullmatch(r"[a-z][a-z0-9._/-]*/v[1-9][0-9]*", schema) is None):
        raise ValueError("signed_json_schema_invalid")
    if not isinstance(wire, bytes) or not 1 <= len(wire) <= MAXIMUM_CANONICAL_BYTES:
        raise ValueError("signed_json_size_invalid")
    try:
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out:
                    raise ValueError()
                out[key] = value
            return out

        def invalid_constant(_text):
            raise ValueError()

        # Numbers are syntax-checked tokens in this byte commitment. Do not
        # round/reformat them; typed consumers own numeric value validation.
        value = json.loads(wire.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=lambda _text: None, parse_float=lambda _text: None,
                           parse_constant=invalid_constant)
        pending = [(value, 0)]
        while pending:
            node, depth = pending.pop()
            if depth > MAXIMUM_DEPTH:
                raise ValueError()
            if isinstance(node, str):
                if any(ord(c) == 0 or 0xD800 <= ord(c) <= 0xDFFF for c in node):
                    raise ValueError()
            elif isinstance(node, list):
                pending.extend((child, depth + 1) for child in node)
            elif isinstance(node, dict):
                pending.extend((key, depth) for key in node)
                pending.extend((child, depth + 1) for child in node.values())
    except Exception as error:
        raise ValueError("signed_json_wire_invalid") from error
    name = schema.encode("ascii")
    return hashlib.sha256(b"hom.aimos.signed-json-bytes/v1\0" + struct.pack(">I", len(name))
                          + name + struct.pack(">I", len(wire)) + wire).digest()


def event_payload_body(event: dict) -> dict:
    if "signed_body_bytes_b64u" not in event:
        return event.get("signed_body")
    wire = exact_base64url(event.get("signed_body_bytes_b64u"), "EVENT_PAYLOAD_BYTES_INVALID")
    signed_json_bytes_commitment_v1("hom.aimos.event/v2", wire)
    # Authenticate unchanged bytes before interpreting values. Do not coerce
    # integer tokens through float before the authority-field range checks.
    body = json.loads(wire.decode("utf-8"))
    pending = [body]
    while pending:
        value = pending.pop()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                finite = math.isfinite(float(value))
            except OverflowError:
                finite = False
            if not finite:
                fail("EVENT_PAYLOAD_PROJECTION_INVALID")
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if not isinstance(body, dict) or body.get("payload_schema") != "hom.aimos.event/v2":
        fail("EVENT_PAYLOAD_VERSION_INVALID")

    def same(a, b):
        if isinstance(a, bool) or isinstance(b, bool):
            return type(a) is type(b) and a == b
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            try:
                return math.isfinite(float(b)) and float(a) == float(b)
            except OverflowError:
                return False
        if type(a) is not type(b):
            return False
        if isinstance(a, dict):
            return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
        if isinstance(a, list):
            return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
        return a == b

    if "signed_body" in event and not same(body, event["signed_body"]):
        fail("EVENT_PAYLOAD_PROJECTION_INVALID")
    return body


def event_payload_commitment(event: dict) -> bytes:
    body = event_payload_body(event)
    if not isinstance(body, dict):
        fail("EVENT_PAYLOAD_INVALID")
    if "payload_schema" not in body:
        if "signed_body_bytes_b64u" in event:
            fail("EVENT_PAYLOAD_VERSION_INVALID")
        return sha256(canonical_bytes(body))
    if body["payload_schema"] != "hom.aimos.event/v2":
        fail("EVENT_PAYLOAD_VERSION_INVALID")
    wire = exact_base64url(event.get("signed_body_bytes_b64u"), "EVENT_PAYLOAD_BYTES_INVALID")
    commitment = signed_json_bytes_commitment_v1(body["payload_schema"], wire)
    if (not isinstance(event.get("nonce"), str) or not event["nonce"]
            or body.get("nonce") != event["nonce"]
            or isinstance(body.get("ledger_version"), bool) or body.get("ledger_version") != 1
            or _exact_integer(body.get("ledger_seq"), 1, MAXIMUM_SAFE_INTEGER, "EVENT_PAYLOAD_PROJECTION_INVALID") < 1
            or _exact_integer(body.get("ts_signed"), 1, MAXIMUM_SAFE_INTEGER, "EVENT_PAYLOAD_PROJECTION_INVALID") < 1):
        fail("EVENT_PAYLOAD_PROJECTION_INVALID")
    return commitment


def verify_event_payload_signature(event: dict, public_key: str) -> bool:
    try:
        commitment = event_payload_commitment(event)
        if event_payload_body(event).get("payload_schema") == "hom.aimos.event/v2":
            return verify_ed25519(public_key, commitment, event.get("signature_b64u"))
        return verify_payload_signature(public_key, event["signed_body"], event.get("nonce"),
                                        event.get("ts_signed"), event.get("signature_b64u"))
    except (ValueError, TypeError, KeyError, OverflowError):
        return False


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
    if value.is_integer():
        if abs(value) > MAXIMUM_SAFE_INTEGER:
            fail("CANONICAL_NUMBER_INVALID")
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


def _exact_integer(value: Any, minimum: int, maximum: int, reason: str) -> int:
    # JSON 3, 3.0 and 3e0 have the same integral numeric value. Check the
    # domain before conversion; bool/string/null/fractional values never coerce.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(reason)
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        fail(reason)
    if value < minimum or value > maximum:
        fail(reason)
    return int(value)


def u16(value: int | float, reason: str = "U16_INVALID") -> bytes:
    return struct.pack(">H", _exact_integer(value, 0, 0xFFFF, reason))


def u32(value: int | float, reason: str = "U32_INVALID") -> bytes:
    return struct.pack(">I", _exact_integer(value, 0, 0xFFFFFFFF, reason))


def i64(value: int | float, reason: str = "I64_INVALID") -> bytes:
    value = _exact_integer(value, -MAXIMUM_SAFE_INTEGER, MAXIMUM_SAFE_INTEGER, reason)
    try:
        return struct.pack(">q", value)
    except struct.error:
        fail(reason)


def u64(value: int | float, reason: str = "U64_INVALID") -> bytes:
    value = _exact_integer(value, 0, MAXIMUM_SAFE_INTEGER, reason)
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


def request_target_message_v5(body, method, target, claims, nonce, signed_ts, wire=None):
    signed_ts = _exact_integer(signed_ts, 1, MAXIMUM_SAFE_INTEGER, "REQUEST_CONTEXT_INVALID")
    m = str(method or "").upper()
    if (not re.fullmatch(r"[A-Z]+", m) or not isinstance(nonce, str) or not nonce
        or not isinstance(target, str) or not target.startswith("/") or target.startswith("//")
        or re.search(r"[^\x21-\x7e]|[#\\]|%(?![0-9a-fA-F]{2})", target)):
        fail("REQUEST_CONTEXT_INVALID")
    keys = set()
    for field in (target.split("?", 1)[1] if "?" in target else "").split("&"):
        if not field:
            continue
        key = unquote_to_bytes(field.split("=", 1)[0].replace("+", " ")).decode("utf-8", errors="strict")
        if "\0" in key or key in keys:
            fail("REQUEST_CONTEXT_INVALID")
        keys.add(key)
    if not isinstance(claims, dict) or set(claims) != {"prev_chain_hash", "device_fp"}:
        fail("REQUEST_CONTEXT_INVALID")
    prev, device = claims["prev_chain_hash"], claims["device_fp"]
    if prev is not None and (not isinstance(prev, str) or len(exact_base64url(prev)) != 32):
        fail("REQUEST_CONTEXT_INVALID")
    if device is not None and (not isinstance(device, str) or not device or prev is None):
        fail("REQUEST_CONTEXT_INVALID")
    fields = [wire if wire is not None else canonical_json(body).encode("utf-8"), m.encode("ascii"),
              target.encode("ascii"), canonical_json(claims).encode("utf-8"), nonce.encode("utf-8"), str(signed_ts).encode("ascii")]
    return b"hom.aimos.request-envelope/v5\0" + b"".join(struct.pack(">I", len(value)) + value for value in fields)


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
    request_form: int = 3,
    claims=None,
) -> bool:
    try:
        if request_form not in (3, 5):
            return False
        return verify_ed25519(
            public_key,
            request_target_message_v5(body, method, path, claims, nonce, signed_ts) if request_form == 5
            else request_context_message(body, method, path, nonce, signed_ts),
            signature,
        )
    except Exception:
        return False


def retained_provenance_message(row: dict) -> dict:
    if row.get("body_json_encoding") != "hom-aimos/canonical-json/v1" or "body_json" in row:
        fail("PROVENANCE_BYTES_INVALID")
    if any(key not in row for key in ("signed_method", "signed_path", "signed_claims", "memory_originated_at", "prev_mutation_hash")):
        fail("PROVENANCE_CONTEXT_INVALID")
    wire = exact_base64url(row.get("body_json_bytes_b64u"), "PROVENANCE_BYTES_INVALID")
    if not 1 <= len(wire) <= MAXIMUM_CANONICAL_BYTES:
        fail("PROVENANCE_BYTES_INVALID")
    try:
        body = parse_json_wire(wire.decode("utf-8"))
        if not isinstance(body, (dict, list)):
            fail("PROVENANCE_BYTES_INVALID")
        pending = [(body, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > MAXIMUM_DEPTH or (type(value) in (int, float) and not math.isfinite(float(value))):
                fail("PROVENANCE_BYTES_INVALID")
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            pending.extend((child, depth + 1) for child in children)
    except Exception:
        fail("PROVENANCE_BYTES_INVALID")
    form = _exact_integer(row.get("sig_form_version"), 1, 2, "PROVENANCE_CONTEXT_INVALID")
    request_form = _exact_integer(row.get("request_sig_form"), 1, 5, "PROVENANCE_CONTEXT_INVALID")
    if request_form == 5 and form != 1:
        fail("PROVENANCE_CONTEXT_INVALID")
    ts = _exact_integer(row.get("ts_signed"), 1, MAXIMUM_SAFE_INTEGER, "PROVENANCE_CONTEXT_INVALID")
    if (request_form not in (1, 3, 4, 5)
        or not isinstance(row.get("nonce"), str) or not row["nonce"]
        or type(row.get("is_genesis")) is not bool or row["is_genesis"] != (row.get("prev_mutation_hash") is None)
        or row.get("identity_tier") not in ("T1", "T2", "T3")
        or (row["identity_tier"] in ("T2", "T3") and request_form not in (4, 5))):
        fail("PROVENANCE_CONTEXT_INVALID")
    content_hash = sha256_hex(wire)
    if content_hash != row.get("content_hash"):
        fail("PROVENANCE_COMMITMENT_INVALID")
    nonce = row["nonce"]
    origin_seconds = None
    if form == 2:
        try:
            if not isinstance(row.get("memory_originated_at"), str):
                fail("PROVENANCE_CONTEXT_INVALID")
            origin = datetime.fromisoformat(row["memory_originated_at"].replace("Z", "+00:00"))
            if origin.isoformat(timespec="milliseconds").replace("+00:00", "Z") != row["memory_originated_at"]:
                fail("PROVENANCE_CONTEXT_INVALID")
            origin_seconds = math.floor(origin.timestamp())
            if abs(origin_seconds) > MAXIMUM_SAFE_INTEGER:
                fail("PROVENANCE_CONTEXT_INVALID")
        except Exception:
            fail("PROVENANCE_CONTEXT_INVALID")
        suffix = f"\n{nonce}\n{ts}\n{origin_seconds}"
    elif request_form == 5:
        if row["identity_tier"] in ("T2", "T3") and not (row.get("signed_claims") or {}).get("prev_chain_hash"):
            fail("PROVENANCE_CONTEXT_INVALID")
        request_target_message_v5(body, row["signed_method"], row["signed_path"], row["signed_claims"], nonce, ts, wire)
        suffix = ""
    elif request_form == 1:
        if any(row.get(key) is not None for key in ("signed_method", "signed_path", "signed_claims")):
            fail("PROVENANCE_CONTEXT_INVALID")
        suffix = f"\n{nonce}\n{ts}"
    else:
        method, path = row.get("signed_method"), row.get("signed_path")
        if not isinstance(method, str) or not method or not isinstance(path, str) or not path:
            fail("PROVENANCE_CONTEXT_INVALID")
        suffix = f"\n{method.upper()}\n{path.split('?')[0]}"
        if request_form == 4:
            claims = row.get("signed_claims")
            if (not isinstance(claims, dict) or not isinstance(claims.get("prev_chain_hash"), str)
                or len(exact_base64url(claims["prev_chain_hash"])) != 32
                or (claims.get("device_fp") is not None and (not isinstance(claims["device_fp"], str) or not claims["device_fp"]))):
                fail("PROVENANCE_CONTEXT_INVALID")
            suffix += "\n" + canonical_json({"prev_chain_hash": claims["prev_chain_hash"], "device_fp": claims.get("device_fp")})
        elif row.get("signed_claims") is not None:
            fail("PROVENANCE_CONTEXT_INVALID")
        suffix += f"\n{nonce}\n{ts}"
    mutation = sha256_hex(exact_hash_bytes(content_hash)
        + (b"" if row.get("prev_mutation_hash") is None else exact_hash_bytes(row["prev_mutation_hash"]))
        + nonce.encode("utf-8") + str(ts).encode("ascii")
        + (b"" if origin_seconds is None else str(origin_seconds).encode("ascii")))
    if mutation != row.get("mutation_hash"):
        fail("PROVENANCE_COMMITMENT_INVALID")
    message = request_target_message_v5(body, row["signed_method"], row["signed_path"], row["signed_claims"], nonce, ts, wire) if request_form == 5 and form != 2 else wire + suffix.encode("utf-8")
    return {"body": body, "wire": wire, "message": message, "content_hash": content_hash, "mutation_hash": mutation}


def legacy_occurrence_reference(row: dict, company_id: str) -> str:
    if (not isinstance(company_id, str) or not company_id or not isinstance(row.get("agent_id"), str) or not row["agent_id"]
        or not isinstance(row.get("event_type"), str) or not row["event_type"] or row["event_type"] != row["event_type"].upper()):
        fail("PROVENANCE_CONTEXT_INVALID")
    epoch = datetime.fromisoformat(row["agent_valid_from"].replace("Z", "+00:00"))
    delta = epoch - datetime(1970, 1, 1, tzinfo=timezone.utc)
    milliseconds = delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
    fields = [company_id.encode("utf-8"), uuid_bytes(row["memory_id"]), uuid_bytes(row["provenance_id"]),
        exact_hash_bytes(row["mutation_hash"]), row["agent_id"].encode("utf-8"), i64(milliseconds),
        exact_hash_bytes(row["cert_fingerprint"]), row["event_type"].encode("utf-8"), u16(row["sig_form_version"])]
    return sha256_hex(b"hom.aimos.memory-occurrence-ref/legacy-v1\x00" + b"".join(_tlv(index + 1, value) for index, value in enumerate(fields)))


def decode_certificate(certificate: str) -> dict[str, Any]:
    try:
        envelope = parse_json_wire(exact_base64url(certificate, "CERTIFICATE_INVALID").decode("utf-8"))
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
    flag = _exact_integer(flag, 0, 1, "OCCURRENCE_ENCODING_INVALID")
    if flag == 0 and str(value or "") == "":
        return b"\x00", b""
    if flag == 1:
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
        _exact_integer(record.get("sig_form_version"), 3, 3, "OCCURRENCE_ENCODING_INVALID") != 3
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
        i64(record.get("signer_valid_from_unix_ms"), "OCCURRENCE_ENCODING_INVALID"),
        exact_hash_bytes(record.get("cert_fingerprint_hex"), "OCCURRENCE_ENCODING_INVALID"),
        _occurrence_text(identity_tier, uppercase=True),
        u16(record.get("sig_form_version"), "OCCURRENCE_ENCODING_INVALID"),
        nonce,
        u64(record.get("ts_signed_unix_seconds"), "OCCURRENCE_ENCODING_INVALID"),
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
