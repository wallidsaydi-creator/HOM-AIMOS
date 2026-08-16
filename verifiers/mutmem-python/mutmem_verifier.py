"""Independent MutMem cognitive-evidence verifier.

This module is deliberately implemented from the public protocol specification
and the JSON evidence schema.  It does not import HOM-AIMOS source, connect to
its database or server, read signing keys, inspect environment variables, or
perform network I/O.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key


SCHEMA = "hom.aimos.mutmem-cognitive-evidence/v1"
VERIFIER_VERSION = "0.1.0"
MASTER_ISSUER = "aimos-master"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_DEPTH = 32
MAX_BUNDLE_BYTES = 512 * 1024 * 1024

TRANSITION_DOMAIN = b"aimos.cognitive-transition/v2\0"
BASELINE_DOMAIN = b"aimos.cognitive-baseline/v1\0"
PROJECTION_DOMAIN = b"aimos.cwc/v1\0"
CORPUS_DOMAIN = b"aimos.cognitive-corpus-proof/v1\0"
EVENT_LINK_DOMAIN = b"AIMOS-EVENT-LINK-v1\0"
EVENT_GENESIS_DOMAIN = b"aimos-event-genesis/v1\0"
REVOCATION_DOMAIN = b"aimos-agent-revocation-v1\0"
REVOCATION_SCHEMA = "hom.aimos.agent-revocation/v1"

REQUIRED_CERT_FIELDS = {
    "v", "agent_id", "pubkey", "device_fp", "valid_from", "valid_until",
    "issuer", "issued_at",
}


class VerificationError(Exception):
    """A stable fail-closed protocol or schema error."""


@dataclass(frozen=True)
class Identity:
    agent_id: str
    pubkey: str
    certificate: str
    device_fingerprint: str
    valid_from: int
    valid_until: int
    master_pubkey: str
    master_fingerprint: str
    revocation: dict[str, Any] | None


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _b64u_decode(value: str, reason: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise VerificationError(reason)
    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise VerificationError(reason) from exc


def _exact_hex(value: Any, size: int, reason: str) -> bytes:
    if not isinstance(value, str) or len(value) != size * 2:
        raise VerificationError(reason)
    if value.lower() != value or any(char not in "0123456789abcdef" for char in value):
        raise VerificationError(reason)
    return bytes.fromhex(value)


def _integer(value: Any, reason: str, minimum: int | None = None,
             maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerificationError(reason)
    if abs(value) > MAX_SAFE_INTEGER:
        raise VerificationError(reason)
    if minimum is not None and value < minimum:
        raise VerificationError(reason)
    if maximum is not None and value > maximum:
        raise VerificationError(reason)
    return value


def _json_number(value: float) -> str:
    if not math.isfinite(value):
        raise VerificationError("canonical_json_non_finite_number")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    rendered = repr(value).lower()
    if "e" in rendered:
        mantissa, exponent = rendered.split("e", 1)
        exponent_value = int(exponent)
        if 1e-6 <= abs(value) < 1e21:
            negative = mantissa.startswith("-")
            digits = mantissa.lstrip("-").replace(".", "")
            decimal_at = (1 if "." in mantissa else len(digits)) + exponent_value
            if decimal_at <= 0:
                rendered = "0." + ("0" * -decimal_at) + digits
            elif decimal_at >= len(digits):
                rendered = digits + ("0" * (decimal_at - len(digits)))
            else:
                rendered = digits[:decimal_at] + "." + digits[decimal_at:]
            return ("-" if negative else "") + rendered
        sign = "+" if exponent_value >= 0 else "-"
        rendered = f"{mantissa}e{sign}{abs(exponent_value)}"
    return rendered


def _utf16_sort_key(value: str) -> bytes:
    """Match JavaScript Array.sort ordering over UTF-16 code units."""
    return value.encode("utf-16-be", errors="surrogatepass")


def _js_round(value: float) -> int:
    """Match Math.round for the finite, positive weights used by MutMem."""
    if not math.isfinite(value):
        raise VerificationError("cognitive_evidence_number_invalid")
    return math.floor(value + 0.5)


def canonical_json(value: Any, depth: int = 0) -> str:
    """Canonical JSON compatible with AIMOS's restricted RFC 8785 subset."""
    if depth > MAX_DEPTH:
        raise VerificationError("canonical_json_depth_limit")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise VerificationError("canonical_json_integer_out_of_range")
        return str(value)
    if isinstance(value, float):
        return _json_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise VerificationError("canonical_json_object_key_invalid")
        parts = []
        for key in sorted(value, key=_utf16_sort_key):
            encoded_key = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            parts.append(f"{encoded_key}:{canonical_json(value[key], depth + 1)}")
        return "{" + ",".join(parts) + "}"
    raise VerificationError("canonical_json_type_invalid")


def _iso_millis(epoch_seconds: int) -> str:
    value = _integer(epoch_seconds, "cognitive_evidence_epoch_invalid", 1)
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _iso_to_epoch(value: Any, reason: str) -> int:
    if not isinstance(value, str) or not value:
        raise VerificationError(reason)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError(reason) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = math.floor(parsed.timestamp())
    return _integer(seconds, reason, 1)


def _float4_from_hex(value: Any, reason: str) -> float:
    return struct.unpack(">f", _exact_hex(value, 4, reason))[0]


def _float4(value: float) -> bytes:
    if not math.isfinite(float(value)):
        raise VerificationError("cognitive_evidence_float4_invalid")
    return struct.pack(">f", float(value))


def _uuid_bytes(value: Any, reason: str) -> bytes:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise VerificationError(reason) from exc
    if str(parsed) != str(value):
        raise VerificationError(reason)
    return parsed.bytes


def _int64(value: int, reason: str) -> bytes:
    number = _integer(value, reason)
    try:
        return struct.pack(">q", number)
    except struct.error as exc:
        raise VerificationError(reason) from exc


def _public_key(value: str):
    try:
        return load_der_public_key(_b64u_decode(value, "public_key_invalid"))
    except Exception as exc:
        raise VerificationError("public_key_invalid") from exc


def _verify_raw(public_key_b64u: str, message: bytes, signature: bytes) -> bool:
    try:
        _public_key(public_key_b64u).verify(signature, message)
        return True
    except (InvalidSignature, VerificationError, ValueError, TypeError):
        return False


def _certificate_envelope(certificate: str) -> dict[str, Any]:
    try:
        decoded = _b64u_decode(certificate, "cert_malformed").decode("utf-8")
        envelope = json.loads(decoded, object_pairs_hook=_reject_duplicates)
    except Exception as exc:
        raise VerificationError("cert_malformed") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("body"), dict) \
            or not isinstance(envelope.get("sig"), str):
        raise VerificationError("cert_malformed")
    if not REQUIRED_CERT_FIELDS.issubset(envelope["body"]):
        raise VerificationError("cert_schema")
    return envelope


def _certificate_authority(identity: Identity, body: dict[str, Any]) -> str | None:
    issuer = body.get("issuer")
    if issuer == body.get("agent_id"):
        return identity.pubkey
    if issuer not in {MASTER_ISSUER, identity.master_fingerprint}:
        return None
    try:
        fingerprint = _sha256(_b64u_decode(identity.master_pubkey, "master_key_invalid")).hex()
    except VerificationError:
        return None
    return identity.master_pubkey if fingerprint == identity.master_fingerprint else None


def _verify_certificate(certificate: str, authority: str, signed_at: int) -> tuple[bool, str | None, dict[str, Any] | None]:
    try:
        envelope = _certificate_envelope(certificate)
        body = envelope["body"]
        signature = _b64u_decode(envelope["sig"], "cert_sig_invalid")
        if len(signature) != 64 or not _verify_raw(authority, canonical_json(body).encode(), signature):
            return False, "cert_sig_invalid", None
        if signed_at < int(body["valid_from"]):
            return False, "cert_not_yet_valid", body
        if signed_at > int(body["valid_until"]):
            return False, "cert_expired", body
        return True, None, body
    except VerificationError as exc:
        return False, str(exc), None


def _verify_stored_signature(public_key: str, body: dict[str, Any], nonce: str,
                             signed_at: int, signature: bytes, *,
                             signature_form: int = 1,
                             request_signature_form: int = 1,
                             memory_originated_at: int | None = None,
                             method: str | None = None,
                             path: str | None = None,
                             claims: dict[str, Any] | None = None) -> tuple[bool, str | None]:
    if not isinstance(nonce, str) or not nonce or not isinstance(signed_at, int):
        return False, "malformed_input"
    try:
        message = canonical_json(body)
        if signature_form == 2:
            if not isinstance(memory_originated_at, int):
                return False, "malformed_input"
            message += f"\n{nonce}\n{signed_at}\n{memory_originated_at}"
        elif request_signature_form == 3:
            signed_method = str(method or "").upper()
            signed_path = str(path or "").split("?", 1)[0]
            if not signed_method or not signed_path:
                return False, "malformed_input"
            message += f"\n{signed_method}\n{signed_path}\n{nonce}\n{signed_at}"
        elif request_signature_form == 4:
            signed_method = str(method or "").upper()
            signed_path = str(path or "").split("?", 1)[0]
            claims = claims if isinstance(claims, dict) else {}
            previous = claims.get("prevChainHash", claims.get("prev_chain_hash"))
            device = claims.get("deviceFp", claims.get("device_fp"))
            if not signed_method or not signed_path or not isinstance(previous, str) or not previous \
                    or (device is not None and (not isinstance(device, str) or not device)):
                return False, "malformed_input"
            message += "\n" + signed_method + "\n" + signed_path + "\n"
            message += canonical_json({"prev_chain_hash": previous, "device_fp": device})
            message += f"\n{nonce}\n{signed_at}"
        else:
            message += f"\n{nonce}\n{signed_at}"
        valid = _verify_raw(public_key, message.encode(), signature)
        return valid, None if valid else "sig_invalid"
    except VerificationError:
        return False, "malformed_input"


def _decode_identity(raw: Any, master: dict[str, Any]) -> Identity:
    if not isinstance(raw, dict):
        raise VerificationError("cognitive_evidence_identity_invalid")
    valid_from = _integer(raw.get("valid_from"), "cognitive_evidence_identity_epoch_invalid", 1)
    valid_until = _integer(raw.get("valid_until"), "cognitive_evidence_identity_epoch_invalid", 1)
    identity = Identity(
        agent_id=str(raw.get("agent_id", "")),
        pubkey=str(raw.get("pubkey_b64u", "")),
        certificate=str(raw.get("certificate_b64u", "")),
        device_fingerprint=str(raw.get("device_fingerprint", "")),
        valid_from=valid_from,
        valid_until=valid_until,
        master_pubkey=str(master.get("public_key_b64u", "")),
        master_fingerprint=str(master.get("fingerprint", "")),
        revocation=raw.get("revocation"),
    )
    if not all((identity.agent_id, identity.pubkey, identity.certificate,
                identity.device_fingerprint)) or valid_until <= valid_from:
        raise VerificationError("cognitive_evidence_identity_invalid")
    return identity


def _verify_revocation(raw: dict[str, Any], identity: Identity) -> tuple[bool, str | None]:
    try:
        body = raw.get("signed_body")
        if not isinstance(body, dict) or body.get("schema") != REVOCATION_SCHEMA \
                or body.get("event_type") != "REVOKE_AGENT_IDENTITY":
            return False, "revocation_body_invalid"
        target_cert_hash = _sha256(identity.certificate.encode())
        prior_body = {
            "agent_id": str(body.get("agent_id")),
            "agent_valid_from": _iso_millis(_iso_to_epoch(body.get("agent_valid_from"), "revocation_time_invalid")),
            "target_cert_hash": target_cert_hash.hex(),
        }
        prior_hash = _sha256(canonical_json(prior_body).encode())
        content_hash = _sha256(canonical_json(body).encode())
        signature = _exact_hex(raw.get("signature"), 64, "revocation_signature_invalid")
        mutation_hash = _sha256(REVOCATION_DOMAIN + prior_hash + content_hash + signature)
        revoked_at = _iso_to_epoch(body.get("revoked_at"), "revocation_time_invalid")
        exact = (
            body.get("agent_id") == raw.get("agent_id") == identity.agent_id
            and _iso_to_epoch(body.get("agent_valid_from"), "revocation_time_invalid") == raw.get("agent_valid_from")
            and body.get("target_cert_hash") == target_cert_hash.hex()
            and body.get("prior_identity_hash") == prior_hash.hex()
            and body.get("master_fingerprint") == raw.get("master_fingerprint") == identity.master_fingerprint
            and _exact_hex(raw.get("target_cert_hash"), 32, "revocation_target_invalid") == target_cert_hash
            and _exact_hex(raw.get("prior_identity_hash"), 32, "revocation_prior_invalid") == prior_hash
            and _exact_hex(raw.get("content_hash"), 32, "revocation_content_invalid") == content_hash
            and _exact_hex(raw.get("mutation_hash"), 32, "revocation_mutation_invalid") == mutation_hash
            and raw.get("ts_signed") == revoked_at
        )
        if not exact:
            return False, "revocation_hash_mismatch"
        return _verify_stored_signature(
            identity.master_pubkey, body, str(raw.get("nonce", "")),
            int(raw.get("ts_signed")), signature,
        )
    except (VerificationError, ValueError, TypeError):
        return False, "revocation_proof_malformed"


def _verify_identity_epoch(identity: Identity, signed_at: int) -> tuple[bool, str | None]:
    try:
        envelope = _certificate_envelope(identity.certificate)
        body = envelope["body"]
        authority = _certificate_authority(identity, body)
        if not authority:
            return False, "certificate_authority_missing"
        valid, reason, cert_body = _verify_certificate(identity.certificate, authority, signed_at)
        exact = valid and cert_body is not None \
            and cert_body.get("agent_id") == identity.agent_id \
            and cert_body.get("pubkey") == identity.pubkey \
            and cert_body.get("device_fp") == identity.device_fingerprint \
            and cert_body.get("valid_from") == identity.valid_from \
            and cert_body.get("valid_until") == identity.valid_until \
            and identity.valid_from <= signed_at < identity.valid_until
        if not exact:
            return False, reason or "identity_epoch_mismatch"
        if identity.revocation is None:
            return True, None
        if identity.revocation.get("master_fingerprint") != identity.master_fingerprint:
            return False, "revocation_master_mismatch"
        revocation_valid, revocation_reason = _verify_revocation(identity.revocation, identity)
        if not revocation_valid:
            return False, f"revocation_{revocation_reason}"
        if int(identity.revocation.get("ts_signed")) <= signed_at:
            return False, "identity_revoked_before_signature"
        return True, None
    except VerificationError as exc:
        return False, str(exc)


def _event_genesis(company: str, agent: str, valid_from: int) -> bytes:
    return _sha256(EVENT_GENESIS_DOMAIN + company.encode() + b"\0" + agent.encode()
                   + b"\0" + _iso_millis(valid_from).encode())


def _event_mutation(previous: bytes, content: bytes, nonce: str, signed_at: int) -> bytes:
    return _sha256(EVENT_LINK_DOMAIN + previous + content + nonce.encode() + str(signed_at).encode())


def _verify_event(event: dict[str, Any], identity: Identity) -> tuple[bool, str | None]:
    try:
        body = event.get("signed_body")
        if not isinstance(body, dict) or event.get("proof_required") is not True \
                or event.get("ledger_version") != 1:
            return False, "event_proof_version"
        content_hash = _sha256(canonical_json(body).encode())
        previous = _exact_hex(event.get("previous_mutation_hash"), 32, "event_previous_invalid")
        mutation_hash = _event_mutation(previous, content_hash, str(event.get("nonce", "")), int(event.get("signed_at")))
        exact = (
            body.get("event_id") == event.get("event_id")
            and body.get("company_id") == event.get("company_id")
            and body.get("subject_agent_id") == event.get("subject_agent_id")
            and body.get("signer_agent_id") == event.get("signer_agent_id")
            and _iso_to_epoch(body.get("signer_valid_from"), "event_epoch_invalid") == event.get("signer_valid_from")
            and body.get("cert_fingerprint") == event.get("certificate_fingerprint")
            and body.get("identity_tier") == event.get("identity_tier")
            and body.get("authority_kind") == event.get("authority_kind")
            and body.get("operation") == event.get("operation")
            and body.get("key") == event.get("key")
            and canonical_json(body.get("metadata")) == canonical_json(event.get("metadata"))
            and body.get("parent_event_id") == event.get("parent_event_id")
            and body.get("ledger_seq") == event.get("ledger_sequence")
            and body.get("prev_mutation_hash") == previous.hex()
            and body.get("ts_signed") == event.get("signed_at")
            and _exact_hex(event.get("content_hash"), 32, "event_content_invalid") == content_hash
            and _exact_hex(event.get("mutation_hash"), 32, "event_mutation_invalid") == mutation_hash
        )
        if not exact:
            return False, "event_proof_hash_mismatch"
        signature = _exact_hex(event.get("signature"), 64, "event_signature_invalid")
        valid, reason = _verify_stored_signature(
            identity.pubkey, body, str(event.get("nonce", "")),
            int(event.get("signed_at")), signature,
        )
        return (valid, reason if not valid else None)
    except (VerificationError, ValueError, TypeError):
        return False, "event_proof_malformed"


def _verify_event_stream(stream: dict[str, Any], master: dict[str, Any], company: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    identity = _decode_identity(stream.get("identity"), master)
    if stream.get("signer_agent_id") != identity.agent_id \
            or stream.get("signer_valid_from") != identity.valid_from:
        raise VerificationError("cognitive_evidence_event_identity_mismatch")
    events = stream.get("events")
    if not isinstance(events, list):
        raise VerificationError("cognitive_evidence_event_stream_invalid")
    previous = _event_genesis(company, identity.agent_id, identity.valid_from)
    indexed: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events):
        signed_at = _integer(event.get("signed_at"), "event_time_invalid", 1)
        identity_valid, _ = _verify_identity_epoch(identity, signed_at)
        if event.get("company_id") != company or event.get("signer_agent_id") != identity.agent_id \
                or not identity_valid:
            raise VerificationError("cognitive_evidence_event_identity_epoch_invalid")
        if event.get("ledger_sequence") != index + 1 \
                or _exact_hex(event.get("previous_mutation_hash"), 32, "event_previous_invalid") != previous:
            raise VerificationError("event_ledger_chain_link_invalid")
        envelope = _certificate_envelope(identity.certificate)
        cert_body = envelope["body"]
        certificate_fingerprint = _sha256(identity.certificate.encode()).hex()
        if cert_body.get("agent_id") != identity.agent_id or cert_body.get("pubkey") != identity.pubkey \
                or event.get("certificate_fingerprint") != certificate_fingerprint:
            raise VerificationError("event_ledger_identity_mismatch")
        authority = _certificate_authority(identity, cert_body)
        if not authority:
            raise VerificationError("event_ledger_certificate_issuer_invalid")
        cert_valid, cert_reason, _ = _verify_certificate(identity.certificate, authority, signed_at)
        if not cert_valid:
            raise VerificationError(f"event_ledger_certificate_invalid:{cert_reason}")
        proof_valid, proof_reason = _verify_event(event, identity)
        if not proof_valid:
            raise VerificationError(f"event_ledger_proof_invalid:{proof_reason}")
        event_id = str(event.get("event_id", ""))
        if not event_id or event_id in indexed:
            raise VerificationError("cognitive_evidence_event_duplicate")
        indexed[event_id] = {**event, "event_stream_verified": True}
        previous = _exact_hex(event.get("mutation_hash"), 32, "event_mutation_invalid")
    result = {
        "signer_agent_id": identity.agent_id,
        "signer_valid_from": identity.valid_from,
        "event_count": len(events),
        "valid": True,
        "reason": None,
    }
    return result, indexed


def _cognitive_baseline_hash(company: str, memory_id: str, event_id: str,
                             event_hash: bytes, content_hash: bytes,
                             observed_float4: bytes, weight_milli: int,
                             observed_at: int, signer_epoch: int,
                             cert_fingerprint: bytes) -> bytes:
    company_bytes = company.encode()
    return _sha256(
        BASELINE_DOMAIN + struct.pack(">i", len(company_bytes)) + company_bytes
        + _uuid_bytes(memory_id, "cognitive_baseline_memory_malformed")
        + _uuid_bytes(event_id, "cognitive_baseline_event_malformed")
        + event_hash + content_hash + observed_float4
        + _int64(weight_milli, "cognitive_baseline_weight_malformed")
        + _int64(observed_at, "cognitive_baseline_observation_malformed")
        + _int64(signer_epoch, "cognitive_baseline_epoch_malformed")
        + cert_fingerprint
    )


def _projection_hash(memory_id: str, old_milli: int, new_milli: int,
                     provenance_hash: bytes, previous: bytes | None) -> bytes:
    return _sha256(
        PROJECTION_DOMAIN + _uuid_bytes(memory_id, "cognitive_uuid_malformed")
        + _int64(old_milli, "projection_weight_invalid")
        + _int64(new_milli, "projection_weight_invalid")
        + provenance_hash + (previous if previous is not None else bytes(32))
    )


def _transition_hash(company: str, memory_id: str, old_milli: int,
                     new_milli: int, provenance_hash: bytes) -> bytes:
    if old_milli == new_milli or not 100 <= old_milli <= 3000 or not 100 <= new_milli <= 3000:
        raise VerificationError("cognitive_transition_weight_malformed")
    company_bytes = company.encode()
    return _sha256(
        TRANSITION_DOMAIN + struct.pack(">i", len(company_bytes)) + company_bytes
        + _uuid_bytes(memory_id, "cognitive_transition_identity_malformed")
        + _int64(old_milli, "cognitive_transition_weight_malformed")
        + _int64(new_milli, "cognitive_transition_weight_malformed")
        + provenance_hash
    )


def _verify_baseline(baseline: dict[str, Any], memory: dict[str, Any],
                     identity: Identity, event: dict[str, Any] | None) -> tuple[bool, str | None]:
    try:
        observed_float4 = _exact_hex(baseline.get("observed_weight_float4"), 4, "baseline_float4_invalid")
        observed = struct.unpack(">f", observed_float4)[0]
        identity_valid, identity_reason = _verify_identity_epoch(identity, int(baseline.get("observed_at")))
        certificate_fingerprint = _sha256(identity.certificate.encode()).hex()
        exact = (
            baseline.get("company_id") == memory.get("company_id")
            and baseline.get("memory_id") == memory.get("memory_id")
            and baseline.get("live_content_hash") == memory.get("content_hash")
            and observed_float4 != _float4(1)
            and _js_round(observed * 1000) == baseline.get("observed_weight_milli")
            and baseline.get("attestation_reason") == "retained_nondefault_weight_baseline"
            and baseline.get("historical_origin_claimed") is False
            and baseline.get("signer_agent_id") == "housekeeper"
            and baseline.get("signer_valid_from") == identity.valid_from
            and baseline.get("certificate_fingerprint") == certificate_fingerprint
            and identity_valid
        )
        if not exact:
            return False, identity_reason or "baseline_binding_invalid"
        if event is None or event.get("event_id") != baseline.get("event_id") \
                or event.get("mutation_hash") != baseline.get("event_mutation_hash"):
            return False, "baseline_event_missing"
        event_epoch_valid, _ = _verify_identity_epoch(identity, int(event.get("signed_at")))
        if event.get("company_id") != baseline.get("company_id") \
                or event.get("signer_agent_id") != baseline.get("signer_agent_id") \
                or event.get("signer_valid_from") != baseline.get("signer_valid_from") \
                or event.get("certificate_fingerprint") != baseline.get("certificate_fingerprint") \
                or event.get("event_stream_verified") is not True \
                or abs(int(event.get("signed_at")) - int(baseline.get("observed_at"))) > 5 \
                or not event_epoch_valid:
            return False, "baseline_event_epoch_invalid"
        event_valid, event_reason = _verify_event(event, identity)
        if not event_valid:
            return False, f"baseline_event_{event_reason}"
        metadata = event.get("metadata")
        if not isinstance(metadata, dict) or event.get("operation") != "cognitive_initial_weight_attested" \
                or event.get("key") != memory.get("memory_id") \
                or metadata.get("schema") != "hom.aimos.cognitive-initial-weight/v1" \
                or metadata.get("observed_weight_float4") != observed_float4.hex() \
                or metadata.get("weight_milli") != baseline.get("observed_weight_milli") \
                or metadata.get("observed_ts") != baseline.get("observed_at") \
                or metadata.get("memory_content_hash") != memory.get("content_hash") \
                or metadata.get("historical_origin_claimed") is not False \
                or metadata.get("canonical_memory_mutation") is not False:
            return False, "baseline_event_binding_invalid"
        expected = _cognitive_baseline_hash(
            str(baseline.get("company_id")), str(baseline.get("memory_id")),
            str(baseline.get("event_id")),
            _exact_hex(baseline.get("event_mutation_hash"), 32, "baseline_event_invalid"),
            _exact_hex(baseline.get("live_content_hash"), 32, "baseline_content_invalid"),
            observed_float4, int(baseline.get("observed_weight_milli")),
            int(baseline.get("observed_at")), identity.valid_from,
            _exact_hex(baseline.get("certificate_fingerprint"), 32, "baseline_certificate_invalid"),
        )
        if expected != _exact_hex(baseline.get("baseline_hash"), 32, "baseline_hash_invalid"):
            return False, "baseline_hash_invalid"
        signature = _exact_hex(baseline.get("signature"), 64, "baseline_signature_invalid")
        if not _verify_raw(identity.pubkey, expected, signature):
            return False, "baseline_signature_invalid"
        return True, None
    except (VerificationError, ValueError, TypeError):
        return False, "baseline_binding_invalid"


def _verify_provenance(provenance: dict[str, Any], identity: Identity) -> tuple[bool, str | None]:
    try:
        body = provenance.get("body")
        if not isinstance(body, dict):
            return False, "signed_body_missing"
        content_hash = _sha256(canonical_json(body).encode())
        if content_hash != _exact_hex(provenance.get("content_hash"), 32, "content_hash_invalid"):
            return False, "signed_body_content_hash_mismatch"
        if _sha256(identity.certificate.encode()).hex() != provenance.get("certificate_fingerprint"):
            return False, "signer_certificate_fingerprint_mismatch"
        signed_at = _integer(provenance.get("signed_at"), "provenance_time_invalid", 1)
        identity_valid, identity_reason = _verify_identity_epoch(identity, signed_at)
        if not identity_valid or provenance.get("signer_agent_id") != identity.agent_id \
                or provenance.get("signer_valid_from") != identity.valid_from:
            reason = "signer_revoked_before_evidence" \
                if identity_reason == "identity_revoked_before_signature" else identity_reason
            # The production owner reports a retained certificate/public-key
            # substitution as a row mismatch. Preserve that protocol-level
            # reason instead of leaking the helper's identity-epoch wording.
            if reason == "identity_epoch_mismatch":
                reason = "signer_certificate_row_mismatch"
            return False, reason or "signer_certificate_row_mismatch"
        previous_value = provenance.get("previous_mutation_hash")
        if provenance.get("is_genesis") != (previous_value is None):
            return False, "provenance_genesis_shape_invalid"
        request_form = int(provenance.get("request_signature_form", 1))
        signature_form = int(provenance.get("signature_form", 1))
        claims = provenance.get("signed_claims")
        if provenance.get("identity_tier") in {"T2", "T3"} and request_form != 4:
            return False, "elevated_provenance_requires_form4"
        if request_form == 4:
            if not isinstance(claims, dict):
                return False, "signed_chain_claim_invalid"
            previous_claim = claims.get("prev_chain_hash")
            if len(_b64u_decode(previous_claim, "signed_chain_claim_invalid")) != 32:
                return False, "signed_chain_claim_invalid"
            if provenance.get("identity_tier") == "T3" \
                    and claims.get("device_fp") != identity.device_fingerprint:
                return False, "signed_device_claim_mismatch"
        signature = _exact_hex(provenance.get("signature"), 64, "signature_missing")
        valid, reason = _verify_stored_signature(
            identity.pubkey, body, str(provenance.get("nonce", "")), signed_at,
            signature, signature_form=signature_form,
            request_signature_form=request_form,
            memory_originated_at=provenance.get("memory_originated_at"),
            method=provenance.get("signed_method"), path=provenance.get("signed_path"),
            claims=claims,
        )
        if not valid:
            return False, reason or "signature_invalid"
        previous = None if previous_value is None else _exact_hex(previous_value, 32, "previous_hash_invalid")
        parts = [content_hash]
        if previous is not None:
            parts.append(previous)
        parts.extend([str(provenance.get("nonce", "")).encode(), str(signed_at).encode()])
        if signature_form == 2:
            parts.append(str(provenance.get("memory_originated_at")).encode())
        expected_mutation = _sha256(b"".join(parts))
        if expected_mutation != _exact_hex(provenance.get("mutation_hash"), 32, "mutation_hash_invalid"):
            return False, "mutation_hash_mismatch"
        if provenance.get("event_type") != "REWEIGHT" or body.get("event_type") != "REWEIGHT":
            return False, "signed_body_event_type_mismatch"
        return True, None
    except (VerificationError, ValueError, TypeError):
        return False, "provenance_malformed_input"


def _order_projections(projections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_hash: dict[str, dict[str, Any]] = {}
    child: dict[str, dict[str, Any]] = {}
    genesis: list[dict[str, Any]] = []
    for projection in projections:
        current = str(projection.get("projection_hash", ""))
        previous = projection.get("previous_projection_hash")
        if current in by_hash or (previous is not None and previous in child):
            raise VerificationError("cognitive_projection_fork")
        by_hash[current] = projection
        if previous is None:
            genesis.append(projection)
        else:
            child[str(previous)] = projection
    if len(genesis) != 1:
        raise VerificationError("cognitive_projection_genesis_invalid")
    ordered = []
    visited = set()
    current: dict[str, Any] | None = genesis[0]
    while current is not None:
        digest = str(current.get("projection_hash", ""))
        if digest in visited:
            raise VerificationError("cognitive_projection_cycle")
        visited.add(digest)
        ordered.append(current)
        current = child.get(digest)
    if len(ordered) != len(projections):
        raise VerificationError("cognitive_projection_disconnected")
    return ordered


def _verify_memory(memory: dict[str, Any], master: dict[str, Any],
                   event_index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    memory_id = str(memory.get("memory_id", ""))
    projections = memory.get("projections")
    baseline = memory.get("baseline")
    if not isinstance(projections, list):
        raise VerificationError("portable_evidence_malformed")
    baseline_valid = None
    baseline_reason = None
    if baseline is not None:
        identity = _decode_identity(baseline.get("identity"), master)
        baseline_valid, baseline_reason = _verify_baseline(
            baseline, memory, identity, event_index.get(str(baseline.get("event_id"))),
        )
    if not projections:
        if baseline is not None:
            valid = bool(baseline_valid) and memory.get("retrieval_weight_float4") == baseline.get("observed_weight_float4")
            return _record(memory_id, "signed_initial_weight", valid, 0, 0,
                           None if valid else baseline_reason or "baseline_terminal_weight_mismatch")
        is_default = _exact_hex(memory.get("retrieval_weight_float4"), 4, "memory_weight_invalid") == _float4(1)
        return _record(memory_id, "default_empty_chain" if is_default else "unattested_initial_weight",
                       is_default, 0, 0, None if is_default else "unattested_initial_weight")
    try:
        ordered = _order_projections(projections)
    except VerificationError as exc:
        return _record(memory_id, "certified_chain", False, 0, 0, str(exc))
    previous_hash = None
    previous_milli = None
    signatures = 0
    for index, projection in enumerate(ordered):
        old_milli = projection.get("old_weight_milli")
        new_milli = projection.get("new_weight_milli")
        try:
            _integer(old_milli, "projection_display_invalid", 100, 3000)
            _integer(new_milli, "projection_display_invalid", 100, 3000)
            old_float = _exact_hex(projection.get("old_weight_float4"), 4, "projection_display_invalid")
            new_float = _exact_hex(projection.get("new_weight_float4"), 4, "projection_display_invalid")
        except VerificationError:
            return _record(memory_id, "certified_chain", False, index, signatures, "projection_display_invalid")
        if old_milli == new_milli or old_float != _float4(old_milli / 1000) \
                or new_float != _float4(new_milli / 1000):
            return _record(memory_id, "certified_chain", False, index, signatures, "projection_display_invalid")
        if previous_milli is not None and old_milli != previous_milli:
            return _record(memory_id, "certified_chain", False, index, signatures, "continuity_break")
        provenance = projection.get("provenance")
        if not isinstance(provenance, dict):
            return _record(memory_id, "certified_chain", False, index, signatures, "provenance_malformed_input")
        identity = _decode_identity(provenance.get("identity"), master)
        provenance_valid, provenance_reason = _verify_provenance(provenance, identity)
        body = provenance.get("body") if isinstance(provenance.get("body"), dict) else {}
        bound = (
            provenance.get("event_type") == "REWEIGHT"
            and provenance.get("binding_schema_version") == 2
            and provenance.get("signer_agent_id") == "housekeeper"
            and provenance.get("backfilled") is False
            and body.get("event_type") == "REWEIGHT"
            and body.get("company_id") == memory.get("company_id")
            and str(body.get("memory_id")) == memory_id
            and _js_round(float(body.get("old_weight")) * 1000) == old_milli
            and _js_round(float(body.get("new_weight")) * 1000) == new_milli
            and projection.get("company_id") == memory.get("company_id")
            and projection.get("memory_id") == memory_id
            and projection.get("provenance_mutation_hash") == provenance.get("mutation_hash")
        )
        if not provenance_valid or not bound:
            return _record(memory_id, "certified_chain", False, index, signatures,
                           f"provenance_{provenance_reason or 'event_type_invalid'}")
        provenance_hash = _exact_hex(projection.get("provenance_mutation_hash"), 32, "projection_hash_invalid")
        expected_projection = _projection_hash(memory_id, old_milli, new_milli, provenance_hash, previous_hash)
        if expected_projection != _exact_hex(projection.get("projection_hash"), 32, "projection_hash_invalid"):
            return _record(memory_id, "certified_chain", False, index, signatures, "projection_hash_invalid")
        expected_transition = _transition_hash(str(memory.get("company_id")), memory_id,
                                               old_milli, new_milli, provenance_hash)
        transition_signature = _exact_hex(projection.get("transition_signature"), 64, "transition_signature_invalid")
        if expected_transition != _exact_hex(projection.get("transition_hash"), 32, "transition_hash_invalid") \
                or not _verify_raw(identity.pubkey, expected_transition, transition_signature):
            return _record(memory_id, "certified_chain", False, index, signatures, "transition_signature_invalid")
        previous_hash = expected_projection
        previous_milli = new_milli
        signatures += 1
    if baseline is not None and (not baseline_valid or baseline.get("observed_weight_milli") != ordered[0].get("old_weight_milli")):
        return _record(memory_id, "certified_chain", False, len(ordered), signatures, "baseline_chain_anchor_invalid")
    if baseline is None and ordered[0].get("old_weight_milli") != 1000:
        return _record(memory_id, "certified_chain", False, len(ordered), signatures, "default_chain_anchor_invalid")
    terminal_valid = _exact_hex(memory.get("retrieval_weight_float4"), 4, "terminal_weight_mismatch") == _float4(previous_milli / 1000)
    return _record(memory_id, "certified_chain", terminal_valid, len(ordered), signatures,
                   None if terminal_valid else "terminal_weight_mismatch")


def _record(memory_id: str, status: str, ok: bool, chain_length: int,
            signatures: int, reason: str | None) -> dict[str, Any]:
    return {
        "memory_id": memory_id,
        "certification_status": status,
        "ok": ok,
        "chain_length": chain_length,
        "sigs_verified": signatures,
        "reason": reason,
    }


def _corpus_root(records: list[dict[str, Any]]) -> bytes:
    return _sha256(CORPUS_DOMAIN + canonical_json(records).encode())


def verify_bundle(bundle: Any) -> dict[str, Any]:
    """Verify one hostile cognitive-evidence bundle without runtime authority."""
    if not isinstance(bundle, dict):
        raise VerificationError("cognitive_evidence_bundle_invalid")
    expected = {"company_id", "event_streams", "format", "master_identity", "memories", "sql_records"}
    if set(bundle) != expected:
        raise VerificationError("cognitive_evidence_bundle_schema_invalid")
    format_record = bundle.get("format")
    if not isinstance(format_record, dict) or format_record != {
        "schema": SCHEMA,
        "version": 1,
        "authority": "descriptive_only",
        "binary_encoding": "lowercase_hex",
        "time_encoding": "unix_seconds",
    }:
        raise VerificationError("cognitive_evidence_bundle_schema_invalid")
    if not isinstance(bundle.get("event_streams"), list) or not isinstance(bundle.get("memories"), list) \
            or not isinstance(bundle.get("sql_records"), list):
        raise VerificationError("cognitive_evidence_bundle_schema_invalid")
    company = bundle.get("company_id")
    master = bundle.get("master_identity")
    if not isinstance(company, str) or not company.strip() or not isinstance(master, dict):
        raise VerificationError("cognitive_evidence_bundle_identity_invalid")
    fingerprint = str(master.get("fingerprint", ""))
    _exact_hex(fingerprint, 32, "cognitive_evidence_bundle_identity_invalid")
    actual_fingerprint = _sha256(_b64u_decode(str(master.get("public_key_b64u", "")), "master_key_invalid")).hex()
    if actual_fingerprint != fingerprint:
        raise VerificationError("cognitive_evidence_master_fingerprint_mismatch")
    canonical = canonical_json(bundle)

    event_results = []
    event_index: dict[str, dict[str, Any]] = {}
    for stream in bundle["event_streams"]:
        try:
            result, indexed = _verify_event_stream(stream, master, company)
            for event_id, event in indexed.items():
                if event_id in event_index:
                    raise VerificationError("cognitive_evidence_event_duplicate")
                event_index[event_id] = event
            event_results.append(result)
        except VerificationError as exc:
            event_results.append({
                "signer_agent_id": str(stream.get("signer_agent_id", "")) if isinstance(stream, dict) else "",
                "signer_valid_from": stream.get("signer_valid_from") if isinstance(stream, dict) else None,
                "event_count": len(stream.get("events", [])) if isinstance(stream, dict) and isinstance(stream.get("events"), list) else 0,
                "valid": False,
                "reason": str(exc),
            })

    records = []
    previous_memory_id = None
    for memory in bundle["memories"]:
        if not isinstance(memory, dict):
            raise VerificationError("cognitive_evidence_memory_order_invalid")
        memory_id = str(memory.get("memory_id", ""))
        if not memory_id or memory.get("company_id") != company \
                or (previous_memory_id is not None and memory_id <= previous_memory_id):
            raise VerificationError("cognitive_evidence_memory_order_invalid")
        previous_memory_id = memory_id
        _exact_hex(memory.get("content_hash"), 32, "cognitive_evidence_memory_content_invalid")
        retrieval_float = _float4_from_hex(memory.get("retrieval_weight_float4"), "cognitive_evidence_memory_weight_invalid")
        if _js_round(retrieval_float * 1000) != memory.get("retrieval_weight_milli"):
            raise VerificationError("cognitive_evidence_memory_weight_invalid")
        try:
            records.append(_verify_memory(memory, master, event_index))
        except Exception:
            records.append(_record(
                memory_id,
                "certified_chain" if memory.get("projections") else
                "signed_initial_weight" if memory.get("baseline") else "unattested_initial_weight",
                False, 0, 0, "portable_evidence_malformed",
            ))

    sql_rows = []
    for row in bundle["sql_records"]:
        if not isinstance(row, dict):
            raise VerificationError("cognitive_evidence_sql_record_invalid")
        sql_rows.append({
            "memory_id": row.get("memory_id"),
            "certification_status": row.get("certification_status"),
            "ok": row.get("ok") is True,
            "chain_length": _integer(row.get("chain_length"), "cognitive_evidence_sql_count_invalid", 0),
            "sigs_verified": _integer(row.get("signatures_verified"), "cognitive_evidence_sql_count_invalid", 0),
            "reason": row.get("reason"),
        })
    sql_by_id = {str(row["memory_id"]): row for row in sql_rows}
    parity = len(sql_by_id) == len(sql_rows) == len(records)
    if parity:
        for record in records:
            sql = sql_by_id.get(record["memory_id"])
            if sql != record:
                parity = False
                break
    proof_root = _corpus_root(records).hex()
    bundle_hash = _sha256(canonical.encode()).hex()
    all_streams_valid = all(result["valid"] for result in event_results)
    all_records_valid = all(record["ok"] for record in records)
    valid = all_streams_valid and all_records_valid and parity
    primary_reason = None
    if not all_streams_valid:
        primary_reason = next(result["reason"] for result in event_results if not result["valid"])
    elif not all_records_valid:
        primary_reason = next(record["reason"] for record in records if not record["ok"])
    elif not parity:
        primary_reason = "sql_portable_parity_mismatch"
    return {
        "verdict": "valid" if valid else "invalid",
        "schema": SCHEMA,
        "verifier_version": VERIFIER_VERSION,
        "primary_reason": primary_reason,
        "records": records,
        "sql_rows": sql_rows,
        "parity": parity,
        "proof_root": proof_root,
        "bundle_sha256": bundle_hash,
        "event_stream_results": event_results,
        "counts": {
            "event_streams": len(event_results),
            "events": sum(result["event_count"] for result in event_results),
            "memories": len(records),
            "projections": sum(len(memory.get("projections", [])) for memory in bundle["memories"]),
        },
    }


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("json_duplicate_key")
        result[key] = value
    return result


def parse_bundle(raw: bytes, maximum_bytes: int = MAX_BUNDLE_BYTES) -> dict[str, Any]:
    if len(raw) > maximum_bytes:
        raise VerificationError("bundle_size_limit")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                            parse_constant=lambda _: (_ for _ in ()).throw(VerificationError("json_non_finite")))
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("bundle_json_malformed") from exc
    canonical_json(parsed)
    if not isinstance(parsed, dict):
        raise VerificationError("cognitive_evidence_bundle_invalid")
    return parsed
