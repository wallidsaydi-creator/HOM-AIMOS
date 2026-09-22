"""Independent MutMem V2 mutation-outcome verifier."""

from __future__ import annotations

import re
from typing import Any

from crypto_kernel import (
    canonical_bytes,
    event_payload_commitment,
    event_payload_body,
    exact_base64url,
    exact_hash_bytes,
    framed_utf8,
    i64,
    sha256_hex,
    uuid_bytes,
    verify_ed25519,
    verify_payload_signature,
    verify_event_payload_signature,
    retained_provenance_message, legacy_occurrence_reference, decode_certificate, verify_certificate,
    occurrence_commitment_v3, occurrence_signature_message_v3, parse_json_wire,
)
from recall_verifier import verify_recall_envelope


FAILURE_CODES = (
    "MUTATION_ANCESTRY_REQUIRED", "MUTATION_ANCESTRY_BINDING_INVALID", "MUTATION_ANCESTRY_BRIDGE_INVALID", "MUTATION_ANCESTRY_PARENT_INVALID",
    "MUTATION_BUNDLE_COMMITMENT_INVALID", "MUTATION_OUTCOME_SCHEMA_INVALID",
    "MUTATION_RECALL_BINDING_INVALID", "MUTATION_OUTCOME_EVENT_INVALID",
    "MUTATION_VALENCE_BINDING_INVALID", "MUTATION_TERMINAL_KIND_INVALID",
    "MUTATION_OBSERVATION_TERMINAL_INVALID", "MUTATION_NOOP_TERMINAL_INVALID",
    "MUTATION_TRANSITION_PROVENANCE_INVALID", "MUTATION_PROJECTION_BINDING_INVALID",
    "MUTATION_PROJECTION_HASH_INVALID", "MUTATION_TRANSITION_HASH_INVALID",
)
WITNESS_FAILURE_CODES = (
    "MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED",
    "MUTATION_CRYPTOGRAPHIC_WITNESS_COMMITMENT_INVALID",
    "MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID",
    "MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID", "MUTATION_VALENCE_SIGNATURE_INVALID",
    "MUTATION_TERMINAL_SIGNATURE_INVALID", "MUTATION_PROVENANCE_SIGNATURE_INVALID",
    "MUTATION_TRANSITION_SIGNATURE_INVALID",
)
DOMAIN = b"hom.aimos.mutmem-portable-mutation-evidence/v2\x00"
TRANSITION_DOMAIN = b"aimos.cognitive-transition/v2\x00"
PROJECTION_DOMAIN = b"aimos.cwc/v1\x00"
WITNESS_DOMAIN = b"hom.aimos.mutmem-portable-mutation-witness/v1\x00"
EVENT_LINK_DOMAIN = b"AIMOS-EVENT-LINK-v1\x00"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
TERMINALS = ("authorized_transition", "signed_noop", "occurrence_observation")


class MutMemMutationVerificationError(ValueError):
    def __init__(self, reason: str):
        super().__init__(f"mutmem_v2_mutation:{reason}")
        self.reason = reason


def fail(reason: str) -> None:
    if reason not in FAILURE_CODES and reason not in WITNESS_FAILURE_CODES:
        raise MutMemMutationVerificationError("UNDECLARED_FAILURE_CODE")
    raise MutMemMutationVerificationError(reason)


def _hash(value: Any, reason: str) -> str:
    normalized = str(value or "").lower()
    if HEX32.fullmatch(normalized) is None:
        fail(reason)
    return normalized


def mutation_bundle_hash(body: dict) -> str:
    return sha256_hex(DOMAIN + canonical_bytes(body))


def _projection_hash(projection: dict) -> str:
    return sha256_hex(
        PROJECTION_DOMAIN + uuid_bytes(projection["memory_id"])
        + i64(projection["old_weight_milli"]) + i64(projection["new_weight_milli"])
        + exact_hash_bytes(projection["provenance_mutation_hash"])
        + (
            exact_hash_bytes(projection["prev_projection_hash"])
            if projection.get("prev_projection_hash") else b"\x00" * 32
        )
    )


def _transition_hash(company_id: str, projection: dict) -> str:
    return sha256_hex(
        TRANSITION_DOMAIN + framed_utf8(company_id) + uuid_bytes(projection["memory_id"])
        + i64(projection["old_weight_milli"]) + i64(projection["new_weight_milli"])
        + exact_hash_bytes(projection["provenance_mutation_hash"])
    )


def _event_mutation_hash(previous: str, content: str, nonce: Any, signed_ts: Any) -> str:
    return sha256_hex(
        EVENT_LINK_DOMAIN + exact_hash_bytes(previous) + exact_hash_bytes(content)
        + str(nonce).encode() + canonical_bytes(signed_ts)
    )


def _witness_hash(body: dict) -> str:
    return sha256_hex(WITNESS_DOMAIN + canonical_bytes(body))


def _iso(value: Any) -> str:
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S") + f".{parsed.microsecond // 1000:03d}Z"


def _same_identity(proof: dict, housekeeper: dict) -> bool:
    try:
        same_epoch = _iso(proof.get("signer_valid_from")) == _iso(housekeeper.get("valid_from"))
        from datetime import datetime
        same_end = all(field not in proof or (
            isinstance(proof[field], str) and _iso(proof[field]) == _iso(housekeeper["valid_until"])
        ) for field in ("signer_valid_until", "agent_valid_until"))
        signed_ts = proof.get("ts_signed")
        in_interval = _safe_integer(signed_ts) and (
            datetime.fromisoformat(housekeeper["valid_from"].replace("Z", "+00:00")).timestamp()
            <= signed_ts <= datetime.fromisoformat(housekeeper["valid_until"].replace("Z", "+00:00")).timestamp()
        )
    except (ValueError, TypeError, OverflowError):
        return False
    return (
        proof.get("signer_agent_id") == "housekeeper"
        and isinstance(proof.get("signer_valid_from"), str)
        and same_epoch and same_end and in_interval
        and proof.get("identity_tier") == housekeeper.get("identity_tier")
        and proof.get("cert_fingerprint") == housekeeper.get("cert_fingerprint")
        and proof.get("signer_public_key_b64u") == housekeeper.get("public_key_b64u")
        and proof.get("signer_certificate") == housekeeper.get("certificate")
    )


def _same_timestamp(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return _iso(left) == _iso(right)
    except (ValueError, TypeError, OverflowError):
        return False


def _safe_integer(value: Any) -> bool:
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and abs(value) <= 9007199254740991 and float(value).is_integer())


def _same_repeated_fields(summary: dict, proof: dict, fields: tuple) -> bool:
    # Compare canonical typed values; Python equality alone equates True and 1.
    return all(
        field not in summary or (
            field in proof and canonical_bytes(summary[field]) == canonical_bytes(proof[field])
        ) for field in fields
    )


def _verify_full_event(proof: dict, summary: dict, housekeeper: dict) -> bool:
    if not isinstance(proof, dict):
        return False
    try:
        body = event_payload_body(proof)
        proof = {**proof, "signed_body": body,
                 "metadata": proof.get("metadata") if "metadata" in proof
                 else body.get("metadata") if "signed_body_bytes_b64u" in proof else None}
    except (ValueError, TypeError, AttributeError):
        return False
    summary_id = summary.get("event_id") or summary.get("id")
    if (
        not isinstance(proof, dict) or proof.get("event_id") != summary_id
        or not isinstance(proof.get("timestamp"), str)
        or any(field in summary and summary[field] != proof.get("event_id") for field in ("event_id", "id"))
        or ("id" in proof and proof["id"] != proof.get("event_id"))
        or not _safe_integer(proof.get("ledger_seq")) or proof["ledger_seq"] < 1
        or proof.get("operation") != summary.get("operation")
        or proof.get("parent_event_id") != summary.get("parent_event_id")
        or proof.get("mutation_hash") != summary.get("mutation_hash")
        or canonical_bytes(proof.get("metadata")) != canonical_bytes(summary.get("metadata"))
        or proof.get("proof_required") is not True or not _safe_integer(proof.get("ledger_version")) or proof.get("ledger_version") != 1
        or not _same_identity(proof, housekeeper)
        or not _same_repeated_fields(summary, proof, (
            "company_id", "subject_agent_id", "key", "timestamp", "ledger_seq",
            "signer_agent_id", "signer_valid_from", "cert_fingerprint", "identity_tier",
            "authority_kind", "ts_signed", "nonce", "content_hash", "prev_mutation_hash",
            "signature_b64u", "signed_body", "signed_body_bytes_b64u", "signer_valid_until",
            "signer_public_key_b64u", "signer_certificate",
        ))
    ):
        return False
    body = proof.get("signed_body") or {}
    try:
        timestamp_matches = __import__("datetime").datetime.fromisoformat(
            proof["timestamp"].replace("Z", "+00:00")
        ).timestamp() * 1000 == proof["ts_signed"] * 1000
    except (ValueError, TypeError, OverflowError):
        return False
    if (
        body.get("event_id") != proof.get("event_id")
        or not isinstance(body.get("signer_valid_from"), str)
        or body.get("company_id") != proof.get("company_id")
        or body.get("subject_agent_id") != proof.get("subject_agent_id")
        or body.get("signer_agent_id") != proof.get("signer_agent_id")
        or not _same_timestamp(body.get("signer_valid_from"), proof.get("signer_valid_from"))
        or body.get("cert_fingerprint") != proof.get("cert_fingerprint")
        or body.get("identity_tier") != proof.get("identity_tier")
        or body.get("authority_kind") != proof.get("authority_kind")
        or body.get("operation") != proof.get("operation") or body.get("key") != proof.get("key")
        or canonical_bytes(body.get("metadata")) != canonical_bytes(proof.get("metadata"))
        or body.get("parent_event_id") != proof.get("parent_event_id")
        or not _safe_integer(body.get("ledger_seq")) or body["ledger_seq"] != proof["ledger_seq"]
        or body.get("prev_mutation_hash") != proof.get("prev_mutation_hash")
        or not _safe_integer(body.get("ts_signed")) or body["ts_signed"] != proof["ts_signed"]
        or not timestamp_matches
    ):
        return False
    try:
        content_hash = event_payload_commitment(proof).hex()
    except (ValueError, TypeError, KeyError, OverflowError):
        return False
    if (
        proof.get("content_hash") != content_hash
        or proof.get("mutation_hash") != _event_mutation_hash(
            proof.get("prev_mutation_hash"), content_hash, proof.get("nonce"), proof.get("ts_signed")
        )
    ):
        return False
    return verify_event_payload_signature(proof, housekeeper["public_key_b64u"])


def _verify_valence(proof: dict, summary: dict, bundle: dict, housekeeper: dict) -> bool:
    if (
        not isinstance(proof, dict) or proof.get("proof_required") is not True
        or not _same_identity(proof, housekeeper)
        or proof.get("row_hash") != summary.get("row_hash")
        or proof.get("reward_sign") != summary.get("reward_sign")
        or canonical_bytes(proof.get("body_json")) != canonical_bytes(summary.get("body_json"))
        or proof.get("memory_id") != bundle["outcome_evidence"]["memory_id"]
        or proof.get("company_id") != bundle.get("company_id")
        or not _same_repeated_fields(summary, proof, (
            "company_id", "memory_id", "context_hash", "identity_tier", "ts_signed",
            "signer_agent_id", "signer_valid_from", "cert_fingerprint", "signature_b64u",
            "nonce", "content_hash", "prev_hash", "signer_valid_until",
            "signer_public_key_b64u", "signer_certificate",
        ))
    ):
        return False
    body = proof.get("body_json") or {}
    reward = body.get("reward_sign")
    if (
        body.get("event_type") != "VALENCE"
        or isinstance(reward, bool) or reward not in (-1, 1)
        or isinstance(proof.get("reward_sign"), bool) or reward != proof.get("reward_sign")
        or body.get("memory_id") != proof.get("memory_id")
        or body.get("company_id") != proof.get("company_id")
        or body.get("context_hash") != proof.get("context_hash")
        or body.get("identity_tier") != proof.get("identity_tier")
        or isinstance(proof.get("ts_signed"), bool)
        or not isinstance(proof.get("ts_signed"), (int, float))
        or not float(proof["ts_signed"]).is_integer()
        or abs(proof["ts_signed"]) > 9007199254740991
    ):
        return False
    content_hash = sha256_hex(canonical_bytes(proof["body_json"]))
    pieces = [bytes.fromhex(content_hash)]
    if proof.get("prev_hash"):
        pieces.append(bytes.fromhex(proof["prev_hash"]))
    pieces.extend([str(proof.get("nonce")).encode(), canonical_bytes(proof["ts_signed"])])
    row_hash = sha256_hex(b"".join(pieces))
    body = proof["body_json"]
    if (
        proof.get("content_hash") != content_hash or proof.get("row_hash") != row_hash
        or not _safe_integer(body.get("ts_signed")) or body.get("ts_signed") != proof.get("ts_signed")
        or body.get("cert_fingerprint") != proof.get("cert_fingerprint")
        or body.get("signer_agent_id") != proof.get("signer_agent_id")
        or not _same_timestamp(body.get("signer_valid_from"), proof.get("signer_valid_from"))
    ):
        return False
    return verify_payload_signature(
        housekeeper["public_key_b64u"], body, proof.get("nonce"),
        int(proof["ts_signed"]), proof.get("signature_b64u"),
    )


def _verify_provenance(proof: dict, summary: dict, housekeeper: dict) -> bool:
    identity_view = dict(proof or {})
    identity_view["signer_agent_id"] = identity_view.get("agent_id")
    identity_view["signer_valid_from"] = identity_view.get("agent_valid_from")
    if (
        not isinstance(proof, dict) or proof.get("provenance_id") != summary.get("provenance_id")
        or proof.get("memory_id") != summary.get("memory_id")
        or proof.get("event_type") != summary.get("event_type")
        or proof.get("mutation_hash") != summary.get("mutation_hash")
        or canonical_bytes(proof.get("body_json")) != canonical_bytes(summary.get("body_json"))
        or proof.get("event_type") != "REWEIGHT"
        or (proof.get("body_json") or {}).get("event_type") != "REWEIGHT"
        or ("is_genesis" in proof and proof["is_genesis"] is not False)
        or proof.get("backfilled") is not False or not _same_identity(identity_view, housekeeper)
        or not _same_repeated_fields(summary, proof, tuple(proof))
        or (proof.get("body_json") or {}).get("memory_id") != proof.get("memory_id")
        or (proof.get("body_json") or {}).get("company_id") != housekeeper.get("company_id")
        or ("ts_signed" in (proof.get("body_json") or {}) and (
            not _safe_integer(proof["body_json"]["ts_signed"])
            or proof["body_json"]["ts_signed"] != proof.get("ts_signed")
        ))
    ):
        return False
    content_hash = sha256_hex(canonical_bytes(proof["body_json"]))
    pieces = [bytes.fromhex(content_hash)]
    if proof.get("prev_mutation_hash"):
        pieces.append(bytes.fromhex(proof["prev_mutation_hash"]))
    pieces.extend([str(proof.get("nonce")).encode(), canonical_bytes(proof["ts_signed"])])
    if proof.get("sig_form_version") == 2:
        from datetime import datetime
        originated = int(datetime.fromisoformat(
            proof.get("memory_originated_at").replace("Z", "+00:00")
        ).timestamp())
        pieces.append(str(originated).encode())
    if (
        proof.get("content_hash") != content_hash
        or proof.get("mutation_hash") != sha256_hex(b"".join(pieces))
        or not _safe_integer(proof.get("sig_form_version")) or proof.get("sig_form_version") != 1
        or not _safe_integer(proof.get("request_sig_form")) or proof.get("request_sig_form") != 1
    ):
        return False
    return verify_payload_signature(
        housekeeper["public_key_b64u"], proof["body_json"], proof.get("nonce"),
        int(proof["ts_signed"]), proof.get("signature_b64u"),
    )


def _validate_ancestry(bundle: dict) -> dict | None:
    p = (bundle.get("terminal") or {}).get("reweight_provenance") or {}
    body = p.get("body_json") or {}
    if "ancestry_binding" not in body:
        return None
    b = body["ancestry_binding"]
    def ref(value, kinds, expected, names):
        return (isinstance(value, dict) and set(value) == set(names)
            and value.get("kind") in kinds
            and ((expected is None and value["kind"] == "genesis" and value["commitment_hex"] is None)
                or (isinstance(expected, str) and HEX32.fullmatch(expected) is not None
                    and value["kind"] != "genesis" and value["commitment_hex"] == expected)))
    projection = bundle.get("cognitive_projection") or {}
    if ("prev_mutation_hash" not in p or not isinstance(b, dict)
        or set(b) != {"schema", "native_predecessor", "projection_predecessor"}
        or b.get("schema") != "hom.aimos.cognitive-ancestry-binding/v1"
        or not ref(b.get("native_predecessor"), ("genesis", "mutation_hash", "occurrence_ref"),
            p["prev_mutation_hash"], ("kind", "commitment_hex", "provenance_id"))
        or not ref(b.get("projection_predecessor"), ("genesis", "projection_hash"),
            projection.get("prev_projection_hash"), ("kind", "commitment_hex"))):
        fail("MUTATION_ANCESTRY_BINDING_INVALID")
    parent_id = b["native_predecessor"]["provenance_id"]
    if ((p["prev_mutation_hash"] is None and parent_id is not None)
        or (p["prev_mutation_hash"] is not None and (not isinstance(parent_id, str) or UUID.fullmatch(parent_id) is None))):
        fail("MUTATION_ANCESTRY_BINDING_INVALID")
    return b


def _verify_ancestry_parent(parent, binding, bundle, trust_context, housekeeper) -> int:
    ref = binding["native_predecessor"]
    if ref["kind"] == "genesis":
        if parent is not None:
            fail("MUTATION_ANCESTRY_PARENT_INVALID")
        return 0
    try:
        from datetime import datetime
        if (not isinstance(parent, dict) or parent.get("provenance_id") != ref["provenance_id"]
            or parent.get("memory_id") != bundle["outcome_evidence"]["memory_id"]
            or parent["provenance_id"] == bundle["terminal"]["reweight_provenance"]["provenance_id"]
            or parent.get("body_json_encoding") != "hom-aimos/canonical-json/v1" or "body_json" in parent):
            raise ValueError("parent_binding")
        cert = decode_certificate(parent["signer_certificate"])["body"]
        fingerprint = sha256_hex(parent["signer_certificate"].encode())
        epoch = int(datetime.fromisoformat(parent["agent_valid_from"].replace("Z", "+00:00")).timestamp() * 1000)
        trust = next(o["body"] for o in trust_context["objects"] if o["kind"] == "trust_anchor")
        self_signed = cert["issuer"] == "housekeeper" and parent["signer_certificate"] == housekeeper["certificate"]
        if (not self_signed and cert["issuer"] not in ("aimos-master", trust_context["expected_master_fingerprint"])
            or cert["agent_id"] != parent["agent_id"] or fingerprint != parent["cert_fingerprint"]
            or not _safe_integer(epoch) or not _safe_integer(cert["valid_from"]) or epoch != cert["valid_from"] * 1000
            or _iso(parent["agent_valid_from"]) != parent["agent_valid_from"]
            or not verify_certificate(certificate=parent["signer_certificate"],
                authority_public_key=housekeeper["public_key_b64u"] if self_signed else trust["master_public_key_b64u"],
                expected_agent_id=parent["agent_id"], expected_subject_public_key=cert["pubkey"],
                at_unix_seconds=parent["ts_signed"])["valid"]):
            raise ValueError("parent_certificate")
        if not isinstance(parent.get("revocation_events"), list) or "identity_revoked_at" not in parent:
            raise ValueError("parent_revocation")
        if parent["identity_revoked_at"] is not None:
            revoked = datetime.fromisoformat(parent["identity_revoked_at"].replace("Z", "+00:00")).timestamp() * 1000
            if _iso(parent["identity_revoked_at"]) != parent["identity_revoked_at"] or revoked <= parent["ts_signed"] * 1000:
                raise ValueError("parent_revocation")
        for rev in parent["revocation_events"]:
            b = rev["signed_body"]
            prior = sha256_hex(canonical_bytes({"agent_id": parent["agent_id"],
                "agent_valid_from": parent["agent_valid_from"], "target_cert_hash": fingerprint}))
            if (b.get("schema") != "hom.aimos.agent-revocation/v1" or b.get("event_type") != "REVOKE_AGENT_IDENTITY"
                or b.get("agent_id") != parent["agent_id"] or b.get("agent_valid_from") != parent["agent_valid_from"]
                or b.get("target_cert_hash") != fingerprint or b.get("prior_identity_hash") != prior
                or b.get("master_fingerprint") != trust_context["expected_master_fingerprint"]
                or rev["content_hash"] != sha256_hex(canonical_bytes(b)) or not _safe_integer(rev["ts_signed"])
                or datetime.fromisoformat(b["revoked_at"].replace("Z", "+00:00")).timestamp() // 1 != rev["ts_signed"]
                or rev["ts_signed"] <= parent["ts_signed"]
                or not verify_payload_signature(trust["master_public_key_b64u"], b, rev["nonce"],
                    rev["ts_signed"], rev["signature_b64u"])
                or rev["mutation_hash"] != sha256_hex(b"aimos-agent-revocation-v1\x00" + exact_hash_bytes(prior)
                    + exact_hash_bytes(rev["content_hash"]) + exact_base64url(rev["signature_b64u"]))):
                raise ValueError("parent_revocation")
        if parent["sig_form_version"] == 3 and _safe_integer(parent["sig_form_version"]):
            body = parse_json_wire(exact_base64url(parent["body_json_bytes_b64u"]))
            commitment = occurrence_commitment_v3(body)
            message = occurrence_signature_message_v3(commitment)
            if (commitment != parent["mutation_hash"] or body["company_id"] != bundle["company_id"]
                or body["memory_id"] != parent["memory_id"] or body["occurrence_event_id"] != parent["provenance_id"]
                or body["agent_id"] != parent["agent_id"] or body["signer_valid_from_unix_ms"] != epoch
                or body["cert_fingerprint_hex"] != fingerprint or body["ts_signed_unix_seconds"] != parent["ts_signed"]
                or body["request_body_hash_hex"] != parent["content_hash"]
                or body["event_type"] != parent["event_type"] or body["identity_tier"] != parent["identity_tier"]
                or body["nonce_hex"] != parent["nonce"] or type(parent.get("is_genesis")) is not bool
                or parent["is_genesis"] != (parent["prev_mutation_hash"] is None)
                or (body["predecessor_commitment_hex"] if body["predecessor_present"] == 1 else None) != parent["prev_mutation_hash"]):
                raise ValueError("parent_occurrence")
        else:
            decoded = retained_provenance_message(parent)
            body, message = decoded["body"], decoded["message"]
            commitment = parent["mutation_hash"] if ref["kind"] == "mutation_hash" else legacy_occurrence_reference(parent, bundle["company_id"])
            if (body.get("memory_id") is not None and body["memory_id"] != parent["memory_id"]
                or body.get("company_id") is not None and body["company_id"] != bundle["company_id"]):
                raise ValueError("parent_scope")
        if ref["kind"] == "mutation_hash":
            commitment = parent["mutation_hash"]
        if commitment != ref["commitment_hex"] or not verify_ed25519(cert["pubkey"], message, parent["signature_b64u"]):
            raise ValueError("parent_signature")
        return 2 + len(parent["revocation_events"])
    except Exception:
        fail("MUTATION_ANCESTRY_PARENT_INVALID")


def _verify_ancestry_bridge(bundle, witness, trust_context, housekeeper, binding) -> int:
    event = witness.get("ancestry_event")
    p = bundle["cognitive_projection"]
    try:
        body = event_payload_body(event)
        metadata = body["metadata"]
        summary = {"event_id": event["event_id"], "operation": "cognitive_ancestry_bound",
            "parent_event_id": None, "mutation_hash": event["mutation_hash"], "metadata": metadata}
        if (not _verify_full_event(event, summary, housekeeper)
            or event["key"] != p["provenance_mutation_hash"] or event["authority_kind"] != "housekeeper_autonomous"
            or event["subject_agent_id"] != "housekeeper" or body["actor_agent_id"] is not None
            or body["actor_valid_from"] is not None or body["request_envelope_digest"] is not None
            or metadata.get("schema") != "hom.aimos.cognitive-ancestry-bridge/v1"
            or metadata.get("company_id") != bundle["company_id"] or metadata.get("memory_id") != p["memory_id"]
            or metadata.get("native_mutation_hash") != p["provenance_mutation_hash"]
            or metadata.get("projection_hash") != p["projection_hash"] or metadata.get("ancestry_binding") != binding
            or metadata.get("old_weight_milli") != p["old_weight_milli"] or metadata.get("new_weight_milli") != p["new_weight_milli"]
            or metadata.get("signer_agent_id") != housekeeper["agent_id"] or metadata.get("signer_valid_from") != housekeeper["valid_from"]
            or metadata.get("cert_fingerprint") != housekeeper["cert_fingerprint"]
            or metadata.get("attestation_kind") != "atomic_transition" or metadata.get("historical_origin_claimed") is not False
            or witness["terminal_proof"]["provenance"]["prev_mutation_hash"] != bundle["terminal"]["reweight_provenance"]["prev_mutation_hash"]):
            raise ValueError("bridge_binding")
    except Exception:
        fail("MUTATION_ANCESTRY_BRIDGE_INVALID")
    return 1 + _verify_ancestry_parent(witness.get("native_predecessor"), binding, bundle, trust_context, housekeeper)


def _verify_witness(
    bundle: dict, witness: dict, trust_context: dict, expected_master_fingerprint: str
) -> tuple[int, dict]:
    if witness is None or trust_context is None:
        fail("MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED")
    body = {key: value for key, value in witness.items() if key != "witness_sha256"}
    fmt = witness.get("format") or {}
    if (
        fmt.get("schema") != "hom.aimos.mutmem-portable-mutation-witness/v1"
        or fmt.get("version") != 1 or fmt.get("canonicalization") != "hom-aimos/canonical-json/v1"
        or fmt.get("hash") != "sha256" or fmt.get("signature") != "ed25519"
        or witness.get("witness_sha256") != _witness_hash(body)
    ):
        fail("MUTATION_CRYPTOGRAPHIC_WITNESS_COMMITMENT_INVALID")
    trust_result = verify_recall_envelope(
        trust_context, expected_master_fingerprint=expected_master_fingerprint,
        verify_cryptography=True,
    )
    housekeeper = next(
        (obj["body"] for obj in trust_context["objects"]
         if obj.get("kind") == "housekeeper_identity_epoch"), None,
    )
    if (
        witness.get("mutation_bundle_sha256") != bundle.get("bundle_sha256")
        or witness.get("trust_context_bundle_sha256") != trust_result["bundle_sha256"]
        or witness.get("expected_master_fingerprint") != expected_master_fingerprint
        or housekeeper is None or housekeeper.get("company_id") != bundle.get("company_id")
    ):
        fail("MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID")
    if not _verify_full_event(witness.get("outcome_event"), bundle["outcome_event"], housekeeper):
        fail("MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID")
    if witness["outcome_event"].get("company_id") != bundle.get("company_id"):
        fail("MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID")
    if not _verify_valence(
        witness.get("valence_evidence"), bundle["valence_evidence"], bundle, housekeeper
    ):
        fail("MUTATION_VALENCE_SIGNATURE_INVALID")
    outcome_metadata = event_payload_body(witness["outcome_event"])["metadata"]
    if "reward_sign" in outcome_metadata and (
        isinstance(outcome_metadata["reward_sign"], bool)
        or outcome_metadata["reward_sign"] != witness["valence_evidence"]["body_json"]["reward_sign"]
    ):
        fail("MUTATION_VALENCE_BINDING_INVALID")
    count = 2
    terminal_proof = witness.get("terminal_proof") or {}
    if bundle["terminal"]["kind"] == "authorized_transition":
        if terminal_proof.get("kind") != "reweight_provenance" or not _verify_provenance(
            terminal_proof.get("provenance"), bundle["terminal"]["reweight_provenance"], housekeeper
        ):
            fail("MUTATION_PROVENANCE_SIGNATURE_INVALID")
        projection = bundle["cognitive_projection"]
        if not verify_ed25519(
            housekeeper["public_key_b64u"], bytes.fromhex(projection["transition_hash"]),
            projection["transition_signature_b64u"],
        ):
            fail("MUTATION_TRANSITION_SIGNATURE_INVALID")
        count += 2
    else:
        if (terminal_proof.get("event") or {}).get("company_id") != bundle["company_id"]:
            fail("MUTATION_TERMINAL_SIGNATURE_INVALID")
        if terminal_proof.get("kind") != "terminal_event" or not _verify_full_event(
            terminal_proof.get("event"), bundle["terminal"]["event"], housekeeper
        ):
            fail("MUTATION_TERMINAL_SIGNATURE_INVALID")
        count += 1
    ancestry = _validate_ancestry(bundle)
    if ancestry is not None:
        count += _verify_ancestry_bridge(bundle, witness, trust_context, housekeeper, ancestry)
    return count, trust_result, ancestry is not None


def _validate_outcome(bundle: dict) -> dict:
    outcome = bundle.get("outcome_evidence") or {}
    recall = bundle.get("recall_receipt") or {}
    if (
        outcome.get("schema") != "hom.aimos.mutation-outcome-evidence/v2"
        or outcome.get("company_id") != bundle.get("company_id")
        or UUID.fullmatch(str(outcome.get("memory_id") or "")) is None
        or HEX32.fullmatch(str(outcome.get("live_content_hash") or "")) is None
        or HEX32.fullmatch(str(outcome.get("occurrence_ref") or "")) is None
        or outcome.get("target_scope") not in ("principal_state", "occurrence_observation")
        or UUID.fullmatch(str(outcome.get("recall_event_id") or "")) is None
        or HEX32.fullmatch(str(outcome.get("recall_event_mutation_hash") or "")) is None
        or HEX32.fullmatch(str(outcome.get("recall_merkle_root") or "")) is None
        or HEX32.fullmatch(str(outcome.get("security_closure_sha256") or "")) is None
        or UUID.fullmatch(str(outcome.get("outcome_id") or "")) is None
    ):
        fail("MUTATION_OUTCOME_SCHEMA_INVALID")
    if (
        recall.get("event_id") != outcome["recall_event_id"]
        or recall.get("mutation_hash") != outcome["recall_event_mutation_hash"]
        or recall.get("merkle_root") != outcome["recall_merkle_root"]
        or recall.get("security_closure_sha256") != outcome["security_closure_sha256"]
        or (recall.get("evidence") or {}).get("memory_id") != outcome["memory_id"]
        or (recall.get("evidence") or {}).get("live_content_hash") != outcome["live_content_hash"]
        or (recall.get("evidence") or {}).get("occurrence_ref") != outcome["occurrence_ref"]
    ):
        fail("MUTATION_RECALL_BINDING_INVALID")
    return outcome


def _validate_outcome_event(bundle: dict, outcome: dict) -> dict:
    event = bundle.get("outcome_event") or {}
    metadata = event.get("metadata") or {}
    if (
        UUID.fullmatch(str(event.get("event_id") or "")) is None
        or HEX32.fullmatch(str(event.get("mutation_hash") or "")) is None
        or event.get("operation") != "mutation_outcome_evidence_v2"
        or event.get("parent_event_id") != outcome["recall_event_id"]
        or metadata.get("target_scope") != outcome["target_scope"]
        or metadata.get("memory_id") != outcome["memory_id"]
        or metadata.get("live_content_hash") != outcome["live_content_hash"]
        or metadata.get("occurrence_ref") != outcome["occurrence_ref"]
    ):
        fail("MUTATION_OUTCOME_EVENT_INVALID")
    if not _same_repeated_fields(metadata, outcome, (
        "outcome_id", "recall_event_id", "recall_event_mutation_hash",
        "recall_merkle_root", "security_closure_sha256",
    )):
        fail("MUTATION_OUTCOME_EVENT_INVALID")
    return event


def _validate_valence(bundle: dict, outcome: dict, event: dict) -> dict:
    valence = bundle.get("valence_evidence") or {}
    body = valence.get("body_json") or {}
    if (
        HEX32.fullmatch(str(valence.get("row_hash") or "")) is None
        or isinstance(valence.get("reward_sign"), bool)
        or valence.get("reward_sign") not in (-1, 1)
        or ("reward_sign" in (event.get("metadata") or {}) and (
            isinstance(event["metadata"]["reward_sign"], bool)
            or event["metadata"]["reward_sign"] != valence["reward_sign"]
        ))
        or ("reward_sign" in body and (
            isinstance(body["reward_sign"], bool) or body["reward_sign"] != valence["reward_sign"]
        ))
        or body.get("evidence_schema") != "hom.aimos.mutation-outcome-evidence/v2"
        or body.get("target_scope") != outcome["target_scope"]
        or body.get("memory_id") != outcome["memory_id"]
        or body.get("target_live_content_hash") != outcome["live_content_hash"]
        or body.get("target_occurrence_ref") != outcome["occurrence_ref"]
        or body.get("recall_event_id") != outcome["recall_event_id"]
        or body.get("recall_event_mutation_hash") != outcome["recall_event_mutation_hash"]
        or body.get("recall_merkle_root") != outcome["recall_merkle_root"]
        or body.get("security_closure_sha256") != outcome["security_closure_sha256"]
        or body.get("outcome_id") != outcome["outcome_id"]
        or body.get("outcome_event_id") != event["event_id"]
        or body.get("outcome_event_mutation_hash") != event["mutation_hash"]
    ):
        fail("MUTATION_VALENCE_BINDING_INVALID")
    return valence


def _validate_terminal(bundle: dict, outcome: dict, event: dict, valence: dict) -> None:
    terminal = bundle.get("terminal") or {}
    kind = terminal.get("kind")
    if kind not in TERMINALS:
        fail("MUTATION_TERMINAL_KIND_INVALID")
    terminal_metadata = (terminal.get("event") or {}).get("metadata") or {}
    if "reward_sign" in terminal_metadata and (
        isinstance(terminal_metadata["reward_sign"], bool)
        or terminal_metadata["reward_sign"] != valence["reward_sign"]
    ):
        fail("MUTATION_VALENCE_BINDING_INVALID")
    if "context_hash" in terminal_metadata and terminal_metadata["context_hash"] != valence["body_json"].get("context_hash"):
        fail("MUTATION_VALENCE_BINDING_INVALID")
    if kind == "occurrence_observation":
        terminal_event = terminal.get("event") or {}
        metadata = terminal_event.get("metadata") or {}
        if (
            outcome["target_scope"] != "occurrence_observation"
            or bundle.get("cognitive_projection") is not None
            or terminal_event.get("operation") != "mutation_occurrence_observation_retained"
            or terminal_event.get("parent_event_id") != event["event_id"]
            or metadata.get("outcome_id") != outcome["outcome_id"]
            or metadata.get("occurrence_ref") != outcome["occurrence_ref"]
            or metadata.get("projection_appended") is not False
        ):
            fail("MUTATION_OBSERVATION_TERMINAL_INVALID")
        return
    if kind == "signed_noop":
        terminal_event = terminal.get("event") or {}
        metadata = terminal_event.get("metadata") or {}
        if (
            outcome["target_scope"] != "principal_state"
            or bundle.get("cognitive_projection") is not None
            or terminal_event.get("operation") != "cognitive_weight_unchanged"
            or metadata.get("valence_row_hash") != valence["row_hash"]
            or metadata.get("projection_appended") is not False
        ):
            fail("MUTATION_NOOP_TERMINAL_INVALID")
        return
    provenance = terminal.get("reweight_provenance") or {}
    projection = bundle.get("cognitive_projection") or {}
    if (
        outcome["target_scope"] != "principal_state" or provenance.get("event_type") != "REWEIGHT"
        or provenance.get("memory_id") != outcome["memory_id"]
        or (provenance.get("body_json") or {}).get("valence_row_hash") != valence["row_hash"]
        or HEX32.fullmatch(str(provenance.get("mutation_hash") or "")) is None
    ):
        fail("MUTATION_TRANSITION_PROVENANCE_INVALID")
    try:
        signature = exact_base64url(projection.get("transition_signature_b64u"))
    except Exception:
        signature = b""
    old_weight = projection.get("old_weight_milli")
    new_weight = projection.get("new_weight_milli")
    if (
        projection.get("memory_id") != outcome["memory_id"]
        or projection.get("provenance_mutation_hash") != provenance["mutation_hash"]
        or not isinstance(old_weight, int) or isinstance(old_weight, bool)
        or not isinstance(new_weight, int) or isinstance(new_weight, bool)
        or old_weight == new_weight or old_weight < 100 or old_weight > 3000
        or new_weight < 100 or new_weight > 3000
        or HEX32.fullmatch(str(projection.get("projection_hash") or "")) is None
        or HEX32.fullmatch(str(projection.get("transition_hash") or "")) is None
        or len(signature) != 64
    ):
        fail("MUTATION_PROJECTION_BINDING_INVALID")
    if projection["projection_hash"] != _projection_hash(projection):
        fail("MUTATION_PROJECTION_HASH_INVALID")
    if projection["transition_hash"] != _transition_hash(bundle["company_id"], projection):
        fail("MUTATION_TRANSITION_HASH_INVALID")


def verify_mutation_bundle(
    bundle: dict,
    *,
    witness: dict | None = None,
    trust_context: dict | None = None,
    expected_master_fingerprint: str | None = None,
    verify_cryptography: bool = False,
    require_ancestry: bool = False,
) -> dict:
    body = {key: value for key, value in (bundle or {}).items() if key != "bundle_sha256"}
    fmt = (bundle or {}).get("format") or {}
    if (
        fmt.get("schema") != "hom.aimos.mutmem-portable-mutation-evidence/v2"
        or fmt.get("version") != 2
        or fmt.get("native_outcome_schema") != "hom.aimos.mutation-outcome-evidence/v2"
        or fmt.get("canonicalization") != "hom-aimos/canonical-json/v1"
        or fmt.get("hash") != "sha256" or fmt.get("signature") != "ed25519"
        or bundle.get("bundle_sha256") != mutation_bundle_hash(body)
    ):
        fail("MUTATION_BUNDLE_COMMITMENT_INVALID")
    if _hash(bundle.get("recall_evidence_sha256"), "MUTATION_RECALL_BINDING_INVALID") != sha256_hex(
        canonical_bytes(bundle.get("recall_receipt"))
    ):
        fail("MUTATION_RECALL_BINDING_INVALID")
    outcome = _validate_outcome(bundle)
    event = _validate_outcome_event(bundle, outcome)
    valence = _validate_valence(bundle, outcome, event)
    _validate_terminal(bundle, outcome, event, valence)
    ancestry = _validate_ancestry(bundle)
    if require_ancestry and (ancestry is None or not verify_cryptography):
        fail("MUTATION_ANCESTRY_REQUIRED")
    crypto = _verify_witness(
        bundle, witness, trust_context, expected_master_fingerprint
    ) if verify_cryptography else None
    return {
        "schema": "hom.aimos.mutmem-independent-mutation-result/v2",
        "valid": True,
        "bundle_sha256": bundle["bundle_sha256"],
        "terminal_kind": bundle["terminal"]["kind"],
        "native_outcome_schema_preserved": True,
        "cryptographic_signatures_verified": crypto is not None,
        "external_trust_established": crypto is not None,
        "verified_signature_count": crypto[0] if crypto else 0,
        "witness_required": True,
        "ancestry_binding_authenticated": bool(crypto and crypto[2]),
        "historical_evidence_only": ancestry is None,
    }
