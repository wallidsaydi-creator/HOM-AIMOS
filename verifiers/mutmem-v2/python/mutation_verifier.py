"""Independent MutMem V2 mutation-outcome verifier."""

from __future__ import annotations

import re
from typing import Any

from crypto_kernel import (
    canonical_bytes,
    exact_base64url,
    exact_hash_bytes,
    framed_utf8,
    i64,
    sha256_hex,
    uuid_bytes,
    verify_ed25519,
    verify_payload_signature,
)
from recall_verifier import verify_recall_envelope


FAILURE_CODES = (
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
        + str(nonce).encode() + str(signed_ts).encode()
    )


def _witness_hash(body: dict) -> str:
    return sha256_hex(WITNESS_DOMAIN + canonical_bytes(body))


def _iso(value: Any) -> str:
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S") + f".{parsed.microsecond // 1000:03d}Z"


def _same_identity(proof: dict, housekeeper: dict) -> bool:
    return (
        proof.get("signer_agent_id") == "housekeeper"
        and _iso(proof.get("signer_valid_from")) == _iso(housekeeper.get("valid_from"))
        and proof.get("cert_fingerprint") == housekeeper.get("cert_fingerprint")
        and proof.get("signer_public_key_b64u") == housekeeper.get("public_key_b64u")
        and proof.get("signer_certificate") == housekeeper.get("certificate")
    )


def _verify_full_event(proof: dict, summary: dict, housekeeper: dict) -> bool:
    summary_id = summary.get("event_id") or summary.get("id")
    if (
        not isinstance(proof, dict) or proof.get("event_id") != summary_id
        or proof.get("operation") != summary.get("operation")
        or proof.get("parent_event_id") != summary.get("parent_event_id")
        or proof.get("mutation_hash") != summary.get("mutation_hash")
        or canonical_bytes(proof.get("metadata")) != canonical_bytes(summary.get("metadata"))
        or proof.get("proof_required") is not True or proof.get("ledger_version") != 1
        or not _same_identity(proof, housekeeper)
    ):
        return False
    body = proof.get("signed_body") or {}
    if (
        body.get("event_id") != proof.get("event_id")
        or body.get("company_id") != proof.get("company_id")
        or body.get("subject_agent_id") != proof.get("subject_agent_id")
        or body.get("signer_agent_id") != proof.get("signer_agent_id")
        or _iso(body.get("signer_valid_from")) != _iso(proof.get("signer_valid_from"))
        or body.get("cert_fingerprint") != proof.get("cert_fingerprint")
        or body.get("identity_tier") != proof.get("identity_tier")
        or body.get("authority_kind") != proof.get("authority_kind")
        or body.get("operation") != proof.get("operation") or body.get("key") != proof.get("key")
        or canonical_bytes(body.get("metadata")) != canonical_bytes(proof.get("metadata"))
        or body.get("parent_event_id") != proof.get("parent_event_id")
        or int(body.get("ledger_seq")) != int(proof.get("ledger_seq"))
        or body.get("prev_mutation_hash") != proof.get("prev_mutation_hash")
        or int(body.get("ts_signed")) != int(proof.get("ts_signed"))
        or int(__import__("datetime").datetime.fromisoformat(
            proof.get("timestamp").replace("Z", "+00:00")
        ).timestamp() * 1000) != int(proof.get("ts_signed")) * 1000
    ):
        return False
    content_hash = sha256_hex(canonical_bytes(body))
    if (
        proof.get("content_hash") != content_hash
        or proof.get("mutation_hash") != _event_mutation_hash(
            proof.get("prev_mutation_hash"), content_hash, proof.get("nonce"), proof.get("ts_signed")
        )
    ):
        return False
    return verify_payload_signature(
        housekeeper["public_key_b64u"], body, proof.get("nonce"),
        proof.get("ts_signed"), proof.get("signature_b64u"),
    )


def _verify_valence(proof: dict, summary: dict, bundle: dict, housekeeper: dict) -> bool:
    if (
        not isinstance(proof, dict) or proof.get("proof_required") is not True
        or not _same_identity(proof, housekeeper)
        or proof.get("row_hash") != summary.get("row_hash")
        or proof.get("reward_sign") != summary.get("reward_sign")
        or canonical_bytes(proof.get("body_json")) != canonical_bytes(summary.get("body_json"))
        or proof.get("memory_id") != bundle["outcome_evidence"]["memory_id"]
        or proof.get("company_id") != bundle.get("company_id")
    ):
        return False
    content_hash = sha256_hex(canonical_bytes(proof["body_json"]))
    pieces = [bytes.fromhex(content_hash)]
    if proof.get("prev_hash"):
        pieces.append(bytes.fromhex(proof["prev_hash"]))
    pieces.extend([str(proof.get("nonce")).encode(), str(proof.get("ts_signed")).encode()])
    row_hash = sha256_hex(b"".join(pieces))
    body = proof["body_json"]
    if (
        proof.get("content_hash") != content_hash or proof.get("row_hash") != row_hash
        or body.get("ts_signed") != proof.get("ts_signed")
        or body.get("cert_fingerprint") != proof.get("cert_fingerprint")
        or body.get("signer_agent_id") != proof.get("signer_agent_id")
        or _iso(body.get("signer_valid_from")) != _iso(proof.get("signer_valid_from"))
    ):
        return False
    return verify_payload_signature(
        housekeeper["public_key_b64u"], body, proof.get("nonce"),
        proof.get("ts_signed"), proof.get("signature_b64u"),
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
        or proof.get("backfilled") is not False or not _same_identity(identity_view, housekeeper)
    ):
        return False
    content_hash = sha256_hex(canonical_bytes(proof["body_json"]))
    pieces = [bytes.fromhex(content_hash)]
    if proof.get("prev_mutation_hash"):
        pieces.append(bytes.fromhex(proof["prev_mutation_hash"]))
    pieces.extend([str(proof.get("nonce")).encode(), str(proof.get("ts_signed")).encode()])
    if proof.get("sig_form_version") == 2:
        from datetime import datetime
        originated = int(datetime.fromisoformat(
            proof.get("memory_originated_at").replace("Z", "+00:00")
        ).timestamp())
        pieces.append(str(originated).encode())
    if (
        proof.get("content_hash") != content_hash
        or proof.get("mutation_hash") != sha256_hex(b"".join(pieces))
        or proof.get("sig_form_version") != 1 or proof.get("request_sig_form") != 1
    ):
        return False
    return verify_payload_signature(
        housekeeper["public_key_b64u"], proof["body_json"], proof.get("nonce"),
        proof.get("ts_signed"), proof.get("signature_b64u"),
    )


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
        or housekeeper is None
    ):
        fail("MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID")
    if not _verify_full_event(witness.get("outcome_event"), bundle["outcome_event"], housekeeper):
        fail("MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID")
    if not _verify_valence(
        witness.get("valence_evidence"), bundle["valence_evidence"], bundle, housekeeper
    ):
        fail("MUTATION_VALENCE_SIGNATURE_INVALID")
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
        if terminal_proof.get("kind") != "terminal_event" or not _verify_full_event(
            terminal_proof.get("event"), bundle["terminal"]["event"], housekeeper
        ):
            fail("MUTATION_TERMINAL_SIGNATURE_INVALID")
        count += 1
    return count, trust_result


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
    return event


def _validate_valence(bundle: dict, outcome: dict, event: dict) -> dict:
    valence = bundle.get("valence_evidence") or {}
    body = valence.get("body_json") or {}
    if (
        HEX32.fullmatch(str(valence.get("row_hash") or "")) is None
        or valence.get("reward_sign") not in (-1, 1)
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
    }
