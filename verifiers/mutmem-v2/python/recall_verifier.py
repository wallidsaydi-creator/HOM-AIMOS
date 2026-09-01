"""Independent MutMem V2 recall-disclosure verifier."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from crypto_kernel import (
    canonical_bytes,
    canonical_json,
    exact_base64url,
    exact_hash_bytes,
    framed_utf8,
    occurrence_commitment_v3,
    recall_merkle_root,
    sha256,
    sha256_hex,
    u32,
    u64,
    verify_certificate,
    verify_occurrence_signature_v3,
    verify_payload_signature,
    verify_request_context_signature,
)


SCHEMAS = {
    "trust_anchor": "hom.aimos.mutmem-trust-anchor/v2",
    "actor_identity_epoch": "hom.aimos.mutmem-actor-identity-epoch/v2",
    "actor_revocation_state": "hom.aimos.mutmem-actor-revocation-state/v2",
    "housekeeper_identity_epoch": "hom.aimos.mutmem-housekeeper-identity-epoch/v2",
    "housekeeper_revocation_state": "hom.aimos.mutmem-housekeeper-revocation-state/v2",
    "effective_recall_grant": "hom.aimos.mutmem-effective-recall-grant/v2",
    "request_envelope": "hom.aimos.mutmem-request-envelope/v2",
    "request_receipt": "hom.aimos.mutmem-request-receipt/v2",
    "content_state_projection": "hom.aimos.mutmem-content-state-projection/v2",
    "epistemic_recall_decision": "hom.aimos.mutmem-epistemic-recall-decision/v2",
    "final_security_closure": "hom.aimos.mutmem-final-security-closure/v2",
    "return_projection": "hom-aimos/native-recall-return-projection/v1",
    "native_recall_receipt": "hom.aimos.mutmem-native-recall-receipt/v2",
    "memory_state": "hom.aimos.mutmem-memory-state/v2",
    "provenance_chain": "hom.aimos.mutmem-provenance-chain/v2",
    "occurrence": "hom.aimos.mutmem-occurrence-evidence/v2",
    "epistemic_projection": "hom.aimos.mutmem-epistemic-projection/v2",
    "receipt_evidence": "hom.aimos.mutmem-recall-evidence-entry/v2",
}

STRUCTURAL_FAILURE_CODES = (
    "ENVELOPE_COMMITMENT_INVALID", "OBJECT_SCHEMA_INVALID", "TRUST_ROOT_MISMATCH",
    "TRUST_ANCHOR_KEY_MISMATCH", "IDENTITY_SCOPE_MISMATCH",
    "IDENTITY_CERTIFICATE_BINDING_INVALID", "IDENTITY_EPOCH_INVALID",
    "REVOCATION_STATE_INVALID", "HOUSEKEEPER_IDENTITY_INVALID",
    "HOUSEKEEPER_REVOCATION_STATE_INVALID", "HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID",
    "GRANT_SCOPE_MISMATCH", "GRANT_NOT_EFFECTIVE", "GRANT_COMMITMENT_INVALID",
    "REQUEST_CONTEXT_INVALID", "REQUEST_BODY_HASH_MISMATCH", "COMMAND_HASH_MISMATCH",
    "REQUEST_RECEIPT_BINDING_INVALID", "REQUEST_RECEIPT_COMMITMENT_INVALID",
    "AUTHORITY_MUTATION_BINDING_INVALID", "DECISION_HASH_MALFORMED",
    "CONTENT_STATE_BINDING_INVALID", "EPISTEMIC_BINDING_INVALID",
    "SECURITY_CLOSURE_BINDING_INVALID", "RETURN_PROJECTION_BINDING_INVALID",
    "RESULT_CARDINALITY_INVALID", "RESULT_IDENTITY_BINDING_INVALID",
    "PROVENANCE_BINDING_INVALID", "OCCURRENCE_BINDING_INVALID",
    "OCCURRENCE_NATIVE_BODY_INVALID", "EPISTEMIC_PROJECTION_BINDING_INVALID",
    "RECEIPT_EVIDENCE_BINDING_INVALID", "MERKLE_ENTRY_BINDING_INVALID",
    "MERKLE_ROOT_MISMATCH", "EVENT_RECEIPT_BINDING_INVALID",
    "EVENT_RECEIPT_COMMITMENT_INVALID", "REVOCATION_EVENT_BINDING_INVALID",
)
CRYPTOGRAPHIC_FAILURE_CODES = (
    "EXPECTED_TRUST_ANCHOR_REQUIRED", "ACTOR_CERTIFICATE_SIGNATURE_INVALID",
    "HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID", "MASTER_GRANT_SIGNATURE_INVALID",
    "ACTOR_REQUEST_SIGNATURE_INVALID", "HOUSEKEEPER_EVENT_SIGNATURE_INVALID",
    "HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID",
)
SINGLETON_KINDS = (
    "trust_anchor", "actor_identity_epoch", "actor_revocation_state",
    "housekeeper_identity_epoch", "housekeeper_revocation_state",
    "effective_recall_grant", "request_envelope", "request_receipt",
    "content_state_projection", "epistemic_recall_decision", "final_security_closure",
    "return_projection", "native_recall_receipt",
)
RESULT_KINDS = (
    "memory_state", "provenance_chain", "occurrence",
    "epistemic_projection", "receipt_evidence",
)
HEX32 = __import__("re").compile(r"^[0-9a-f]{64}$")
UUID = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    __import__("re").IGNORECASE,
)
DATA_CLASSES = ("public", "internal", "confidential", "restricted")
RETURN_PATHS = {
    "identifier_exact", "post_compaction_handoff", "semantic_cache",
    "adaptive_early_exit", "normal_recall",
}
OBJECT_DOMAIN = b"hom.aimos.mutmem-portable-object/v2\x00"
BUNDLE_DOMAIN = b"hom.aimos.mutmem-portable-evidence/v2\x00"
RECALL_AUTHORIZATION_DOMAIN = b"aimos-recall-authorization-v1\x00"
REQUEST_RECEIPT_DOMAIN = b"aimos-request-receipt-v1\x00"
EVENT_LINK_DOMAIN = b"AIMOS-EVENT-LINK-v1\x00"


class MutMemRecallVerificationError(ValueError):
    def __init__(self, reason: str):
        super().__init__(f"mutmem_v2_recall:{reason}")
        self.reason = reason


def fail(reason: str) -> None:
    if reason not in STRUCTURAL_FAILURE_CODES and reason not in CRYPTOGRAPHIC_FAILURE_CODES:
        raise MutMemRecallVerificationError("UNDECLARED_FAILURE_CODE")
    raise MutMemRecallVerificationError(reason)


def _string(value: Any) -> str:
    return "" if value is None else str(value)


def _equal(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def _without_schema(value: dict) -> dict:
    return {key: item for key, item in value.items() if key != "schema"}


def _hash(value: Any, reason: str = "DECISION_HASH_MALFORMED") -> str:
    normalized = _string(value).lower()
    if HEX32.fullmatch(normalized) is None:
        fail(reason)
    return normalized


def _iso(value: Any, reason: str) -> str:
    try:
        text = _string(value)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
        milliseconds = parsed.microsecond // 1000
        return parsed.strftime("%Y-%m-%dT%H:%M:%S") + f".{milliseconds:03d}Z"
    except Exception:
        fail(reason)


def _unix_seconds(value: Any, reason: str) -> int:
    try:
        parsed = datetime.fromisoformat(_iso(value, reason).replace("Z", "+00:00"))
        return int(parsed.timestamp())
    except Exception:
        fail(reason)


def _signature(value: Any, reason: str) -> bytes:
    try:
        decoded = exact_base64url(value, reason)
        if len(decoded) != 64:
            fail(reason)
        return decoded
    except Exception:
        fail(reason)


def _canonical_sha(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def _recall_authorization_mutation_hash(
    *, previous_mutation_hash: str | None, content_hash: str, nonce: Any, signed_ts: Any
) -> str:
    return sha256_hex(
        RECALL_AUTHORIZATION_DOMAIN
        + (b"\x00" * 32 if previous_mutation_hash is None else exact_hash_bytes(previous_mutation_hash))
        + exact_hash_bytes(content_hash)
        + _string(nonce).encode()
        + _string(signed_ts).encode()
    )


def _request_receipt_mutation_hash(
    *, previous_mutation_hash: str | None, request_hash: str, claims_hash: str | None,
    signature: str, method: Any, path: Any, nonce: Any, signed_ts: Any,
) -> str:
    return sha256_hex(
        REQUEST_RECEIPT_DOMAIN
        + (b"\x00" * 32 if previous_mutation_hash is None else exact_hash_bytes(previous_mutation_hash))
        + exact_hash_bytes(request_hash)
        + (b"\x00" * 32 if claims_hash is None else exact_hash_bytes(claims_hash))
        + _signature(signature, "REQUEST_RECEIPT_COMMITMENT_INVALID")
        + _string(method).encode() + _string(path).encode()
        + _string(nonce).encode() + _string(signed_ts).encode()
    )


def _event_mutation_hash(previous: str, content: str, nonce: Any, signed_ts: Any) -> str:
    return sha256_hex(
        EVENT_LINK_DOMAIN + exact_hash_bytes(previous) + exact_hash_bytes(content)
        + _string(nonce).encode() + _string(signed_ts).encode()
    )


def _object_hash(obj: dict) -> str:
    body_bytes = canonical_bytes(obj["body"])
    if len(body_bytes) > 1024 * 1024:
        fail("ENVELOPE_COMMITMENT_INVALID")
    return sha256_hex(
        OBJECT_DOMAIN + framed_utf8(obj["kind"]) + framed_utf8(obj["schema"])
        + u32(len(body_bytes)) + body_bytes
    )


def _reconstruct_envelope(envelope: dict) -> dict:
    try:
        result_count = envelope.get("result_count")
        if (
            not isinstance(envelope, dict) or not isinstance(envelope.get("objects"), list)
            or not isinstance(result_count, int) or isinstance(result_count, bool)
            or result_count < 0 or result_count > 200
        ):
            fail("ENVELOPE_COMMITMENT_INVALID")
        if len(envelope["objects"]) != 13 + 5 * result_count:
            fail("ENVELOPE_COMMITMENT_INVALID")
        singletons: dict[str, dict] = {}
        results: list[dict[str, dict]] = [{} for _ in range(result_count)]
        subjects: dict[int, str] = {}
        expected_keys = {
            "ordinal", "kind", "schema", "subject_id", "result_ordinal", "body_sha256", "body"
        }
        for obj in envelope["objects"]:
            kind = obj.get("kind") if isinstance(obj, dict) else None
            if (
                not isinstance(obj, dict) or set(obj) != expected_keys
                or kind not in SINGLETON_KINDS + RESULT_KINDS
                or not isinstance(obj.get("body"), dict)
                or obj["body"].get("schema") != obj.get("schema")
                or obj.get("body_sha256") != _object_hash(obj)
            ):
                fail("ENVELOPE_COMMITMENT_INVALID")
            if kind in SINGLETON_KINDS:
                if obj["subject_id"] is not None or obj["result_ordinal"] is not None or kind in singletons:
                    fail("ENVELOPE_COMMITMENT_INVALID")
                singletons[kind] = obj
            else:
                ordinal = obj["result_ordinal"]
                subject = _string(obj["subject_id"]).lower()
                if (
                    not isinstance(ordinal, int) or isinstance(ordinal, bool)
                    or ordinal < 0 or ordinal >= result_count
                    or UUID.fullmatch(subject) is None or kind in results[ordinal]
                    or (ordinal in subjects and subjects[ordinal] != subject)
                ):
                    fail("ENVELOPE_COMMITMENT_INVALID")
                subjects[ordinal] = subject
                results[ordinal][kind] = obj
        if any(kind not in singletons for kind in SINGLETON_KINDS) or any(
            any(kind not in group for kind in RESULT_KINDS) for group in results
        ):
            fail("ENVELOPE_COMMITMENT_INVALID")
        ordered = [singletons[kind] for kind in SINGLETON_KINDS]
        ordered.extend(obj for group in results for obj in (group[kind] for kind in RESULT_KINDS))
        if (
            len(ordered) != 13 + 5 * result_count
            or len(ordered) != envelope.get("object_count")
            or any(obj.get("ordinal") != ordinal for ordinal, obj in enumerate(ordered))
        ):
            fail("ENVELOPE_COMMITMENT_INVALID")
        root = recall_merkle_root([
            {
                "ordinal": obj["ordinal"], "kind": obj["kind"], "schema": obj["schema"],
                "subject_id": obj["subject_id"], "result_ordinal": obj["result_ordinal"],
                "body_sha256": obj["body_sha256"],
            }
            for obj in ordered
        ]).hex()
        fingerprint = _string(envelope.get("expected_master_fingerprint")).lower()
        if HEX32.fullmatch(fingerprint) is None:
            fail("ENVELOPE_COMMITMENT_INVALID")
        bundle_hash = sha256_hex(
            BUNDLE_DOMAIN + framed_utf8(envelope.get("bundle_id"))
            + framed_utf8(envelope.get("company_id")) + bytes.fromhex(fingerprint)
            + u64(result_count) + bytes.fromhex(root)
        )
        fmt = envelope.get("format") or {}
        if (
            fmt.get("schema") != "hom.aimos.mutmem-portable-evidence/v2"
            or fmt.get("version") != 2 or fmt.get("profile") != "recall_disclosure"
            or fmt.get("canonicalization") != "hom-aimos/canonical-json/v1"
            or fmt.get("hash") != "sha256" or fmt.get("signature") != "ed25519"
            or fmt.get("trust_anchor_mode") != "external_expected_master_fingerprint_required"
            or fmt.get("native_receipt_schema")
                != "hom-aimos/recall-merkle/v3-epistemic-and-security-closure"
            or envelope.get("object_root_sha256") != root
            or envelope.get("bundle_sha256") != bundle_hash
        ):
            fail("ENVELOPE_COMMITMENT_INVALID")
        return {
            "envelope": envelope, "singletons": singletons, "results": results,
            "object_root": root, "bundle_hash": bundle_hash,
        }
    except MutMemRecallVerificationError:
        raise
    except Exception:
        fail("ENVELOPE_COMMITMENT_INVALID")


def _require_schemas(state: dict) -> None:
    for obj in state["envelope"]["objects"]:
        if obj["schema"] != SCHEMAS.get(obj["kind"]) or obj["body"].get("schema") != obj["schema"]:
            fail("OBJECT_SCHEMA_INVALID")


def _validate_authority(state: dict) -> dict:
    get = lambda kind: state["singletons"][kind]["body"]
    trust = get("trust_anchor")
    identity = get("actor_identity_epoch")
    revocation = get("actor_revocation_state")
    hk_identity = get("housekeeper_identity_epoch")
    hk_revocation = get("housekeeper_revocation_state")
    grant = get("effective_recall_grant")
    request = get("request_envelope")
    receipt = get("request_receipt")
    native = get("native_recall_receipt")
    if _hash(trust.get("master_fingerprint")) != state["envelope"]["expected_master_fingerprint"]:
        fail("TRUST_ROOT_MISMATCH")
    try:
        master_bytes = exact_base64url(trust.get("master_public_key_b64u"))
    except Exception:
        fail("TRUST_ANCHOR_KEY_MISMATCH")
    if sha256_hex(master_bytes) != trust["master_fingerprint"]:
        fail("TRUST_ANCHOR_KEY_MISMATCH")
    agent_id = _string(identity.get("agent_id"))
    valid_from = _iso(identity.get("valid_from"), "IDENTITY_SCOPE_MISMATCH")
    fingerprint = _hash(identity.get("cert_fingerprint"), "IDENTITY_SCOPE_MISMATCH")
    if (
        not identity.get("certificate") or not identity.get("public_key_b64u")
        or sha256_hex(_string(identity["certificate"]).encode()) != fingerprint
    ):
        fail("IDENTITY_CERTIFICATE_BINDING_INVALID")
    company = state["envelope"]["company_id"]
    if (
        not agent_id or identity.get("company_id") != company
        or request.get("company_id") != company or request.get("actor_agent_id") != agent_id
        or _iso(request.get("actor_valid_from"), "IDENTITY_SCOPE_MISMATCH") != valid_from
        or request.get("cert_fingerprint") != fingerprint
        or receipt.get("company_id") != company or receipt.get("actor_agent_id") != agent_id
        or _iso(receipt.get("actor_valid_from"), "IDENTITY_SCOPE_MISMATCH") != valid_from
        or receipt.get("cert_fingerprint") != fingerprint
    ):
        fail("IDENTITY_SCOPE_MISMATCH")
    hk_valid_from = _iso(hk_identity.get("valid_from"), "HOUSEKEEPER_IDENTITY_INVALID")
    hk_fingerprint = _hash(hk_identity.get("cert_fingerprint"), "HOUSEKEEPER_IDENTITY_INVALID")
    if (
        hk_identity.get("company_id") != company or hk_identity.get("agent_id") != "housekeeper"
        or not hk_identity.get("certificate") or not hk_identity.get("public_key_b64u")
        or sha256_hex(_string(hk_identity["certificate"]).encode()) != hk_fingerprint
    ):
        fail("HOUSEKEEPER_IDENTITY_INVALID")
    if agent_id == "housekeeper" and (
        identity.get("identity_tier") not in ("T1", "T1_SYSTEM_SELF")
        or valid_from != hk_valid_from or fingerprint != hk_fingerprint
        or identity.get("certificate") != hk_identity.get("certificate")
        or identity.get("public_key_b64u") != hk_identity.get("public_key_b64u")
    ):
        fail("HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID")
    request_ts = request.get("ts_signed")
    if (
        not isinstance(request_ts, int) or isinstance(request_ts, bool)
        or request_ts < _unix_seconds(valid_from, "IDENTITY_EPOCH_INVALID")
        or request_ts > _unix_seconds(identity.get("valid_until"), "IDENTITY_EPOCH_INVALID")
    ):
        fail("IDENTITY_EPOCH_INVALID")
    evaluated = revocation.get("evaluated_at_unix_seconds")
    if (
        revocation.get("company_id") != company or revocation.get("agent_id") != agent_id
        or _iso(revocation.get("valid_from"), "REVOCATION_STATE_INVALID") != valid_from
        or revocation.get("revoked") is not False or not isinstance(evaluated, int)
        or isinstance(evaluated, bool) or evaluated < request_ts
    ):
        fail("REVOCATION_STATE_INVALID")
    hk_evaluated = hk_revocation.get("evaluated_at_unix_seconds")
    if (
        hk_revocation.get("company_id") != company
        or hk_revocation.get("agent_id") != "housekeeper"
        or _iso(hk_revocation.get("valid_from"), "HOUSEKEEPER_REVOCATION_STATE_INVALID")
            != hk_valid_from
        or hk_revocation.get("revoked") is not False or not isinstance(hk_evaluated, int)
        or isinstance(hk_evaluated, bool)
    ):
        fail("HOUSEKEEPER_REVOCATION_STATE_INVALID")
    clearance = grant.get("clearance_ceiling")
    requested_clearance = (
        clearance if request.get("requested_clearance_level") is None
        else request.get("requested_clearance_level")
    )
    data_index = DATA_CLASSES.index(grant.get("data_class_ceiling")) \
        if grant.get("data_class_ceiling") in DATA_CLASSES else -1
    if (
        grant.get("company_id") != company or grant.get("subject_agent_id") != agent_id
        or _iso(grant.get("subject_valid_from"), "GRANT_SCOPE_MISMATCH") != valid_from
        or grant.get("master_fingerprint") != state["envelope"]["expected_master_fingerprint"]
        or not isinstance(clearance, int) or isinstance(clearance, bool) or clearance < 0 or clearance > 12
        or not isinstance(requested_clearance, int) or isinstance(requested_clearance, bool)
        or requested_clearance < 0 or requested_clearance > clearance or data_index < 0
    ):
        fail("GRANT_SCOPE_MISMATCH")
    requested_class = request.get("requested_data_class")
    if grant.get("allowed") is not True or (
        requested_class is not None
        and (requested_class not in DATA_CLASSES or DATA_CLASSES.index(requested_class) > data_index)
    ):
        fail("GRANT_NOT_EFFECTIVE")
    if grant.get("authority_kind") == "master_signed_recall_grant":
        body = grant.get("signed_body") or {}
        if (
            agent_id == "housekeeper" or body.get("schema") != "hom.aimos.recall-authorization/v1"
            or body.get("company_id") != grant.get("company_id")
            or body.get("subject_agent_id") != grant.get("subject_agent_id")
            or _iso(body.get("subject_valid_from"), "GRANT_COMMITMENT_INVALID") != valid_from
            or bool(body.get("allowed")) != grant.get("allowed")
            or body.get("clearance_ceiling") != clearance
            or body.get("data_class_ceiling") != grant.get("data_class_ceiling")
            or body.get("master_fingerprint") != grant.get("master_fingerprint")
            or _canonical_sha(body) != grant.get("content_hash")
            or _recall_authorization_mutation_hash(
                previous_mutation_hash=grant.get("prev_mutation_hash"),
                content_hash=grant.get("content_hash"), nonce=grant.get("nonce"),
                signed_ts=grant.get("ts_signed"),
            ) != grant.get("mutation_hash")
        ):
            fail("GRANT_COMMITMENT_INVALID")
        _signature(grant.get("signature_b64u"), "GRANT_COMMITMENT_INVALID")
    elif grant.get("authority_kind") == "housekeeper_system_principal":
        system = grant.get("system_principal_body") or {}
        forbidden = (
            "signed_body", "content_hash", "prev_mutation_hash", "ts_signed", "nonce", "signature_b64u"
        )
        canonical_system = {
            "kind": "housekeeper_system_principal", "company_id": system.get("company_id"),
            "agent_id": system.get("agent_id"),
            "valid_from": _iso(system.get("valid_from"), "HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID"),
        }
        if (
            agent_id != "housekeeper" or any(field in grant for field in forbidden)
            or system.get("kind") != "housekeeper_system_principal"
            or system.get("company_id") != company or system.get("agent_id") != "housekeeper"
            or canonical_system["valid_from"] != valid_from or clearance != 12
            or grant.get("data_class_ceiling") != "restricted"
            or grant.get("mutation_hash") != _canonical_sha(canonical_system)
        ):
            fail("HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID")
    else:
        fail("GRANT_COMMITMENT_INVALID")
    if (
        request.get("request_sig_form") != 3 or request.get("signed_method") != "POST"
        or request.get("signed_path") != "/aimos/recall" or not _string(request.get("nonce"))
        or not isinstance(request.get("request_body"), dict)
    ):
        fail("REQUEST_CONTEXT_INVALID")
    _signature(request.get("signature_b64u"), "REQUEST_CONTEXT_INVALID")
    request_hash = _canonical_sha(request["request_body"])
    if request.get("request_body_hash") != request_hash or request.get("outer_request_hash") != request_hash:
        fail("REQUEST_BODY_HASH_MISMATCH")
    if not isinstance(request.get("normalized_command"), dict) or _canonical_sha(
        request["normalized_command"]
    ) != request.get("command_hash"):
        fail("COMMAND_HASH_MISMATCH")
    receipt_id = _string(receipt.get("request_receipt_id"))
    if (
        UUID.fullmatch(receipt_id) is None or receipt.get("request_sig_form") != request.get("request_sig_form")
        or receipt.get("signed_method") != request.get("signed_method")
        or receipt.get("signed_path") != request.get("signed_path")
        or receipt.get("ts_signed") != request_ts or receipt.get("nonce") != request.get("nonce")
        or receipt.get("request_hash") != request_hash
        or native.get("request_receipt_id") != receipt_id
        or native.get("request_receipt_mutation_hash") != receipt.get("mutation_hash")
    ):
        fail("REQUEST_RECEIPT_BINDING_INVALID")
    claims_hash = None if receipt.get("signed_claims") is None else _canonical_sha(receipt["signed_claims"])
    if (
        receipt.get("signed_claims_hash") != claims_hash
        or receipt.get("signature_b64u") != request.get("signature_b64u")
        or _request_receipt_mutation_hash(
            previous_mutation_hash=receipt.get("prev_mutation_hash"),
            request_hash=receipt.get("request_hash"), claims_hash=claims_hash,
            signature=receipt.get("signature_b64u"), method=receipt.get("signed_method"),
            path=receipt.get("signed_path"), nonce=receipt.get("nonce"),
            signed_ts=receipt.get("ts_signed"),
        ) != receipt.get("mutation_hash")
    ):
        fail("REQUEST_RECEIPT_COMMITMENT_INVALID")
    if native.get("authority_mutation_hash") != grant.get("mutation_hash"):
        fail("AUTHORITY_MUTATION_BINDING_INVALID")
    if (
        native.get("outer_request_hash") != request.get("outer_request_hash")
        or native.get("command_hash") != request.get("command_hash")
    ):
        fail("REQUEST_CONTEXT_INVALID")
    return {
        "trust": trust, "identity": identity, "revocation": revocation,
        "housekeeper_identity": hk_identity, "housekeeper_revocation": hk_revocation,
        "grant": grant, "request": request, "request_receipt": receipt,
        "native_receipt": native, "request_ts": request_ts,
    }


def _validate_decisions(state: dict, native: dict) -> dict:
    get = lambda kind: state["singletons"][kind]["body"]
    content = get("content_state_projection")
    epistemic = get("epistemic_recall_decision")
    security = get("final_security_closure")
    projection = get("return_projection")
    admission_hash = _hash(content.get("admission_decision_sha256"))
    selection_hash = _hash(content.get("return_selection_decision_sha256"))
    state_root = _hash(content.get("state_view_root_sha256"))
    occurrence_root = _hash(content.get("occurrence_view_root_sha256"))
    epistemic_hash = _hash(epistemic.get("decision_sha256"))
    security_hash = _hash(security.get("decision_sha256"))
    _hash(projection.get("decision_sha256"))
    if (
        content.get("native_decision_schema") != "hom.aimos.content-state-occurrence-kernel/v1"
        or security.get("native_decision_schema")
            != "hom-aimos/canary-recall-final-closure/v2-epistemic-scope"
    ):
        fail("OBJECT_SCHEMA_INVALID")
    if (
        projection.get("content_state_selection_sha256") != selection_hash
        or security.get("state_view_root_sha256") != state_root
        or security.get("occurrence_view_root_sha256") != occurrence_root
    ):
        fail("CONTENT_STATE_BINDING_INVALID")
    if (
        security.get("epistemic_decision_sha256") != epistemic_hash
        or native.get("epistemic_decision_sha256") != epistemic_hash
    ):
        fail("EPISTEMIC_BINDING_INVALID")
    if (
        projection.get("final_security_closure_sha256") != security_hash
        or native.get("canary_final_security_closure_sha256") != security_hash
    ):
        fail("SECURITY_CLOSURE_BINDING_INVALID")
    if (
        not isinstance(epistemic.get("selected_memory_ids"), list)
        or not isinstance(security.get("selected_clean_memory_ids"), list)
        or not isinstance(projection.get("projected_memory_ids"), list)
        or not isinstance(projection.get("projected_live_content_hashes"), list)
        or projection.get("return_path") != security.get("return_path")
        or projection.get("return_path") not in RETURN_PATHS
        or projection.get("ordered_unique_subset_of_final_clean_security_closure") is not True
        or projection.get("output_content_commitments_unchanged") is not True
        or projection.get("canonical_memory_mutated") is not False
        or projection.get("retention_changed") is not False
        or native.get("return_projection_event_body_bound") is not True
        or not _equal(native.get("return_projection"), projection)
    ):
        fail("RETURN_PROJECTION_BINDING_INVALID")
    return {
        "content": content, "epistemic": epistemic, "security": security,
        "projection": projection, "admission_hash": admission_hash,
        "selection_hash": selection_hash, "epistemic_hash": epistemic_hash,
        "security_hash": security_hash,
    }


def _validate_results(state: dict, decisions: dict, native: dict) -> dict:
    count = state["envelope"]["result_count"]
    if (
        native.get("merkle_schema") != "hom-aimos/recall-merkle/v3-epistemic-and-security-closure"
        or native.get("result_count") != count or not isinstance(native.get("evidence"), list)
        or len(native["evidence"]) != count
        or decisions["projection"].get("projected_output_count") != count
        or len(decisions["projection"]["projected_memory_ids"]) != count
        or len(decisions["projection"]["projected_live_content_hashes"]) != count
    ):
        fail("RESULT_CARDINALITY_INVALID")
    evidence: list[dict] = []
    occurrences: list[dict] = []
    for ordinal, group in enumerate(state["results"]):
        memory = group["memory_state"]["body"]
        provenance = group["provenance_chain"]["body"]
        occurrence = group["occurrence"]["body"]
        epistemic = group["epistemic_projection"]["body"]
        receipt = group["receipt_evidence"]["body"]
        memory_id = _string(memory.get("memory_id")).lower()
        live_hash = _hash(memory.get("live_content_hash"), "RESULT_IDENTITY_BINDING_INVALID")
        if (
            UUID.fullmatch(memory_id) is None or group["memory_state"].get("subject_id") != memory_id
            or any(_string(body.get("memory_id")).lower() != memory_id
                   for body in (provenance, occurrence, epistemic, receipt))
            or any(_string(value).lower() != live_hash for value in (
                provenance.get("live_content_hash"), occurrence.get("live_content_hash_hex"),
                epistemic.get("live_content_hash"), receipt.get("live_content_hash"),
            ))
        ):
            fail("RESULT_IDENTITY_BINDING_INVALID")
        if (
            provenance.get("save_mutation_hash") != receipt.get("save_mutation_hash")
            or provenance.get("binding_mutation_hash") != receipt.get("binding_mutation_hash")
            or HEX32.fullmatch(_string(provenance.get("save_mutation_hash"))) is None
            or HEX32.fullmatch(_string(provenance.get("binding_mutation_hash"))) is None
        ):
            fail("PROVENANCE_BINDING_INVALID")
        if (
            occurrence.get("occurrence_ref") != receipt.get("occurrence_ref")
            or HEX32.fullmatch(_string(occurrence.get("occurrence_ref"))) is None
        ):
            fail("OCCURRENCE_BINDING_INVALID")
        if occurrence.get("occurrence_form") == "v3":
            body = occurrence.get("native_body") or {}
            try:
                commitment = occurrence_commitment_v3(body)
            except Exception:
                fail("OCCURRENCE_NATIVE_BODY_INVALID")
            if (
                occurrence.get("native_schema") != "hom.aimos.memory-occurrence/v3"
                or body.get("schema") != occurrence.get("native_schema")
                or body.get("memory_id") != memory_id
                or body.get("live_content_hash_hex") != live_hash
                or body.get("occurrence_commitment") != occurrence.get("occurrence_ref")
                or commitment != occurrence.get("occurrence_ref")
                or not _string(occurrence.get("signature_b64u"))
                or not _string(occurrence.get("signer_certificate"))
            ):
                fail("OCCURRENCE_NATIVE_BODY_INVALID")
        elif occurrence.get("occurrence_form") == "legacy_v1":
            if (
                occurrence.get("native_schema") != "hom.aimos.memory-occurrence-ref/legacy-v1"
                or (occurrence.get("native_body") or {}).get("memory_id") != memory_id
            ):
                fail("OCCURRENCE_NATIVE_BODY_INVALID")
        else:
            fail("OCCURRENCE_NATIVE_BODY_INVALID")
        if (
            epistemic.get("decision_sha256") != decisions["epistemic_hash"]
            or memory_id not in decisions["epistemic"]["selected_memory_ids"]
        ):
            fail("EPISTEMIC_PROJECTION_BINDING_INVALID")
        if receipt.get("ordinal") != ordinal or not _equal(
            _without_schema(receipt), native["evidence"][ordinal]
        ):
            fail("RECEIPT_EVIDENCE_BINDING_INVALID")
        if (
            decisions["projection"]["projected_memory_ids"][ordinal] != memory_id
            or decisions["projection"]["projected_live_content_hashes"][ordinal] != live_hash
            or decisions["security"]["selected_clean_memory_ids"][ordinal] != memory_id
        ):
            fail("RETURN_PROJECTION_BINDING_INVALID")
        selected_occurrences = decisions["content"].get("selected_occurrence_refs")
        if not isinstance(selected_occurrences, list) or receipt.get("occurrence_ref") not in selected_occurrences:
            fail("CONTENT_STATE_BINDING_INVALID")
        evidence.append(_without_schema(receipt))
        occurrences.append(occurrence)
    if (
        not _equal(decisions["epistemic"]["selected_memory_ids"], decisions["projection"]["projected_memory_ids"])
        or not _equal(decisions["security"]["selected_clean_memory_ids"], decisions["projection"]["projected_memory_ids"])
    ):
        fail("RETURN_PROJECTION_BINDING_INVALID")
    return {"evidence": evidence, "occurrences": occurrences}


def _validate_event(authority: dict, decisions: dict, evidence: list[dict]) -> dict:
    native = authority["native_receipt"]
    entries = [
        {"entry_type": "epistemic_decision", "decision_sha256": decisions["epistemic_hash"]},
        {"entry_type": "canary_final_security_closure", "decision_sha256": decisions["security_hash"]},
        *evidence,
    ]
    if not _equal(native.get("merkle_entries"), entries):
        fail("MERKLE_ENTRY_BINDING_INVALID")
    root = recall_merkle_root(entries).hex()
    if native.get("merkle_root") != root:
        fail("MERKLE_ROOT_MISMATCH")
    event = native.get("event_receipt") or {}
    body = event.get("signed_body") or {}
    metadata = body.get("metadata") or {}
    identity = authority["identity"]
    if (
        body.get("operation") != "recall_receipt"
        or body.get("company_id") != identity.get("company_id")
        or body.get("actor_agent_id") != identity.get("agent_id")
        or _iso(body.get("actor_valid_from"), "EVENT_RECEIPT_BINDING_INVALID")
            != _iso(identity.get("valid_from"), "EVENT_RECEIPT_BINDING_INVALID")
        or metadata.get("command_hash") != native.get("command_hash")
        or metadata.get("outer_request_hash") != native.get("outer_request_hash")
        or metadata.get("authority_mutation_hash") != native.get("authority_mutation_hash")
        or metadata.get("request_receipt_id") != native.get("request_receipt_id")
        or metadata.get("request_receipt_mutation_hash") != native.get("request_receipt_mutation_hash")
        or metadata.get("merkle_root") != root or metadata.get("result_count") != len(evidence)
        or not _equal(metadata.get("evidence"), evidence)
        or not _equal(metadata.get("return_projection"), native.get("return_projection"))
    ):
        fail("EVENT_RECEIPT_BINDING_INVALID")
    hk = authority["housekeeper_identity"]
    if (
        body.get("signer_agent_id") != "housekeeper"
        or _iso(body.get("signer_valid_from"), "HOUSEKEEPER_IDENTITY_INVALID")
            != _iso(hk.get("valid_from"), "HOUSEKEEPER_IDENTITY_INVALID")
        or body.get("cert_fingerprint") != hk.get("cert_fingerprint")
        or event.get("signer_certificate") != hk.get("certificate")
        or sha256_hex(_string(event.get("signer_certificate")).encode()) != hk.get("cert_fingerprint")
    ):
        fail("HOUSEKEEPER_IDENTITY_INVALID")
    content_hash = _canonical_sha(body)
    mutation_hash = _event_mutation_hash(
        event.get("prev_mutation_hash"), content_hash, event.get("nonce"), event.get("ts_signed")
    )
    if (
        event.get("content_hash") != content_hash or event.get("mutation_hash") != mutation_hash
        or body.get("prev_mutation_hash") != event.get("prev_mutation_hash")
        or body.get("ts_signed") != event.get("ts_signed")
    ):
        fail("EVENT_RECEIPT_COMMITMENT_INVALID")
    _signature(event.get("signature_b64u"), "EVENT_RECEIPT_COMMITMENT_INVALID")
    if (
        authority["revocation"].get("source_event_mutation_hash") != event.get("mutation_hash")
        or authority["revocation"].get("evaluated_at_unix_seconds") != event.get("ts_signed")
        or authority["housekeeper_revocation"].get("source_event_mutation_hash") != event.get("mutation_hash")
        or authority["housekeeper_revocation"].get("evaluated_at_unix_seconds") != event.get("ts_signed")
    ):
        fail("REVOCATION_EVENT_BINDING_INVALID")
    return {"event": event, "root": root}


def _validate_cryptography(
    state: dict,
    authority: dict,
    occurrences: list[dict],
    event: dict,
    expected_master_fingerprint: str | None,
) -> int:
    expected = _string(expected_master_fingerprint).lower()
    if (
        HEX32.fullmatch(expected) is None
        or expected != state["envelope"]["expected_master_fingerprint"]
    ):
        fail("EXPECTED_TRUST_ANCHOR_REQUIRED")
    master_key = authority["trust"]["master_public_key_b64u"]
    identity = authority["identity"]
    actor_cert = verify_certificate(
        certificate=identity["certificate"], authority_public_key=master_key,
        expected_agent_id=identity["agent_id"],
        expected_subject_public_key=identity["public_key_b64u"],
        at_unix_seconds=authority["request_ts"],
    )
    if (
        not actor_cert.get("valid")
        or actor_cert["body"].get("valid_from")
            != _unix_seconds(identity["valid_from"], "ACTOR_CERTIFICATE_SIGNATURE_INVALID")
        or actor_cert["body"].get("valid_until")
            != _unix_seconds(identity["valid_until"], "ACTOR_CERTIFICATE_SIGNATURE_INVALID")
        or actor_cert["body"].get("issuer") not in ("aimos-master", expected)
    ):
        fail("ACTOR_CERTIFICATE_SIGNATURE_INVALID")
    hk = authority["housekeeper_identity"]
    hk_cert = verify_certificate(
        certificate=hk["certificate"], authority_public_key=master_key,
        expected_agent_id="housekeeper", expected_subject_public_key=hk["public_key_b64u"],
        at_unix_seconds=event["ts_signed"],
    )
    if (
        not hk_cert.get("valid")
        or hk_cert["body"].get("valid_from")
            != _unix_seconds(hk["valid_from"], "HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID")
        or hk_cert["body"].get("valid_until")
            != _unix_seconds(hk["valid_until"], "HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID")
        or hk_cert["body"].get("issuer") not in ("aimos-master", expected)
    ):
        fail("HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID")
    count = 2
    grant = authority["grant"]
    if grant["authority_kind"] == "master_signed_recall_grant":
        if not verify_payload_signature(
            master_key, grant["signed_body"], grant["nonce"],
            grant["ts_signed"], grant["signature_b64u"],
        ):
            fail("MASTER_GRANT_SIGNATURE_INVALID")
        count += 1
    request = authority["request"]
    if not verify_request_context_signature(
        identity["public_key_b64u"], request["request_body"], request["signed_method"],
        request["signed_path"], request["nonce"], request["ts_signed"],
        request["signature_b64u"],
    ):
        fail("ACTOR_REQUEST_SIGNATURE_INVALID")
    count += 1
    if not verify_payload_signature(
        hk["public_key_b64u"], event["signed_body"], event["nonce"],
        event["ts_signed"], event["signature_b64u"],
    ):
        fail("HOUSEKEEPER_EVENT_SIGNATURE_INVALID")
    count += 1
    for occurrence in occurrences:
        if (
            occurrence.get("occurrence_form") != "v3"
            or occurrence.get("signer_certificate") != hk["certificate"]
            or not verify_occurrence_signature_v3(
                occurrence["native_body"], occurrence["signature_b64u"], hk["public_key_b64u"]
            )
        ):
            fail("HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID")
        count += 1
    return count


def verify_recall_envelope(
    envelope: dict,
    *,
    expected_master_fingerprint: str | None = None,
    verify_cryptography: bool = True,
) -> dict:
    state = _reconstruct_envelope(envelope)
    _require_schemas(state)
    authority = _validate_authority(state)
    decisions = _validate_decisions(state, authority["native_receipt"])
    results = _validate_results(state, decisions, authority["native_receipt"])
    terminal = _validate_event(authority, decisions, results["evidence"])
    signature_count = (
        _validate_cryptography(
            state, authority, results["occurrences"], terminal["event"],
            expected_master_fingerprint,
        )
        if verify_cryptography else 0
    )
    return {
        "schema": "hom.aimos.mutmem-independent-recall-result/v2",
        "valid": True,
        "bundle_sha256": state["bundle_hash"],
        "object_root_sha256": state["object_root"],
        "result_count": state["envelope"]["result_count"],
        "structural_predicate_count": len(STRUCTURAL_FAILURE_CODES),
        "cryptographic_signatures_verified": bool(verify_cryptography),
        "external_trust_established": bool(verify_cryptography),
        "verified_signature_count": signature_count,
    }


def recall_authorization_mutation_hash_for_parity(
    *, previous_mutation_hash: str | None, content_hash: str, nonce: Any, signed_ts: Any
) -> str:
    return _recall_authorization_mutation_hash(
        previous_mutation_hash=previous_mutation_hash,
        content_hash=content_hash,
        nonce=nonce,
        signed_ts=signed_ts,
    )


def request_receipt_mutation_hash_for_parity(**values: Any) -> str:
    return _request_receipt_mutation_hash(**values)
