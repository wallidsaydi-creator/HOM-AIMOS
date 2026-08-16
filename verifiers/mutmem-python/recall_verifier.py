"""Independent MutMem recall-order, Merkle, and intended-N verifier.

This module consumes only hostile evidence JSON and explicit public trust
anchors. It has no AIMOS runtime, authority store, network, signer, policy,
model, or environment-authority dependency.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

from mutmem_verifier import (
    VerificationError,
    _b64u_decode,
    _reject_duplicates,
    canonical_json,
)


RECALL_SCHEMA = "hom.aimos.mutmem-recall-evidence/v1"
CORPUS_SCHEMA = "hom.aimos.mutmem-recall-corpus/v1"
RECALL_VERIFIER_VERSION = "0.1.0"

EVENT_LINK_DOMAIN = b"AIMOS-EVENT-LINK-v1\0"
RECALL_LEAF_PREFIX = b"\x00"
RECALL_NODE_PREFIX = b"\x01"
RECALL_CORPUS_ROOT_DOMAIN = b"aimos.mutmem-recall-corpus/v1\0"
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
COMMAND_FIELDS = {
    "query", "q", "key", "memory_id", "company_id", "agent_id", "limit",
    "clearance_level", "memory_type_filter", "source_filter", "session_id",
    "project_id", "workspace_path", "sort", "mode", "selectivity", "lazy",
    "max_hops", "projection", "cache", "semantic_cache", "early_exit",
    "debug_recall", "doctor_trace", "context_window", "tokens_used",
    "recall_share", "summary_token_budget", "evidence_token_budget",
    "full_detail_token_budget", "answer_shape", "requested_shape", "answer_mode",
    "ts_signed",
}


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _exact_object(value: Any, keys: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerificationError(reason)
    return value


def _allowed_object(value: Any, required: set[str], allowed: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(allowed):
        raise VerificationError(reason)
    return value


def _hex32(value: Any, reason: str) -> bytes:
    if not isinstance(value, str) or not HEX_32.fullmatch(value):
        raise VerificationError(reason)
    return bytes.fromhex(value)


def _canonical_sha(value: Any) -> bytes:
    return _sha256(canonical_json(value).encode("utf-8"))


def _public_key(value: str):
    try:
        return load_der_public_key(_b64u_decode(value, "public_key_invalid"))
    except Exception as exc:
        raise VerificationError("public_key_invalid") from exc


def _verify_raw(pubkey: str, message: bytes, signature: bytes) -> bool:
    try:
        _public_key(pubkey).verify(signature, message)
        return True
    except (InvalidSignature, VerificationError, ValueError, TypeError):
        return False


def _normalize_integer(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    parsed = fallback if value is None else value
    if isinstance(parsed, bool) or not isinstance(parsed, int) or parsed < minimum or parsed > maximum:
        raise VerificationError("recall_integer_invalid")
    return parsed


def normalize_recall_command(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise VerificationError("recall_command_invalid")
    for key in raw:
        if key not in COMMAND_FIELDS:
            raise VerificationError(f"recall_unknown_field:{key}")
    query = str(raw.get("query", raw.get("q", ""))).strip()
    key = None if raw.get("key") is None else str(raw["key"]).strip()
    memory_id = None if raw.get("memory_id") is None else str(raw["memory_id"]).strip()
    if not query and not key and not memory_id:
        raise VerificationError("recall_query_or_identifier_required")
    if memory_id and not UUID.fullmatch(memory_id):
        raise VerificationError("recall_memory_id_invalid")
    result = dict(raw)
    result.update({
        "query": query,
        "q": query,
        "key": key,
        "memory_id": memory_id,
        "company_id": "hom" if raw.get("company_id") is None else str(raw["company_id"]),
        "agent_id": None if raw.get("agent_id") is None else str(raw["agent_id"]),
        "limit": _normalize_integer(raw.get("limit"), 10, 1, 200),
        "clearance_level": None if raw.get("clearance_level") is None
        else _normalize_integer(raw.get("clearance_level"), 1, 0, 12),
        "max_hops": None if raw.get("max_hops") is None
        else _normalize_integer(raw.get("max_hops"), 2, 1, 4),
    })
    return result


def recall_merkle_root(entries: list[Any]) -> bytes:
    if not isinstance(entries, list):
        raise VerificationError("recall_entries_invalid")
    leaves = [_sha256(RECALL_LEAF_PREFIX + canonical_json(entry).encode("utf-8")) for entry in entries]
    if not leaves:
        return _sha256(b"")

    def tree(nodes: list[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        split = 1
        while (split << 1) < len(nodes):
            split <<= 1
        return _sha256(RECALL_NODE_PREFIX + tree(nodes[:split]) + tree(nodes[split:]))

    return tree(leaves)


def recall_corpus_root(intended_n: int, members: list[dict[str, Any]]) -> bytes:
    if isinstance(intended_n, bool) or not isinstance(intended_n, int) or intended_n < 1 \
            or not isinstance(members, list) or len(members) != intended_n:
        raise VerificationError("recall_corpus_intended_n_invalid")
    seen: set[str] = set()
    normalized = []
    for ordinal, member in enumerate(members):
        if not isinstance(member, dict) or member.get("ordinal") != ordinal \
                or not isinstance(member.get("bundle_id"), str) or not member["bundle_id"] \
                or not isinstance(member.get("bundle_sha256"), str) \
                or not HEX_32.fullmatch(member["bundle_sha256"]) \
                or member["bundle_id"] in seen:
            raise VerificationError("recall_corpus_member_invalid")
        seen.add(member["bundle_id"])
        normalized.append({
            "ordinal": ordinal,
            "bundle_id": member["bundle_id"],
            "bundle_sha256": member["bundle_sha256"],
        })
    return _sha256(RECALL_CORPUS_ROOT_DOMAIN + struct.pack(">q", intended_n) + recall_merkle_root(normalized))


def _decode_certificate(certificate: str) -> dict[str, Any]:
    try:
        decoded = _b64u_decode(certificate, "cert_malformed").decode("utf-8")
        envelope = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicates,
        )
    except Exception as exc:
        raise VerificationError("cert_malformed") from exc
    required = {"v", "agent_id", "pubkey", "device_fp", "valid_from", "valid_until", "issuer", "issued_at"}
    if not isinstance(envelope, dict) or set(envelope) != {"body", "sig"} \
            or not isinstance(envelope.get("body"), dict) or set(envelope["body"]) != required \
            or not isinstance(envelope.get("sig"), str) or canonical_json(envelope) != decoded:
        raise VerificationError("cert_schema")
    return envelope


def _verify_trust_anchors(bundle: dict[str, Any]) -> None:
    anchors = _exact_object(bundle.get("trust_anchors"), {"master", "certificates"},
                            "recall_trust_anchor_schema_invalid")
    master = anchors["master"]
    if master is not None:
        _exact_object(master, {"public_key_b64u", "fingerprint"},
                      "recall_trust_anchor_schema_invalid")
        if not isinstance(master["fingerprint"], str) or not HEX_32.fullmatch(master["fingerprint"]) \
                or _sha256(_b64u_decode(master["public_key_b64u"], "master_key_invalid")).hex() \
                != master["fingerprint"]:
            raise VerificationError("recall_trust_anchor_schema_invalid")
    if not isinstance(anchors["certificates"], list) or len(anchors["certificates"]) > 16:
        raise VerificationError("recall_trust_anchor_schema_invalid")
    seen: set[str] = set()
    for anchor in anchors["certificates"]:
        _exact_object(anchor, {"certificate_sha256", "public_key_b64u"},
                      "recall_trust_anchor_schema_invalid")
        if not isinstance(anchor["certificate_sha256"], str) \
                or not HEX_32.fullmatch(anchor["certificate_sha256"]) \
                or anchor["certificate_sha256"] in seen:
            raise VerificationError("recall_trust_anchor_schema_invalid")
        _public_key(anchor["public_key_b64u"])
        seen.add(anchor["certificate_sha256"])


def _trusted_certificate(bundle: dict[str, Any], certificate: str, signed_at: int) -> tuple[dict[str, Any], str]:
    envelope = _decode_certificate(certificate)
    body = envelope["body"]
    cert_sha = _sha256(certificate.encode("utf-8")).hex()
    authority = None
    if body.get("issuer") == body.get("agent_id"):
        for anchor in bundle["trust_anchors"]["certificates"]:
            if anchor.get("certificate_sha256") == cert_sha and anchor.get("public_key_b64u") == body.get("pubkey"):
                authority = body["pubkey"]
                break
    else:
        master = bundle["trust_anchors"].get("master")
        if isinstance(master, dict) and body.get("issuer") in {"aimos-master", master.get("fingerprint")} \
                and _sha256(_b64u_decode(master.get("public_key_b64u"), "master_key_invalid")).hex() == master.get("fingerprint"):
            authority = master["public_key_b64u"]
    if authority is None:
        raise VerificationError("recall_trust_anchor_missing")
    if not _verify_raw(authority, canonical_json(body).encode("utf-8"),
                       _b64u_decode(envelope["sig"], "cert_sig_invalid")):
        raise VerificationError("cert_sig_invalid")
    if isinstance(signed_at, bool) or not isinstance(signed_at, int) \
            or signed_at < body["valid_from"] or signed_at > body["valid_until"]:
        raise VerificationError("cert_epoch_invalid")
    return body, cert_sha


def _verify_request(bundle: dict[str, Any]) -> dict[str, Any]:
    request = _exact_object(bundle.get("request"), {
        "body", "method", "path", "nonce", "ts_signed", "signature", "certificate",
    }, "recall_request_schema_invalid")
    if not isinstance(request["body"], dict):
        raise VerificationError("recall_request_schema_invalid")
    cert, _ = _trusted_certificate(bundle, request["certificate"], request["ts_signed"])
    if cert.get("agent_id") != request["body"].get("agent_id"):
        raise VerificationError("recall_request_identity_invalid")
    if request["method"] != "POST" or request["path"] != "/aimos/recall" \
            or request["body"].get("ts_signed") != request["ts_signed"] \
            or not isinstance(request["nonce"], str) or not request["nonce"]:
        raise VerificationError("recall_request_context_invalid")
    message = (canonical_json(request["body"]) + "\nPOST\n/aimos/recall\n"
               + request["nonce"] + "\n" + str(request["ts_signed"])).encode("utf-8")
    if not _verify_raw(cert["pubkey"], message, _b64u_decode(request["signature"], "recall_request_signature_invalid")):
        raise VerificationError("recall_request_signature_invalid")
    return normalize_recall_command(request["body"])


def _verify_event(bundle: dict[str, Any], receipt: dict[str, Any], expected: dict[str, str]) -> dict[str, Any] | None:
    event = receipt.get("event_receipt")
    if event is None:
        return {"verdict": "indeterminate", "primary_reason": "recall_mandatory_evidence_missing"}
    _exact_object(event, {
        "event_id", "proof_required", "ledger_version", "ledger_seq", "signed_body",
        "content_hash", "mutation_hash", "prev_mutation_hash", "signer_agent_id",
        "signer_valid_from", "cert_fingerprint", "signer_certificate", "identity_tier",
        "ts_signed", "nonce", "signature",
    }, "recall_event_receipt_schema_invalid")
    cert, cert_sha = _trusted_certificate(bundle, event["signer_certificate"], event["ts_signed"])
    body = event["signed_body"]
    if not isinstance(body, dict):
        raise VerificationError("recall_event_body_invalid")
    content = _canonical_sha(body)
    previous = _hex32(event["prev_mutation_hash"], "recall_event_previous_hash_invalid")
    mutation = _sha256(EVENT_LINK_DOMAIN + previous + content + str(event["nonce"]).encode("utf-8")
                       + str(event["ts_signed"]).encode("utf-8"))
    exact = (
        event["proof_required"] is True and event["ledger_version"] == body.get("ledger_version") == 1
        and event["event_id"] == body.get("event_id")
        and event["signer_agent_id"] == body.get("signer_agent_id")
        and event["signer_valid_from"] == body.get("signer_valid_from")
        and event["ts_signed"] == body.get("ts_signed")
        and event["cert_fingerprint"] == cert_sha == body.get("cert_fingerprint")
        and event["content_hash"] == content.hex() and event["mutation_hash"] == mutation.hex()
        and event["prev_mutation_hash"] == body.get("prev_mutation_hash")
        and body.get("company_id") == bundle["company_id"] and body.get("operation") == "recall_receipt"
        and body.get("key") == expected["command_hash"]
        and body.get("metadata", {}).get("command_hash") == expected["command_hash"]
        and body.get("metadata", {}).get("outer_request_hash") == expected["outer_hash"]
        and body.get("metadata", {}).get("merkle_root") == expected["merkle_root"]
        and body.get("metadata", {}).get("result_count") == len(receipt["evidence"])
        and canonical_json(body.get("metadata", {}).get("evidence")) == canonical_json(receipt["evidence"])
    )
    if not exact:
        raise VerificationError("recall_event_binding_invalid")
    message = (canonical_json(body) + "\n" + str(event["nonce"]) + "\n"
               + str(event["ts_signed"])).encode("utf-8")
    if not _verify_raw(cert["pubkey"], message, _b64u_decode(event["signature"], "recall_event_signature_invalid")):
        raise VerificationError("recall_event_signature_invalid")
    return None


def _verify_memory_bindings(bundle: dict[str, Any], receipt: dict[str, Any], command: dict[str, Any]) -> None:
    for index, memory in enumerate(bundle["memories"]):
        evidence = receipt["evidence"][index]
        reason = f"recall_receipt_memory_binding_invalid:{index}"
        _exact_object(memory, {"id", "source", "memory_type", "provenance_proof"}, reason)
        proof = _exact_object(memory["provenance_proof"], {
            "live_content_hash", "save_mutation_hash", "binding_mutation_hash",
        }, reason)
        _exact_object(evidence, {
            "ordinal", "memory_id", "live_content_hash", "save_mutation_hash", "binding_mutation_hash",
            "truth_state", "raw_calibration_score", "calibrated_score", "calibration_event_id",
            "calibration_mutation_hash", "calibration_formula_version",
        }, reason)
        valid = evidence["ordinal"] == index and evidence["memory_id"] == memory["id"] \
            and memory["source"] == command.get("source_filter") \
            and (command.get("memory_type_filter") is None
                 or memory["memory_type"] == command.get("memory_type_filter")) \
            and evidence["live_content_hash"] == proof["live_content_hash"] \
            and evidence["save_mutation_hash"] == proof["save_mutation_hash"] \
            and evidence["binding_mutation_hash"] == proof["binding_mutation_hash"] \
            and all(isinstance(evidence[field], str) and HEX_32.fullmatch(evidence[field])
                    for field in ("live_content_hash", "save_mutation_hash", "binding_mutation_hash"))
        if not valid:
            raise VerificationError(reason)


def verify_recall_bundle(bundle: Any) -> dict[str, Any]:
    try:
        _exact_object(bundle, {
            "bundle_id", "company_id", "format", "memories", "recall_receipt", "request", "trust_anchors",
        }, "recall_bundle_schema_invalid")
        expected_format = {
            "schema": RECALL_SCHEMA, "version": 1, "authority": "descriptive_only",
            "canonicalization": "hom-aimos/canonical-json/v1", "hash": "sha256", "signature": "ed25519",
        }
        if bundle["format"] != expected_format or not isinstance(bundle["bundle_id"], str) or not bundle["bundle_id"] \
                or not isinstance(bundle["company_id"], str) or not bundle["company_id"] \
                or not isinstance(bundle["memories"], list):
            raise VerificationError("recall_bundle_schema_invalid")
        _verify_trust_anchors(bundle)
        command = _verify_request(bundle)
        if command["company_id"] != bundle["company_id"]:
            raise VerificationError("recall_scope_binding_invalid")
        receipt = bundle["recall_receipt"]
        if not isinstance(receipt, dict) or not isinstance(receipt.get("evidence"), list):
            return {"verdict": "indeterminate", "schema": RECALL_SCHEMA,
                    "primary_reason": "recall_mandatory_evidence_missing"}
        receipt_base = {
            "command_hash", "outer_request_hash", "authority_mutation_hash", "request_receipt_id",
            "request_receipt_mutation_hash", "merkle_root", "evidence",
        }
        _allowed_object(receipt, receipt_base, receipt_base | {
            "event_receipt", "merkle_schema", "epistemic_decision_sha256", "merkle_entries",
        }, "recall_receipt_schema_invalid")
        if len(receipt["evidence"]) != len(bundle["memories"]):
            raise VerificationError("recall_receipt_evidence_count_mismatch")
        _verify_memory_bindings(bundle, receipt, command)
        merkle_entries = receipt["evidence"]
        if receipt.get("merkle_schema") is not None:
            expected_first = {"entry_type": "epistemic_decision",
                              "decision_sha256": receipt.get("epistemic_decision_sha256")}
            if receipt.get("merkle_schema") != "hom-aimos/recall-merkle/v2-epistemic-decision" \
                    or not isinstance(receipt.get("epistemic_decision_sha256"), str) \
                    or not HEX_32.fullmatch(receipt["epistemic_decision_sha256"]) \
                    or not isinstance(receipt.get("merkle_entries"), list) \
                    or len(receipt["merkle_entries"]) != len(receipt["evidence"]) + 1 \
                    or canonical_json(receipt["merkle_entries"][0]) != canonical_json(expected_first) \
                    or canonical_json(receipt["merkle_entries"][1:]) != canonical_json(receipt["evidence"]):
                raise VerificationError("recall_receipt_epistemic_binding_invalid")
            merkle_entries = receipt["merkle_entries"]
        command_hash = _canonical_sha(command).hex()
        outer_hash = _canonical_sha(bundle["request"]["body"]).hex()
        merkle_root = recall_merkle_root(merkle_entries).hex()
        if receipt.get("command_hash") != command_hash or receipt.get("outer_request_hash") != outer_hash \
                or receipt.get("merkle_root") != merkle_root \
                or not isinstance(receipt.get("authority_mutation_hash"), str) \
                or not HEX_32.fullmatch(receipt["authority_mutation_hash"]) \
                or not isinstance(receipt.get("request_receipt_mutation_hash"), str) \
                or not HEX_32.fullmatch(receipt["request_receipt_mutation_hash"]):
            raise VerificationError("recall_receipt_cryptographic_binding_invalid")
        indeterminate = _verify_event(bundle, receipt, {
            "command_hash": command_hash, "outer_hash": outer_hash, "merkle_root": merkle_root,
        })
        if indeterminate:
            return {**indeterminate, "schema": RECALL_SCHEMA, "verifier_version": RECALL_VERIFIER_VERSION}
        return {
            "verdict": "valid", "schema": RECALL_SCHEMA, "verifier_version": RECALL_VERIFIER_VERSION,
            "primary_reason": None, "bundle_sha256": _canonical_sha(bundle).hex(),
            "command_hash": command_hash, "outer_request_hash": outer_hash, "merkle_root": merkle_root,
            "counts": {"memories": len(bundle["memories"]), "recall_leaves": len(merkle_entries)},
        }
    except VerificationError as exc:
        return {"verdict": "invalid", "schema": RECALL_SCHEMA,
                "verifier_version": RECALL_VERIFIER_VERSION, "primary_reason": str(exc)}
    except Exception:
        return {"verdict": "invalid", "schema": RECALL_SCHEMA,
                "verifier_version": RECALL_VERIFIER_VERSION, "primary_reason": "recall_verifier_internal_failure"}


def verify_recall_corpus(corpus: Any) -> dict[str, Any]:
    try:
        _exact_object(corpus, {"format", "intended_n", "members", "corpus_root"},
                      "recall_corpus_schema_invalid")
        if corpus["format"] != {"schema": CORPUS_SCHEMA, "version": 1, "authority": "descriptive_only"} \
                or isinstance(corpus["intended_n"], bool) or not isinstance(corpus["intended_n"], int) \
                or corpus["intended_n"] < 1 or not isinstance(corpus["members"], list) \
                or len(corpus["members"]) != corpus["intended_n"]:
            raise VerificationError("recall_corpus_intended_n_invalid")
        summaries = []
        verdicts = []
        seen: set[str] = set()
        for ordinal, member in enumerate(corpus["members"]):
            _exact_object(member, {"ordinal", "bundle_id", "bundle_sha256", "bundle"},
                          "recall_corpus_member_invalid")
            actual_hash = _canonical_sha(member["bundle"]).hex()
            if member["ordinal"] != ordinal or member["bundle_id"] != member["bundle"].get("bundle_id") \
                    or not member["bundle_id"] or member["bundle_id"] in seen \
                    or member["bundle_sha256"] != actual_hash:
                raise VerificationError("recall_corpus_member_invalid")
            seen.add(member["bundle_id"])
            verdict = verify_recall_bundle(member["bundle"])
            verdicts.append({"ordinal": ordinal, "bundle_id": member["bundle_id"],
                             "verdict": verdict["verdict"], "primary_reason": verdict.get("primary_reason")})
            summaries.append({"ordinal": ordinal, "bundle_id": member["bundle_id"],
                              "bundle_sha256": actual_hash})
        root = recall_corpus_root(corpus["intended_n"], summaries).hex()
        if corpus["corpus_root"] != root:
            raise VerificationError("recall_corpus_root_mismatch")
        primary = next((value for value in verdicts if value["verdict"] == "invalid"), None)
        if primary is None:
            primary = next((value for value in verdicts if value["verdict"] == "indeterminate"), None)
        return {
            "verdict": "valid" if primary is None else primary["verdict"],
            "schema": CORPUS_SCHEMA, "verifier_version": RECALL_VERIFIER_VERSION,
            "primary_reason": None if primary is None else primary["primary_reason"],
            "intended_n": corpus["intended_n"], "observed_n": len(corpus["members"]),
            "corpus_root": root, "members": verdicts,
        }
    except VerificationError as exc:
        return {"verdict": "invalid", "schema": CORPUS_SCHEMA,
                "verifier_version": RECALL_VERIFIER_VERSION, "primary_reason": str(exc)}
    except Exception:
        return {"verdict": "invalid", "schema": CORPUS_SCHEMA,
                "verifier_version": RECALL_VERIFIER_VERSION, "primary_reason": "recall_verifier_internal_failure"}
