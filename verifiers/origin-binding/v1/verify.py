#!/usr/bin/env python3
"""Independent standard-library verifier for HOM-AIMOS Origin Binding V1."""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(__file__).resolve().parent
PROFILE_HASH = "49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24"
SCHEMAS = {
    "family_profile": "hom.aimos.origin-family-profile/v1",
    "memory_binding": "hom.aimos.memory-origin-binding/v1",
    "elevation": "hom.aimos.origin-elevation/v1",
    "action_verdict": "hom.aimos.action-origin-verdict/v1",
}
HEX32 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._:-]{0,198}[a-z0-9])?$")
FAMILY_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
TIMESTAMP = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$")
MEMORY_READ = re.compile(r"\b(?:FROM|JOIN)\s+(?:public\.)?aimos_memories\b", re.I)
PRODUCTION_SCAN_ROOTS = ("services", "routes", "jobs", "db", "middleware")
CRITICAL_CLASSIFICATIONS = {
    "MODEL_VISIBLE_DIRECT_READ",
    "MODEL_AND_ACTION_INFLUENCING_DIRECT_READ",
    "MODEL_VISIBLE_HANDOFF_DIRECT_READ",
    "ACTION_INFLUENCING_DIRECT_READ",
    "MODEL_OR_DERIVATION_DIRECT_READ",
    "NONCANONICAL_RETRIEVAL_DIRECT_READ",
    "EXTERNAL_DISCLOSURE_OR_ROUTE_CONTROL_READ",
}


class VerifyError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def fail(code: str) -> None:
    raise VerifyError(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_numbers(value: Any, depth: int = 0) -> None:
    if depth > 32:
        fail("body_depth_invalid")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            fail("body_number_invalid")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer() or abs(value) > 9007199254740991:
            fail("body_number_invalid")
        return
    if isinstance(value, list):
        for child in value:
            validate_numbers(child, depth + 1)
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                fail("body_invalid")
            validate_numbers(child, depth + 1)
        return
    fail("body_invalid")


def canonical_json(value: Any) -> str:
    validate_numbers(value)

    def quote(text: str) -> str:
        # JSON.stringify preserves Unicode scalar values but escapes lone
        # UTF-16 surrogates. Do not normalize Unicode or change string meaning.
        encoded = json.dumps(text, ensure_ascii=False, separators=(",", ":"))
        return "".join(f"\\u{ord(c):04x}" if 0xD800 <= ord(c) <= 0xDFFF else c for c in encoded)

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, (int, float)):
            return str(int(item))
        if isinstance(item, str):
            return quote(item)
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        keys = sorted(item, key=lambda key: key.encode("utf-16-be", errors="surrogatepass"))
        return "{" + ",".join(quote(key) + ":" + encode(item[key]) for key in keys) + "}"

    return encode(value)


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def protocol_bytes(body: dict[str, Any]) -> bytes:
    schema = body.get("schema")
    if schema not in SCHEMAS.values():
        fail("schema_invalid")
    encoded = canonical_bytes(body)
    if not encoded or len(encoded) > 1024 * 1024:
        fail("body_size_invalid")
    return schema.encode("utf-8") + b"\0" + struct.pack(">I", len(encoded)) + encoded


def protocol_hash(body: dict[str, Any]) -> str:
    return sha(protocol_bytes(body))


def exact_keys(value: Any, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        fail("shape_invalid")


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value) or len(value.encode()) > 200:
        fail("identifier_invalid")
    return value


def uuid(value: Any) -> str:
    if not isinstance(value, str) or not UUID.fullmatch(value):
        fail("uuid_invalid")
    return value


def hash32(value: Any) -> str:
    if not isinstance(value, str) or not HEX32.fullmatch(value):
        fail("sha256_invalid")
    return value


def timestamp(value: Any) -> str:
    matched = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not matched:
        fail("timestamp_invalid")
    year, month, day, hour, minute, second, _millisecond = map(int, matched.groups())
    # Shared four-digit proleptic Gregorian wire domain, including year 0000.
    # No Python datetime year-1 restriction or JavaScript date normalization.
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not (1 <= month <= 12 and 1 <= day <= days[month - 1]
            and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        fail("timestamp_invalid")
    return value


def enum(value: Any, allowed: list[str]) -> str:
    if value not in allowed:
        fail("enum_invalid")
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()))
            or abs(value) > 9007199254740991 or value < minimum or value > maximum):
        fail("integer_invalid")
    return int(value)


def ordered_unique(values: Any, maximum: int, validator, order_code: str,
                   duplicate_code: str, count_code: str, allow_empty: bool = False) -> list[Any]:
    if not isinstance(values, list) or len(values) > maximum or (not allow_empty and len(values) < 1):
        fail(count_code)
    normalized = [validator(value) for value in values]
    if len(set(normalized)) != len(normalized):
        fail(duplicate_code)
    if normalized != sorted(normalized, key=lambda value: value.encode("utf-8")):
        fail(order_code)
    return normalized


def parse_json_wire(raw: str | bytes) -> Any:
    def members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("json_duplicate_member")
            result[key] = value
        return result

    def invalid_constant(_value):
        fail("json_wire_invalid")

    return json.loads(raw, object_pairs_hook=members, parse_constant=invalid_constant)


def read_json(name: str) -> Any:
    return parse_json_wire((OUTPUT / name).read_text(encoding="utf-8"))


def verify_sidecar(name: str) -> str:
    payload = (OUTPUT / name).read_bytes()
    expected = (OUTPUT / f"{name}.sha256").read_text(encoding="utf-8").split()[0]
    actual = sha(payload)
    if actual != expected:
        fail(f"artifact_checksum_invalid:{name}")
    return actual


class ProtocolVerifier:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.validate_profile(profile)
        self.families = {entry["id"]: entry for entry in profile["families"]}
        self.confidentiality = profile["confidentiality_order"]
        self.integrity = profile["integrity_order"]
        self.action = profile["action_class_order"]
        self.risk = profile["risk_class_order"]
        self.ingress = profile["ingress_channels"]
        self.classification_authorities = profile["classification_authorities"]
        self.channel_ceiling = {
            "untrusted_external": "untrusted",
            "agent_self": "agent",
            "authenticated_agent": "agent",
            "housekeeper_system": "agent",
            "authenticated_tool": "trusted",
            "authenticated_user": "trusted",
            "system_internal": "trusted",
        }
        self.action_ceiling = {"untrusted": "none", "agent": "inform", "trusted": "act"}

    def validate_profile(self, body: dict[str, Any]) -> None:
        exact_keys(body, {
            "schema", "version", "canonicalization", "hash", "signature", "family_order",
            "maximum_family_count", "maximum_parent_count", "maximum_corroborator_count",
            "confidentiality_order", "integrity_order", "action_class_order", "risk_class_order",
            "ingress_channels", "classification_authorities", "family_action_policies", "families",
        })
        if body["schema"] != SCHEMAS["family_profile"] or body["version"] != 1:
            fail("family_profile_invalid")
        if body["canonicalization"] != "hom-aimos/canonical-json/v1-safe-integers":
            fail("family_profile_invalid")
        if body["hash"] != "sha256" or body["signature"] != "ed25519":
            fail("family_profile_invalid")
        if body["family_order"] != "utf8_lexicographic_ascending":
            fail("family_profile_invalid")
        if body["maximum_family_count"] != 64 or body["maximum_parent_count"] != 64:
            fail("family_profile_invalid")
        if body["maximum_corroborator_count"] != 16:
            fail("family_profile_invalid")
        families = body["families"]
        if not isinstance(families, list) or not 1 <= len(families) <= 64:
            fail("family_count_invalid")
        ids: list[str] = []
        local: dict[str, dict[str, Any]] = {}
        for entry in families:
            exact_keys(entry, {"id", "parent_id", "confidentiality_floor", "action_policy"})
            family_id = entry["id"]
            if not isinstance(family_id, str) or not FAMILY_ID.fullmatch(family_id):
                fail("family_id_invalid")
            if family_id in local:
                fail("family_duplicate")
            if entry["parent_id"] is not None and (
                not isinstance(entry["parent_id"], str)
                or not FAMILY_ID.fullmatch(entry["parent_id"])
            ):
                fail("family_parent_invalid")
            enum(entry["confidentiality_floor"], body["confidentiality_order"])
            enum(entry["action_policy"], body["family_action_policies"])
            ids.append(family_id)
            local[family_id] = entry
        if ids != sorted(ids, key=lambda value: value.encode("utf-8")):
            fail("family_order_invalid")
        for entry in families:
            seen = {entry["id"]}
            cursor = entry
            while cursor["parent_id"] is not None:
                parent = cursor["parent_id"]
                if parent in seen:
                    fail("family_cycle")
                if parent not in local:
                    fail("family_parent_invalid")
                seen.add(parent)
                cursor = local[parent]

    def family_closure(self, family_ids: Any) -> list[str]:
        if not isinstance(family_ids, list) or not 1 <= len(family_ids) <= 64:
            fail("family_count_invalid")
        closure: set[str] = set()
        for family_id in family_ids:
            if not isinstance(family_id, str) or family_id not in self.families:
                fail("family_id_invalid")
            cursor = self.families[family_id]
            while cursor is not None:
                closure.add(cursor["id"])
                cursor = None if cursor["parent_id"] is None else self.families[cursor["parent_id"]]
        return sorted(closure, key=lambda value: value.encode("utf-8"))

    def exact_family_closure(self, values: Any) -> list[str]:
        normalized = ordered_unique(
            values, 64,
            lambda value: value if isinstance(value, str) and value in self.families else fail("family_id_invalid"),
            "family_order_invalid", "family_duplicate", "family_count_invalid",
        )
        if normalized != self.family_closure(normalized):
            fail("family_closure_invalid")
        return normalized

    @staticmethod
    def actor(value: Any) -> dict[str, Any]:
        exact_keys(value, {"agent_id", "valid_from", "cert_fingerprint_sha256"})
        identifier(value["agent_id"])
        timestamp(value["valid_from"])
        hash32(value["cert_fingerprint_sha256"])
        return value

    @staticmethod
    def request(value: Any) -> dict[str, Any]:
        exact_keys(value, {"receipt_id", "mutation_sha256"})
        uuid(value["receipt_id"])
        hash32(value["mutation_sha256"])
        return value

    def binding(self, value: dict[str, Any], with_hash: bool = False) -> dict[str, Any]:
        keys = {
            "schema", "company_id", "memory_id", "occurrence_id", "content_sha256", "actor",
            "request", "origin", "parents", "classification", "confidentiality", "integrity",
            "action_class", "scope", "session_id", "tool_action_event_id", "created_at",
        }
        if with_hash:
            keys.add("binding_sha256")
        exact_keys(value, keys)
        if value["schema"] != SCHEMAS["memory_binding"]:
            fail("schema_invalid")
        identifier(value["company_id"])
        uuid(value["memory_id"])
        uuid(value["occurrence_id"])
        hash32(value["content_sha256"])
        self.actor(value["actor"])
        self.request(value["request"])
        exact_keys(value["origin"], {"ingress_channel", "channel_identity_sha256"})
        ingress = enum(value["origin"]["ingress_channel"], self.ingress)
        hash32(value["origin"]["channel_identity_sha256"])
        exact_keys(value["parents"], {"origin_sha256s"})
        parents = ordered_unique(
            value["parents"]["origin_sha256s"], 64, hash32,
            "parent_order_invalid", "parent_duplicate", "parent_count_invalid", True,
        )
        exact_keys(value["classification"], {
            "profile_sha256", "family_ids", "authority", "evidence_sha256",
        })
        if hash32(value["classification"]["profile_sha256"]) != PROFILE_HASH:
            fail("family_profile_hash_invalid")
        families = self.exact_family_closure(value["classification"]["family_ids"])
        enum(value["classification"]["authority"], self.classification_authorities)
        hash32(value["classification"]["evidence_sha256"])
        confidentiality = enum(value["confidentiality"], self.confidentiality)
        integrity = enum(value["integrity"], self.integrity)
        action = enum(value["action_class"], self.action)
        floor = max(self.confidentiality.index(self.families[item]["confidentiality_floor"])
                    for item in families)
        if self.confidentiality.index(confidentiality) < floor:
            fail("family_confidentiality_floor_invalid")
        if self.integrity.index(integrity) > self.integrity.index(self.channel_ceiling[ingress]):
            fail("channel_integrity_invalid")
        if self.action.index(action) > self.action.index(self.action_ceiling[integrity]):
            fail("integrity_action_class_invalid")
        identifier(value["scope"])
        if value["session_id"] is not None:
            identifier(value["session_id"])
        if value["tool_action_event_id"] is not None:
            uuid(value["tool_action_event_id"])
        timestamp(value["created_at"])
        body = dict(value)
        supplied = None
        if with_hash:
            supplied = hash32(body.pop("binding_sha256"))
        commitment = protocol_hash(body)
        if supplied is not None and supplied != commitment:
            fail("parent_binding_invalid")
        return {**body, "binding_sha256": commitment, "_parents": parents, "_families": families}

    def derivation(self, value: dict[str, Any]) -> dict[str, Any]:
        exact_keys(value, {"child", "parents"})
        child = self.binding(value["child"], True)
        if not isinstance(value["parents"], list) or len(value["parents"]) > 64:
            fail("parent_count_invalid")
        parents = [self.binding(parent, True) for parent in value["parents"]]
        hashes = sorted((parent["binding_sha256"] for parent in parents), key=lambda item: item.encode())
        if hashes != child["_parents"]:
            fail("parent_binding_invalid")
        if not parents:
            return {"valid": True, "parent_count": 0}
        inherited = self.family_closure(sorted(
            {family for parent in parents for family in parent["_families"]},
            key=lambda item: item.encode("utf-8"),
        ))
        if not set(inherited).issubset(set(child["_families"])):
            fail("family_closure_invalid")
        if self.confidentiality.index(child["confidentiality"]) < max(
            self.confidentiality.index(parent["confidentiality"]) for parent in parents
        ):
            fail("confidentiality_downgrade")
        if self.integrity.index(child["integrity"]) > min(
            self.integrity.index(parent["integrity"]) for parent in parents
        ):
            fail("integrity_elevation")
        if self.action.index(child["action_class"]) > min(
            self.action.index(parent["action_class"]) for parent in parents
        ):
            fail("action_class_elevation")
        return {"valid": True, "parent_count": len(parents)}

    @staticmethod
    def corroborator(value: Any) -> dict[str, Any]:
        try:
            exact_keys(value, {
                "principal_id", "valid_from", "administrative_domain_sha256",
                "upstream_source_sha256", "license_sha256",
            })
            identifier(value["principal_id"])
            timestamp(value["valid_from"])
            hash32(value["administrative_domain_sha256"])
            hash32(value["upstream_source_sha256"])
            hash32(value["license_sha256"])
            return value
        except VerifyError:
            fail("corroborator_shape_invalid")

    def elevation(self, value: dict[str, Any]) -> dict[str, Any]:
        exact_keys(value, {
            "schema", "company_id", "elevation_id", "value_sha256", "family_id",
            "action_scope", "risk_class", "base_origin_sha256s", "corroborators",
            "threshold", "user_authorization_sha256", "maximum_uses", "valid_from",
            "valid_until", "created_at",
        })
        if value["schema"] != SCHEMAS["elevation"]:
            fail("schema_invalid")
        identifier(value["company_id"])
        uuid(value["elevation_id"])
        hash32(value["value_sha256"])
        if value["family_id"] not in self.families:
            fail("family_id_invalid")
        identifier(value["action_scope"])
        enum(value["risk_class"], self.risk)
        ordered_unique(value["base_origin_sha256s"], 64, hash32,
                       "parent_order_invalid", "parent_duplicate", "parent_count_invalid")
        corroborators = value["corroborators"]
        if not isinstance(corroborators, list) or len(corroborators) > 16:
            fail("corroborator_count_invalid")
        normalized = [self.corroborator(item) for item in corroborators]
        keys = [":".join((item["administrative_domain_sha256"], item["upstream_source_sha256"],
                          item["principal_id"], item["valid_from"])) for item in normalized]
        if len(set(keys)) != len(keys):
            fail("corroborator_duplicate")
        if keys != sorted(keys, key=lambda item: item.encode()):
            fail("corroborator_order_invalid")
        if len({item["administrative_domain_sha256"] for item in normalized}) != len(normalized):
            fail("corroborator_independence_invalid")
        if len({item["upstream_source_sha256"] for item in normalized}) != len(normalized):
            fail("corroborator_independence_invalid")
        threshold = integer(value["threshold"], 2, 16)
        user_authorization = value["user_authorization_sha256"]
        if user_authorization is not None:
            hash32(user_authorization)
        integer(value["maximum_uses"], 1, 1)
        if user_authorization is None and len(normalized) < threshold:
            fail("elevation_authority_invalid")
        valid_from = timestamp(value["valid_from"])
        valid_until = timestamp(value["valid_until"])
        created_at = timestamp(value["created_at"])
        if valid_until <= valid_from or created_at > valid_until:
            fail("timestamp_order_invalid")
        return {**value, "elevation_sha256": protocol_hash(value)}

    def action_verdict(self, value: dict[str, Any]) -> dict[str, Any]:
        exact_keys(value, {
            "schema", "company_id", "verdict_id", "actor", "tool_name", "action_scope",
            "risk_class", "arguments_sha256", "security_values", "family_ids",
            "input_origin_sha256s", "untrusted_influence", "elevation_sha256",
            "user_authorization_sha256", "decision", "failure_code",
            "previous_verdict_sha256", "created_at",
        })
        if value["schema"] != SCHEMAS["action_verdict"]:
            fail("schema_invalid")
        identifier(value["company_id"])
        uuid(value["verdict_id"])
        self.actor(value["actor"])
        identifier(value["tool_name"])
        identifier(value["action_scope"])
        enum(value["risk_class"], self.risk)
        hash32(value["arguments_sha256"])
        security_values = value["security_values"]
        if not isinstance(security_values, list) or not 1 <= len(security_values) <= 64:
            fail("security_value_shape_invalid")
        value_hashes: list[str] = []
        value_families: list[str] = []
        for security_value in security_values:
            if not isinstance(security_value, dict):
                fail("security_value_shape_invalid")
            try:
                exact_keys(security_value, {"value_sha256", "family_ids"})
            except VerifyError:
                fail("security_value_shape_invalid")
            value_hashes.append(hash32(security_value["value_sha256"]))
            value_families.extend(self.exact_family_closure(security_value["family_ids"]))
        if len(set(value_hashes)) != len(value_hashes):
            fail("security_value_duplicate")
        if value_hashes != sorted(value_hashes, key=lambda item: item.encode()):
            fail("security_value_order_invalid")
        verdict_families = self.exact_family_closure(value["family_ids"])
        if verdict_families != self.family_closure(sorted(
                set(value_families), key=lambda item: item.encode("utf-8"))):
            fail("security_value_family_binding_invalid")
        ordered_unique(value["input_origin_sha256s"], 64, hash32,
                       "parent_order_invalid", "parent_duplicate", "parent_count_invalid")
        if not isinstance(value["untrusted_influence"], bool):
            fail("verdict_semantics_invalid")
        for key in ("elevation_sha256", "user_authorization_sha256", "previous_verdict_sha256"):
            if value[key] is not None:
                hash32(value[key])
        decision = enum(value["decision"], ["ALLOW", "DENY", "INDETERMINATE"])
        failure_code = value["failure_code"]
        if failure_code is not None:
            enum(failure_code, [
                "origin_missing", "origin_invalid", "family_missing", "family_policy_unsatisfied",
                "input_attribution_indeterminate", "untrusted_influence_unlicensed",
                "corroboration_insufficient", "corroboration_not_independent",
                "user_authorization_missing", "user_authorization_invalid",
                "user_authorization_replayed", "action_substitution", "scope_invalid",
                "identity_epoch_invalid", "evidence_expired_or_revoked",
            ])
        if decision == "ALLOW" and failure_code is not None:
            fail("verdict_semantics_invalid")
        if decision != "ALLOW" and failure_code is None:
            fail("verdict_semantics_invalid")
        if (decision == "ALLOW" and value["untrusted_influence"]
                and value["elevation_sha256"] is None
                and value["user_authorization_sha256"] is None):
            fail("verdict_semantics_invalid")
        timestamp(value["created_at"])
        return {**value, "verdict_sha256": protocol_hash(value)}

    def execute(self, operation: str, value: Any) -> dict[str, Any]:
        if operation == "family_profile_hash":
            self.validate_profile(value)
            return {"valid": True, "sha256": protocol_hash(value)}
        if operation == "memory_binding":
            return {"valid": True, "sha256": self.binding(value)["binding_sha256"]}
        if operation == "derivation":
            return self.derivation(value)
        if operation == "elevation":
            return {"valid": True, "sha256": self.elevation(value)["elevation_sha256"]}
        if operation == "action_verdict":
            return {"valid": True, "sha256": self.action_verdict(value)["verdict_sha256"]}
        fail("vector_operation_invalid")


def verify_vectors(verifier: ProtocolVerifier, artifact: dict[str, Any]) -> tuple[int, int]:
    unsigned = {key: artifact[key] for key in ("schema", "intended_n", "valid_n", "invalid_n", "vectors")}
    if sha(canonical_bytes(unsigned)) != artifact["manifest_sha256"]:
        fail("vector_manifest_invalid")
    if sha(canonical_bytes(artifact["vectors"])) != artifact["vectors_root_sha256"]:
        fail("vector_root_invalid")
    if artifact["intended_n"] != len(artifact["vectors"]):
        fail("vector_count_invalid")
    passed = 0
    for vector in artifact["vectors"]:
        expected = vector["expected"]
        try:
            actual = verifier.execute(vector["operation"], vector["input"])
            if expected.get("valid") is not True or actual != expected:
                fail(f"vector_result_mismatch:{vector['id']}")
        except VerifyError as error:
            if expected != {"valid": False, "failure_code": error.code}:
                fail(f"vector_failure_mismatch:{vector['id']}:{error.code}")
        passed += 1
    return passed, artifact["invalid_n"]


def verify_source_manifest(artifact: dict[str, Any]) -> None:
    unsigned = {key: artifact[key] for key in (
        "schema", "source_file_count", "source_files", "source_root_sha256",
    )}
    if sha(canonical_bytes(unsigned)) != artifact["manifest_sha256"]:
        fail("source_manifest_invalid")
    if artifact["source_file_count"] != len(artifact["source_files"]):
        fail("source_file_count_invalid")
    if sha(canonical_bytes(artifact["source_files"])) != artifact["source_root_sha256"]:
        fail("source_root_invalid")
    for entry in artifact["source_files"]:
        file = ROOT / entry["path"]
        if not file.is_file() or sha(file.read_bytes()) != entry["sha256"]:
            fail(f"source_file_invalid:{entry['path']}")


def verify_census(artifact: dict[str, Any], compare_current_source: bool) -> None:
    unsigned = {key: value for key, value in artifact.items() if key != "census_sha256"}
    if sha(canonical_bytes(unsigned)) != artifact["census_sha256"]:
        fail("source_census_hash_invalid")
    declared = [
        (site["file"], site["line"], site["site_sha256"])
        for site in artifact["direct_memory_read_sites"]
    ]
    if artifact["direct_memory_read_site_count"] != len(declared):
        fail("source_census_site_count_invalid")
    if artifact["direct_memory_read_file_count"] != len({row[0] for row in declared}):
        fail("source_census_file_count_invalid")
    critical = sum(
        1 for site in artifact["direct_memory_read_sites"]
        if site["classification"] in CRITICAL_CLASSIFICATIONS
    )
    if critical != artifact["model_or_action_influencing_site_count"]:
        fail("source_census_critical_count_invalid")
    if any(not site["classification"] or not site["closure_owner"]
           for site in artifact["direct_memory_read_sites"]):
        fail("source_census_unclassified_site")
    if compare_current_source:
        observed: list[tuple[str, int, str]] = []
        files: list[Path] = []
        for root_name in PRODUCTION_SCAN_ROOTS:
            files.extend(file for file in (ROOT / root_name).rglob("*")
                         if file.is_file() and file.suffix in {".js", ".mjs", ".cjs", ".sql"})
        for file in sorted(files, key=lambda item: item.relative_to(ROOT).as_posix()):
            relative = file.relative_to(ROOT).as_posix()
            lines = file.read_text(encoding="utf-8").split("\n")
            for index, line in enumerate(lines):
                if not MEMORY_READ.search(line):
                    continue
                context = "\n".join(item.strip() for item in lines[max(0, index - 3):index + 4])
                site_hash = sha(canonical_bytes({"file": relative, "line": index + 1, "context": context}))
                observed.append((relative, index + 1, site_hash))
        if observed != declared:
            fail("source_census_coverage_invalid")


def main() -> None:
    unknown = [arg for arg in sys.argv[1:] if arg != "--artifacts-only"]
    if unknown:
        fail("verifier_argument_invalid")
    artifacts_only = "--artifacts-only" in sys.argv[1:]
    file_hashes = {name: verify_sidecar(name) for name in (
        "family-profile.json", "vectors.json", "source-census.json",
        "source-manifest.json", "protocol-manifest.json",
    )}
    profile_artifact = read_json("family-profile.json")
    exact_keys(profile_artifact, {"body", "profile_sha256"})
    if profile_artifact["profile_sha256"] != PROFILE_HASH:
        fail("family_profile_hash_invalid")
    if protocol_hash(profile_artifact["body"]) != PROFILE_HASH:
        fail("family_profile_hash_invalid")
    verifier = ProtocolVerifier(profile_artifact["body"])
    vectors = read_json("vectors.json")
    vector_count, invalid_count = verify_vectors(verifier, vectors)
    census = read_json("source-census.json")
    verify_census(census, compare_current_source=not artifacts_only)
    source_manifest = read_json("source-manifest.json")
    if not artifacts_only:
        verify_source_manifest(source_manifest)
    manifest = read_json("protocol-manifest.json")
    unsigned = {key: value for key, value in manifest.items() if key != "protocol_root_sha256"}
    if sha(canonical_bytes(unsigned)) != manifest["protocol_root_sha256"]:
        fail("protocol_root_invalid")
    if manifest["schemas"] != SCHEMAS:
        fail("protocol_schema_manifest_invalid")
    expected_domains = {key: (schema.encode() + b"\0").hex() for key, schema in SCHEMAS.items()}
    if manifest["domains_hex"] != expected_domains:
        fail("protocol_domain_manifest_invalid")
    if manifest["family_profile"]["profile_sha256"] != PROFILE_HASH:
        fail("protocol_profile_manifest_invalid")
    if manifest["family_profile"]["file_sha256"] != file_hashes["family-profile.json"]:
        fail("protocol_profile_file_invalid")
    if manifest["vectors"]["file_sha256"] != file_hashes["vectors.json"]:
        fail("protocol_vector_file_invalid")
    if manifest["source_census"]["file_sha256"] != file_hashes["source-census.json"]:
        fail("protocol_census_file_invalid")
    if manifest["source_manifest"]["file_sha256"] != file_hashes["source-manifest.json"]:
        fail("protocol_source_file_invalid")
    if manifest["source_root_sha256"] != source_manifest["source_root_sha256"]:
        fail("protocol_source_root_invalid")
    if manifest["source_file_count"] != source_manifest["source_file_count"]:
        fail("protocol_source_count_invalid")
    if manifest["production_runtime_importers"] != []:
        fail("protocol_runtime_importer_invalid")
    if manifest["database_mutation"] or manifest["runtime_activation"] or manifest["memory_write"]:
        fail("protocol_authority_boundary_invalid")
    print(json.dumps({
        "success": True,
        "status": "OB1_INDEPENDENT_FROZEN_PROTOCOL_VERIFIED" if artifacts_only
                  else "OB1_INDEPENDENT_PROTOCOL_AND_POINT_IN_TIME_SOURCE_VERIFIED",
        "protocol_root_sha256": manifest["protocol_root_sha256"],
        "family_profile_sha256": PROFILE_HASH,
        "vectors_verified": vector_count,
        "negative_vectors_verified": invalid_count,
        "direct_memory_read_sites_verified": census["direct_memory_read_site_count"],
        "source_files_verified": source_manifest["source_file_count"],
        "source_root_sha256": source_manifest["source_root_sha256"],
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except VerifyError as error:
        print(json.dumps({"success": False, "error": error.code}), file=sys.stderr)
        raise SystemExit(1)
