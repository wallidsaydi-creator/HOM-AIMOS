#!/usr/bin/env python3
"""JSON-lines CLI for the independent MutMem V2 Python crypto kernel."""

from __future__ import annotations

import json
import resource
import sys
import time

import cryptography

from crypto_kernel import (
    canonical_json,
    occurrence_commitment_v3,
    recall_merkle_root,
    verify_certificate,
    verify_ed25519,
    verify_occurrence_signature_v3,
)

MAXIMUM_INPUT_BYTES = 64 * 1024 * 1024


def execute(request: dict) -> dict:
    operation = request.get("operation")
    if operation == "canonical_json":
        return {"canonical_json": canonical_json(request.get("value"))}
    if operation == "recall_merkle_root":
        return {"root_sha256": recall_merkle_root(request.get("entries")).hex()}
    if operation == "measure_merkle":
        count = request.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1 or count > 100_000:
            raise ValueError("measurement_count_invalid")
        entries = [{"ordinal": ordinal, "value": f"entry-{ordinal}"} for ordinal in range(count)]
        started = time.perf_counter_ns()
        root = recall_merkle_root(entries).hex()
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_bytes = int(peak if sys.platform == "darwin" else peak * 1024)
        return {
            "count": count,
            "root_sha256": root,
            "elapsed_ms": elapsed_ms,
            "peak_rss_bytes": peak_bytes,
            "time_complexity": "O(n)",
            "auxiliary_peak_space": "O(log n)",
            "python_version": sys.version.split()[0],
            "cryptography_version": cryptography.__version__,
        }
    if operation == "verify_ed25519":
        return {
            "valid": verify_ed25519(
                request.get("public_key"),
                bytes.fromhex(request.get("message_hex") or ""),
                request.get("signature"),
            )
        }
    if operation == "verify_certificate":
        return verify_certificate(
            certificate=request.get("certificate"),
            authority_public_key=request.get("authority_public_key"),
            expected_agent_id=request.get("expected_agent_id"),
            expected_subject_public_key=request.get("expected_subject_public_key"),
            at_unix_seconds=request.get("at_unix_seconds"),
        )
    if operation == "occurrence":
        record = request.get("record")
        commitment = occurrence_commitment_v3(record)
        return {
            "commitment_sha256": commitment,
            "signature_valid": verify_occurrence_signature_v3(
                record, request.get("signature"), request.get("public_key")
            ),
        }
    raise ValueError("unsupported_operation")


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAXIMUM_INPUT_BYTES + 1)
        if len(raw) > MAXIMUM_INPUT_BYTES:
            raise ValueError("input_size_invalid")
        request = json.loads(raw)
        result = execute(request)
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
    except Exception as error:
        sys.stdout.write(
            json.dumps(
                {"valid": False, "error": str(error)},
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
