#!/usr/bin/env python3
"""JSON CLI for the independent MutMem V2 Python verifiers."""

from __future__ import annotations

import json
import sys

from mutation_verifier import MutMemMutationVerificationError, verify_mutation_bundle
from recall_verifier import (
    MutMemRecallVerificationError,
    recall_authorization_mutation_hash_for_parity,
    request_receipt_mutation_hash_for_parity,
    verify_recall_envelope,
)

MAXIMUM_INPUT_BYTES = 64 * 1024 * 1024


def _terminal(profile: str, request: dict) -> dict:
    try:
        if profile == "recall":
            result = verify_recall_envelope(
                request["bundle"],
                expected_master_fingerprint=request.get("expected_master_fingerprint"),
                verify_cryptography=request.get("verify_cryptography", True),
            )
        elif profile == "mutation":
            result = verify_mutation_bundle(
                request["bundle"],
                witness=request.get("witness"),
                trust_context=request.get("trust_context"),
                expected_master_fingerprint=request.get("expected_master_fingerprint"),
                verify_cryptography=request.get("verify_cryptography", False),
            )
        else:
            raise ValueError("profile_invalid")
        return {"valid": True, "reason": None, "result": result}
    except (MutMemRecallVerificationError, MutMemMutationVerificationError) as error:
        return {"valid": False, "reason": error.reason, "result": None}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAXIMUM_INPUT_BYTES + 1)
        if len(raw) > MAXIMUM_INPUT_BYTES:
            raise ValueError("input_size_invalid")
        request = json.loads(raw)
        if request.get("operation") == "byte_parity":
            recall = request["recall_authorization"]
            receipt = request["request_receipt"]
            result = {
                "recall_authorization_mutation_hash":
                    recall_authorization_mutation_hash_for_parity(**recall),
                "request_receipt_mutation_hash":
                    request_receipt_mutation_hash_for_parity(**receipt),
            }
        elif request.get("operation") == "batch":
            result = {
                "terminals": [
                    {"id": item.get("id"), **_terminal(request["profile"], item)}
                    for item in request.get("items", [])
                ]
            }
        else:
            result = _terminal(request["profile"], request)
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
    except Exception as error:
        sys.stdout.write(json.dumps({"valid": False, "error": str(error)}, sort_keys=True) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
