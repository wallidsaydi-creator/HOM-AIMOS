#!/usr/bin/env python3
"""Offline command-line entrypoint for the independent MutMem verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from mutmem_verifier import (
    MAX_BUNDLE_BYTES,
    SCHEMA,
    VERIFIER_VERSION,
    VerificationError,
    parse_bundle,
    verify_bundle,
)
from recall_verifier import (
    CORPUS_SCHEMA,
    RECALL_SCHEMA,
    verify_recall_bundle,
    verify_recall_corpus,
)


class ContractArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(json.dumps({
            "verdict": "indeterminate",
            "primary_reason": "malformed_invocation",
            "diagnostic": message,
        }, sort_keys=True, separators=(",", ":")))
        raise SystemExit(3)


def source_hash() -> str:
    owner = Path(__file__).with_name("mutmem_verifier.py")
    cli = Path(__file__)
    digest = hashlib.sha256()
    recall_owner = Path(__file__).with_name("recall_verifier.py")
    for path in (owner, recall_owner, cli):
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def read_bounded_bundle(location: str) -> bytes:
    """Read at most the declared hostile-input ceiling plus one sentinel byte."""
    if location == "-":
        return sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    path = Path(location)
    if path.is_symlink():
        raise VerificationError("bundle_path_symlink")
    with path.open("rb") as handle:
        return handle.read(MAX_BUNDLE_BYTES + 1)


def main() -> int:
    parser = ContractArgumentParser(prog="mutmem-verify")
    parser.add_argument("operation", choices=(
        "verify-bundle", "verify-recall", "verify-corpus", "inspect", "version",
    ))
    parser.add_argument("bundle", nargs="?")
    args = parser.parse_args()
    identity = {
        "verifier_version": VERIFIER_VERSION,
        "supported_schemas": [SCHEMA, RECALL_SCHEMA, CORPUS_SCHEMA],
        "source_sha256": source_hash(),
    }
    if args.operation == "version":
        print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
        return 0
    if args.bundle is None:
        parser.error("bundle is required")
    try:
        raw = read_bounded_bundle(args.bundle)
        document = parse_bundle(raw)
        schema = document.get("format", {}).get("schema")
        if args.operation == "inspect":
            output = {
                **identity,
                "authority": "non_authoritative_inspection",
                "schema": schema,
                "company_id": document.get("company_id"),
                "event_stream_count": len(document.get("event_streams", [])),
                "memory_count": len(document.get("memories", [])),
                "sql_record_count": len(document.get("sql_records", [])),
            }
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.operation == "verify-corpus":
            output = {**verify_recall_corpus(document), **identity}
        elif args.operation == "verify-recall":
            output = {**verify_recall_bundle(document), **identity}
        elif schema == SCHEMA:
            output = {**verify_bundle(document), **identity}
        elif schema == RECALL_SCHEMA:
            output = {**verify_recall_bundle(document), **identity}
        else:
            raise VerificationError("unsupported_schema")
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0 if output["verdict"] == "valid" else 2 if output["verdict"] == "indeterminate" else 1
    except VerificationError as exc:
        print(json.dumps({
            **identity,
            "verdict": "invalid",
            "primary_reason": str(exc),
        }, sort_keys=True, separators=(",", ":")))
        return 1
    except OSError as exc:
        print(json.dumps({
            **identity,
            "verdict": "indeterminate",
            "primary_reason": "bundle_unavailable",
            "diagnostic": exc.__class__.__name__,
        }, sort_keys=True, separators=(",", ":")))
        return 2
    except Exception as exc:
        print(json.dumps({
            **identity,
            "verdict": "indeterminate",
            "primary_reason": "verifier_internal_failure",
            "diagnostic": exc.__class__.__name__,
        }, sort_keys=True, separators=(",", ":")))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
