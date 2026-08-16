#!/usr/bin/env python3
"""Independent high-precision audit for HOM-AIMOS edit certificates.

This verifier intentionally imports no AIMOS JavaScript. It checks the frozen
Hoeffding/CERT-ED fixed-point construction from JSON vectors using Python's
Decimal arithmetic and exact integer comparisons for the certified radius.
"""

from __future__ import annotations

import argparse
import json
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from pathlib import Path


SCALE = 1_000_000


def audit_vector(vector: dict) -> dict:
    selected = int(vector["selectedCount"])
    n_certify = int(vector["nCertify"])
    n_max = int(vector["nMax"])
    alpha = vector["alphaFamily"]
    p_del = vector["pDel"]

    with localcontext() as context:
        context.prec = 100
        fraction_ppm = int(
            (Decimal(selected) * SCALE / Decimal(n_certify)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        )
        reciprocal = (
            Decimal(int(alpha["denominator"]))
            * Decimal(n_max)
            / Decimal(int(alpha["numerator"]))
        )
        penalty = (reciprocal.ln() / (Decimal(2) * n_certify)).sqrt()
        penalty_ppm = int(
            (penalty * SCALE).to_integral_value(rounding=ROUND_CEILING)
        )

    mu_ppm = max(0, fraction_ppm - penalty_ppm)
    runner_ppm = SCALE - mu_ppm
    common = {
        "fraction_ppm": fraction_ppm,
        "penalty_ppm": penalty_ppm,
        "mu_lower_ppm": mu_ppm,
        "runner_upper_ppm": runner_ppm,
    }
    if mu_ppm <= SCALE // 2:
        return {
            "outcome": "abstain",
            "reason": "confidence_not_above_half",
            **common,
            "radius": None,
        }

    argument_ppm = 1_500_000 - mu_ppm
    p_num = int(p_del["numerator"])
    p_den = int(p_del["denominator"])
    numerator_power = 1
    denominator_power = 1
    radius = 0
    for candidate in range(1, 100_001):
        numerator_power *= p_num
        denominator_power *= p_den
        if numerator_power * SCALE < argument_ppm * denominator_power:
            break
        radius = candidate

    return {
        "outcome": "certified",
        "reason": None,
        **common,
        "theorem_argument_ppm": argument_ppm,
        "radius": radius,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", required=True, type=Path)
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text(encoding="utf-8"))
    failures = []
    results = []
    for vector in vectors:
        actual = audit_vector(vector)
        results.append({"id": vector["id"], "actual": actual})
        if actual != vector["expected"]:
            failures.append({
                "id": vector["id"],
                "expected": vector["expected"],
                "actual": actual,
            })
    print(json.dumps({"success": not failures, "results": results, "failures": failures}, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
