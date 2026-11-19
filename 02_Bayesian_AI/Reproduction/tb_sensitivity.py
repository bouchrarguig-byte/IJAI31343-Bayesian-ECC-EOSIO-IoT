#!/usr/bin/env python3
"""Sensitivity of the lifetime policy to the externally assumed horizon T_b.

SYNTHETIC ONLY. Uses the published controller (exact posterior quantile, so no
Monte Carlo noise), the published prior/lambda/bounds, and the six synthetic
scenarios with the same seeds as ijai31343_adversarial_ai_stats.py. T_b is a
scenario assumption supplied from outside; nothing here estimates it.

Usage (repository root): python 02_Bayesian_AI/Reproduction/tb_sensitivity.py
"""
from __future__ import annotations
import csv, statistics as st, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "02_Bayesian_AI" / "Controller"))
sys.path.insert(0, str(HERE))
from intelligent_key_renewal import (AdaptiveRotationPolicy, BayesianRiskEstimator,  # noqa: E402
                                     PolicyConfig, UnsafePolicyError)
from ijai31343_adversarial_ai_stats import BASE_SEED, SCENARIOS, simulate_labels      # noqa: E402

TB_VALUES = (100, 150, 200, 300, 600, 1200)
REPLICATES, LENGTH = 12, 120


def run(tb: float):
    accepted, rejected, capped, n = [], 0, 0, 0
    for sidx, scenario in enumerate(SCENARIOS):
        for rep in range(REPLICATES):
            events = simulate_labels(scenario, BASE_SEED + sidx * 100_000 + rep, LENGTH)
            cfg = PolicyConfig(posterior_method="exact")
            est = BayesianRiskEstimator(cfg)
            pol = AdaptiveRotationPolicy(cfg, est)
            for ev in events:
                est.observe(ev)
                n += 1
                try:
                    out = pol.select_interval(float(tb))
                except UnsafePolicyError:
                    rejected += 1
                    continue
                t = out["interval_seconds"] if "interval_seconds" in out else next(
                    v for k, v in out.items() if "interval" in k and isinstance(v, (int, float)))
                accepted.append(t)
                risk_limited = cfg.baseline_seconds / (1 + cfg.risk_sensitivity * est.posterior_upper_bound())
                capped += cfg.safety_fraction * tb < min(cfg.maximum_seconds, risk_limited) - 1e-9
    return n, accepted, rejected, capped


def main():
    rows = []
    for tb in TB_VALUES:
        n, acc, rej, cap = run(tb)
        rows.append({"T_b_s": tb, "observations": n,
                     "rejected_pct": round(100 * rej / n, 1),
                     "capped_by_0.7Tb_pct": round(100 * cap / n, 1),
                     "mean_accepted_interval_s": round(st.mean(acc), 2) if acc else ""})
    out = REPO / "05_Experimental_Results/Bayesian_AI/tb_sensitivity.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"{'T_b (s)':>8}{'rejected %':>12}{'capped %':>10}{'mean T (s)':>12}")
    for r in rows:
        print(f"{r['T_b_s']:>8}{r['rejected_pct']:>12}{r['capped_by_0.7Tb_pct']:>10}{str(r['mean_accepted_interval_s']):>12}")
    print("Synthetic scenarios, exact posterior quantile, 6 x 12 x 120 = 8640 observations. CSV:", out)


if __name__ == "__main__":
    main()
