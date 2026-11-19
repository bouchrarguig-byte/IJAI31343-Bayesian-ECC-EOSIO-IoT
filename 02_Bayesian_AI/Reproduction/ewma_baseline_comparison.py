#!/usr/bin/env python3
"""One-step-ahead (prequential) Brier comparison with EWMA baselines.

SYNTHETIC ONLY. Same scenarios and seeds as ijai31343_adversarial_ai_stats.py
(6 scenarios x 12 seeds x 120 observations). The cumulative, 20-observation
window and constant-0.05 predictors are recomputed and checked against the
archived CSV; two exponentially weighted moving averages (alpha 0.05 and 0.10,
initialised at the prior mean 0.05) are added. Lower Brier is better.

Usage (repository root): python 02_Bayesian_AI/Reproduction/ewma_baseline_comparison.py
"""
from __future__ import annotations
import csv, statistics as st, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from ijai31343_adversarial_ai_stats import BASE_SEED, SCENARIOS, simulate_labels  # noqa: E402

PREDICTORS = ("cumulative", "window20", "ewma0p05", "ewma0p10", "constant0p05")


def brier(events, predictor):
    s = n = 0
    window, ewma = [], 0.05
    alpha = {"ewma0p05": 0.05, "ewma0p10": 0.10}.get(predictor)
    total = 0.0
    for ev in events:
        y = 0 if ev == "success" else 1
        if predictor == "cumulative":
            p = (1 + s) / (20 + s + n)
        elif predictor == "window20":
            p = (1 + sum(window)) / (20 + len(window))
        elif alpha is not None:
            p = ewma
        else:
            p = 0.05
        total += (p - y) ** 2
        s, n = s + y, n + 1 - y
        window = (window + [y])[-20:]
        if alpha is not None:
            ewma = (1 - alpha) * ewma + alpha * y
    return total / len(events)


def main():
    rows = []
    for sidx, scenario in enumerate(SCENARIOS):
        for pred in PREDICTORS:
            vals = [brier(simulate_labels(scenario, BASE_SEED + sidx * 100_000 + r, 120), pred) for r in range(12)]
            rows.append({"scenario": scenario, "predictor": pred, "n_seeds": 12,
                         "mean_brier": round(st.mean(vals), 5), "sd_across_seeds": round(st.stdev(vals), 5)})
    # consistency check against the archived Brier table
    archive = REPO / "05_Experimental_Results/Bayesian_AI/synthetic_prequential_brier_aggregates.csv"
    ref = {(r["scenario"], r["predictor"]): float(r["mean_prequential_brier"]) for r in csv.DictReader(archive.open())}
    worst = max(abs(r["mean_brier"] - ref[(r["scenario"], r["predictor"])])
                for r in rows if (r["scenario"], r["predictor"]) in ref)
    out = REPO / "05_Experimental_Results/Bayesian_AI/ewma_baseline_comparison.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"{'scenario':<22}" + "".join(f"{p:>14}" for p in PREDICTORS))
    for sc in SCENARIOS:
        print(f"{sc:<22}" + "".join(f"{next(r['mean_brier'] for r in rows if r['scenario']==sc and r['predictor']==p):>14.4f}" for p in PREDICTORS))
    wins = {p: sum(1 for sc in SCENARIOS if min((r for r in rows if r['scenario']==sc), key=lambda r: r['mean_brier'])['predictor'] == p) for p in PREDICTORS}
    print("best predictor per scenario (count):", wins)
    print(f"max |difference| vs archived table (shared predictors): {worst:.2e}")
    print("Synthetic scenarios only. CSV:", out)


if __name__ == "__main__":
    main()
