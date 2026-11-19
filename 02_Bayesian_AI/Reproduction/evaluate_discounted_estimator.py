#!/usr/bin/env python3
"""Offline comparison: cumulative Beta-Bernoulli (published) vs discounted variants.

SYNTHETIC ONLY. It reuses the scenario generator and seeds of
ijai31343_adversarial_ai_stats.py (6 scenarios, 12 seeds, 120 observations)
and the published prior Beta(1, 19), lambda = 4 and 95% upper quantile. All
posterior quantiles here are EXACT (no Monte Carlo), so differences between
rows are model differences, not simulation noise.

Nothing here is a hardware, attack-detection or energy result. The scenarios are
author-designed, so improvements on them are a sanity check of the mechanism,
not evidence of field performance.

Usage (from the repository root):
    python 02_Bayesian_AI/Reproduction/evaluate_discounted_estimator.py
"""
from __future__ import annotations

import argparse
import csv
import statistics as st
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "02_Bayesian_AI" / "Controller"))
sys.path.insert(0, str(HERE))

from intelligent_key_renewal import beta_ppf          # noqa: E402
from ijai31343_adversarial_ai_stats import BASE_SEED, SCENARIOS, simulate_labels  # noqa: E402

HORIZON, BASELINE, LAMBDA, MAXIMUM, MINIMUM = 600.0, 120.0, 4.0, 300.0, 10.0
PRIOR_A, PRIOR_B, CONF = 1, 19, 0.95
VARIANTS = ("cumulative_published", "window20_published", "discount_0.98", "discount_0.95", "discount_0.90")


def interval(risk: float) -> float:
    return min(MAXIMUM, 0.7 * HORIZON, BASELINE / (1.0 + LAMBDA * risk))


def run(events, variant):
    """Return per-step (prediction, interval) before/after each observation."""
    n_bad = n_ok = 0.0
    window = []
    out = []
    decay = 1.0
    if variant.startswith("discount_"):
        decay = float(variant.split("_")[1])
    for ev in events:
        y = 0 if ev == "success" else 1
        # one-step-ahead prediction BEFORE seeing this label
        if variant == "window20_published":
            pred = (PRIOR_A + sum(window)) / (PRIOR_A + PRIOR_B + len(window))
        else:
            pred = (PRIOR_A + n_bad) / (PRIOR_A + PRIOR_B + n_bad + n_ok)
        # update
        if variant == "window20_published":
            window.append(y)
            window = window[-20:]
            a, b = PRIOR_A + sum(window), PRIOR_B + len(window) - sum(window)
        else:
            n_bad, n_ok = n_bad * decay, n_ok * decay
            if y:
                n_bad += 1
            else:
                n_ok += 1
            a, b = PRIOR_A + n_bad, PRIOR_B + n_ok
        out.append((pred, y, interval(beta_ppf(CONF, a, b))))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--replicates", type=int, default=12)
    ap.add_argument("--length", type=int, default=120)
    ap.add_argument("--output", type=Path,
                    default=REPO / "05_Experimental_Results/Bayesian_AI/discounted_estimator_comparison.csv")
    args = ap.parse_args()

    rows = []
    for sidx, scenario in enumerate(SCENARIOS):
        for variant in VARIANTS:
            brier, mean_int, below60, post_attack, recover = [], [], [], [], []
            for rep in range(args.replicates):
                seed = BASE_SEED + sidx * 100_000 + rep          # same seeds as the published study
                events = simulate_labels(scenario, seed, args.length)
                steps = run(events, variant)
                brier.append(st.mean((p - y) ** 2 for p, y, _ in steps))
                ints = [t for *_, t in steps]
                mean_int.append(st.mean(ints))
                below60.append(sum(t < 60 for t in ints) / len(ints))
                if scenario == "attack_then_recovery":
                    end = args.length // 2                         # attack ends here (generator definition)
                    post = ints[end + 10:]
                    post_attack.append(st.mean(post))
                    first = next((i for i, t in enumerate(ints[end:]) if t >= 70.0), None)
                    recover.append(args.length - end if first is None else first)
            rows.append({
                "scenario": scenario, "estimator": variant, "n_seeds": args.replicates,
                "mean_brier": round(st.mean(brier), 5),
                "mean_interval_s": round(st.mean(mean_int), 2),
                "fraction_below_60s": round(st.mean(below60), 3),
                "post_attack_mean_interval_s": round(st.mean(post_attack), 2) if post_attack else "",
                "steps_to_reach_70s_after_attack": round(st.mean(recover), 1) if recover else "",
            })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print(f"{'scenario':<22}{'estimator':<22}{'Brier':>8}{'mean T(s)':>10}{'<60s':>7}{'post-attack T':>15}{'steps->70s':>12}")
    for r in rows:
        print(f"{r['scenario']:<22}{r['estimator']:<22}{r['mean_brier']:>8.4f}{r['mean_interval_s']:>10.2f}"
              f"{r['fraction_below_60s']:>7.3f}{str(r['post_attack_mean_interval_s']):>15}"
              f"{str(r['steps_to_reach_70s_after_attack']):>12}")
    print("\nSYNTHETIC scenarios only; exact posterior quantiles; same seeds as the published study.")
    print("CSV:", args.output)


if __name__ == "__main__":
    main()
