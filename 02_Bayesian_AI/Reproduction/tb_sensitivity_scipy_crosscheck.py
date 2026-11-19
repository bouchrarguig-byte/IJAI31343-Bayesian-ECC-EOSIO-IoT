#!/usr/bin/env python3
"""Offline reproducible T_b sensitivity for IJ-AI 31343.

Synthetic scenario experiment only. No measured compromise time or actual attacks.
The quantile is EXACT beta.ppf (SciPy), not a Monte Carlo approximation.
Nothing here changes the authenticated key-exchange protocol.
"""
from __future__ import annotations
import argparse
import csv
import json
import random
from functools import lru_cache
from pathlib import Path
from scipy.stats import beta as beta_distribution

BASE_SEED = 31343
SCENARIOS = ('benign','burst_invalid_proofs','step_rise','gradual_ramp','attack_then_recovery','forged_alarm_flood')


def simulated_labels(scenario: str, seed: int, length: int = 120):
    """Match published six-scenario generator in ijai31343_adversarial_ai_stats.py."""
    rng = random.Random(seed)
    for i in range(length):
        rel = i / max(length - 1, 1)
        if scenario == 'benign': p = .01
        elif scenario == 'burst_invalid_proofs':
            p = 1.0 if length//3 <= i < length//3+6 or 2*length//3 <= i < 2*length//3+6 else .01
        elif scenario == 'step_rise': p = .45 if length//3 <= i < 2*length//3 else .01
        elif scenario == 'gradual_ramp': p = .01 + .49 * rel
        elif scenario == 'attack_then_recovery': p = .65 if length//6 <= i < length//2 else .01
        elif scenario == 'forged_alarm_flood': p = 1.0 if length//3 <= i < 2*length//3 else .01
        else: raise ValueError('Unknown scenario: '+scenario)
        yield int(rng.random() < p)


@lru_cache(maxsize=None)
def exact_upper_95(n_suspicious: int, n_ordinary: int) -> float:
    return float(beta_distribution.ppf(.95, 1 + n_suspicious, 19 + n_ordinary))


def experiments(horizons=(100, 150, 200, 600, 1200), length=120, n_seeds=12):
    times = []
    for si, scenario in enumerate(SCENARIOS):
        for rep in range(n_seeds):
            ordinary = suspicious = 0
            for event in simulated_labels(scenario, BASE_SEED + si*100000 + rep, length):
                if event: suspicious += 1
                else: ordinary += 1
                risk = exact_upper_95(suspicious, ordinary)
                unbounded = 120.0/(1.0 + 4.0*risk)
                times.append((scenario,rep,unbounded))
    summary = []
    for tb in horizons:
        # Externally assumed compromise bound, NOT a fitted/learned time to break.
        capped = sum(min(300.0, .7*tb, raw) for _,_,raw in times)
        rejected = sum(min(300.0, .7*tb, raw) < 10.0 for _,_,raw in times)
        capped_fraction = sum(.7*tb < raw and .7*tb < 300.0 for _,_,raw in times)/len(times)
        if rejected:
            mean = None # Fail closed: no replacement by 10 seconds
        else:
            mean = capped/len(times)
        summary.append({'assumed_tb_seconds':tb, 'mean_lifetime_seconds':round(mean,4) if mean is not None else None,
                        'fraction_capped_by_tb':round(capped_fraction,6),'fraction_rejected':round(rejected/len(times),6),
                        'n_observations':len(times)})
    return summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=None,help='CSV output (default: JSON on stdout)')
    args=p.parse_args()
    results=experiments()
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    print(json.dumps({'scope':'synthetic sensitivity, no hardware or time-to-compromise measurements','posterior_quantile':'scipy.stats.beta.ppf(.95,1+s,19+n)', 'results':results},indent=2))

if __name__=='__main__':main()
