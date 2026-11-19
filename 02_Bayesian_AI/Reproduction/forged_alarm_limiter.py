#!/usr/bin/env python3
"""IJ-AI 31343: simulated suspicious-event rate limiter.

Reproduces the 50-alert-in-5-s thought experiment with the original Stage 7
Beta(1,19) policy, lambda=4, 1024 seeded posterior samples. This is an
OFFLINE controller simulation and does not prove network DoS protection,
telemetry authenticity or an installed gateway rate-limit implementation.
No hardware measurements are performed.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
import argparse
import json
import math
import random

SEED = 31343


def upper_risk(alpha: int, beta: int) -> float:
    # Matches BayesianRiskEstimator.posterior_upper_bound in current repository.
    state_seed = (SEED + 1000003*alpha + 1000033*beta) & ((1<<64)-1)
    rng = random.Random(state_seed)
    samples = sorted(rng.betavariate(alpha, beta) for _ in range(1024))
    return samples[math.ceil(.95*len(samples)) - 1]


def lifetime(n_suspicious: int, n_normal: int = 0, tb_seconds: float = 600.) -> float:
    upper = upper_risk(1+n_suspicious,19+n_normal)
    result = min(300., .7*tb_seconds, 120./(1+4*upper))
    if not (10. <= result < tb_seconds):
        raise ValueError('No admissible lifetime: fail closed')
    return result


@dataclass
class SlidingWindowLimiter:
    max_suspicious: int = 10
    window_seconds: float = 60.

    def __post_init__(self):
        if self.max_suspicious < 1 or self.window_seconds <= 0:
            raise ValueError('invalid limiter parameters')
        self._accepted_at = deque()

    def accept(self, time_seconds: float) -> bool:
        # A half-open look-back window: timestamps in [t-window, t].
        while self._accepted_at and self._accepted_at[0] <= time_seconds-self.window_seconds:
            self._accepted_at.popleft()
        if len(self._accepted_at) < self.max_suspicious:
            self._accepted_at.append(time_seconds)
            return True
        return False


def simulate_flood(alert_count: int = 50, duration_seconds: float = 5.) -> dict:
    if alert_count <= 0 or duration_seconds <= 0:
        raise ValueError('alert_count and duration_seconds must be positive')
    limiter = SlidingWindowLimiter()
    accepted = sum(limiter.accept(i * duration_seconds / alert_count) for i in range(alert_count))
    suppressed = alert_count-accepted
    results = {
      'kind':'offline synthetic controller simulation, not hardware or gateway network test',
      'input':{'forged_invalid_proofs':alert_count,'within_seconds':duration_seconds,
               'limiter':'at most 10 counted suspicious observations per 60 s',
               'prior_beta':[1,19],'monte_carlo_samples':1024,'seed':SEED,'assumed_tb_seconds':600},
      'output':{'before_alerts_lifetime_s':round(lifetime(0),4),
                'without_limiter_lifetime_s':round(lifetime(alert_count),4),
                'with_limiter_lifetime_s':round(lifetime(accepted),4),
                'counted_alerts':accepted,'suppressed_alerts':suppressed}
    }
    return results


def self_test():
    r=simulate_flood()
    out=r['output']
    assert (out['counted_alerts'], out['suppressed_alerts']) == (10,40)
    assert abs(out['before_alerts_lifetime_s'] - 76.4) < .1
    assert abs(out['without_limiter_lifetime_s'] - 28.2) < .1
    assert abs(out['with_limiter_lifetime_s'] - 39.4) < .1
    limiter=SlidingWindowLimiter(max_suspicious=2, window_seconds=5.)
    assert limiter.accept(0.) and limiter.accept(1.) and not limiter.accept(2.)
    assert limiter.accept(5.) # the first observation has expired


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=str,default=None,help='JSON file destination')
    args=p.parse_args()
    self_test()
    results=simulate_flood()
    payload=json.dumps(results,indent=2)+'\n'
    if args.output:
        from pathlib import Path
        target=Path(args.output)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(payload,encoding='utf-8')
    print(payload,end='')

if __name__=='__main__':main()
