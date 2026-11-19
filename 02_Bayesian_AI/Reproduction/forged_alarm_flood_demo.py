#!/usr/bin/env python3
"""Forged-alarm flood against the lifetime controller, with and without the v2 limiter.

SYNTHETIC / SOFTWARE ONLY. A burst of N forged suspicious observations (10 per
second) is fed to the controller starting from the prior. The limiter is the
SuspiciousEventLimiter used by the v2 gateway (default: 10 events per 60 s).
This is a controller-level demonstration, not a network or hardware test; the
gateway-level behaviour is covered by 04_Security_Verification/Tests/test_gateway_hardening.py.
"""
from __future__ import annotations
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "02_Bayesian_AI" / "Controller"))
from intelligent_key_renewal import (AdaptiveRotationPolicy, BayesianRiskEstimator,  # noqa: E402
                                     PolicyConfig, SuspiciousEventLimiter)


def flood(n_forged: int, limiter):
    cfg = PolicyConfig(posterior_samples=1024)            # the gateway/paper setting
    est = BayesianRiskEstimator(cfg)
    pol = AdaptiveRotationPolicy(cfg, est)
    start = pol.select_interval(600.0)
    start_t = next(v for k, v in start.items() if "interval" in k and isinstance(v, (int, float)))
    counted = suppressed = 0
    for i in range(n_forged):
        if limiter is None or limiter.allow(i * 0.1):
            est.observe("invalid_proof"); counted += 1
        else:
            suppressed += 1
    end = pol.select_interval(600.0)
    end_t = next(v for k, v in end.items() if "interval" in k and isinstance(v, (int, float)))
    return start_t, end_t, counted, suppressed


def main(n_forged=50):
    s, e, c, x = flood(n_forged, None)
    print(f"no cap        : counted={c:>3} suppressed={x:>3}  interval {s:.3f} -> {e:.3f} s")
    s, e, c, x = flood(n_forged, SuspiciousEventLimiter(10, 60.0))
    print(f"cap 10 / 60 s : counted={c:>3} suppressed={x:>3}  interval {s:.3f} -> {e:.3f} s")


if __name__ == "__main__":
    main()
