"""IJ-AI 31343 -- independent, experimental key-rotation *policy*.

IMPORTANT: This module does not generate, store, distribute, or rotate ECC
keys; only a successful external authenticated handshake can complete a
rotation. The assumed compromise horizon is a supplied scenario parameter,
NOT a measured quantum cryptanalysis time or an AI estimate of such a time.

No third-party dependencies. Intended for controlled tests on a Raspberry Pi.

Revision notes (v2, backward compatible -- defaults reproduce the published
Stage 4 / Stage 7 numbers bit for bit):

* ``posterior_method="exact"`` computes the 95% posterior quantile with the
  regularised incomplete beta function instead of a seeded Monte-Carlo
  sample. It removes the Monte-Carlo error that the original docstring asked
  to be quantified, and it is deterministic and faster. Default stays "mc".
* ``decay`` (0 < decay <= 1) adds optional exponential forgetting of old
  observations (discounted Beta-Bernoulli). Default 1.0 = the published
  cumulative model. It needs ``posterior_method="exact"`` because the counts
  become non-integer.
* ``SuspiciousEventLimiter`` caps how many suspicious observations may update
  the posterior in a sliding time window, which is the rate-limiting
  mitigation listed (but not implemented) in the manuscript for forged-alarm
  floods. It is opt-in and unused unless the caller creates one.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import json
import math
import random
from typing import Literal


class UnsafePolicyError(RuntimeError):
    """No admissible renewal period fits the supplied safety constraints."""


Event = Literal["success", "failed_auth", "replay", "invalid_proof"]
_EVENTS = {"success", "failed_auth", "replay", "invalid_proof"}
_METHODS = {"mc", "exact"}


# ---------------------------------------------------------------------------
# Exact Beta distribution quantile (no third-party dependency)
# ---------------------------------------------------------------------------
def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (modified Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 10_000):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            return h
    raise ArithmeticError("incomplete beta continued fraction did not converge")


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b) = Beta CDF at x."""
    if not (a > 0 and b > 0):
        raise ValueError("Beta parameters must be positive")
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_front = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                 + a * math.log(x) + b * math.log1p(-x))
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def beta_ppf(q: float, a: float, b: float, tol: float = 1e-13) -> float:
    """Quantile (inverse CDF) of Beta(a, b) by bisection on the exact CDF."""
    if not (0.0 < q < 1.0):
        raise ValueError("q must satisfy 0 < q < 1")
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if betainc(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
        if hi - lo < tol:
            break
    return 0.5 * (lo + hi)


@dataclass(frozen=True)
class PolicyConfig:
    # These numbers are EXAMPLES for a laboratory scenario, not published data.
    baseline_seconds: float = 120.0
    minimum_seconds: float = 10.0
    maximum_seconds: float = 300.0
    # Keep strictly below the assumed compromise horizon.
    safety_fraction: float = 0.70
    risk_sensitivity: float = 4.0
    # Beta-Bernoulli Bayesian model of observed suspicious event frequency.
    prior_alpha: int = 1
    prior_beta: int = 19
    confidence: float = 0.95
    posterior_samples: int = 4096
    seed: int = 31343
    # v2 options (defaults keep the published behaviour).
    posterior_method: str = "mc"
    decay: float = 1.0

    def __post_init__(self) -> None:
        fields = (self.baseline_seconds, self.minimum_seconds,
                  self.maximum_seconds, self.safety_fraction,
                  self.risk_sensitivity, self.confidence, self.decay)
        if any(not math.isfinite(x) for x in fields):
            raise ValueError("Every real-valued configuration must be finite")
        if not (0 < self.minimum_seconds <= self.baseline_seconds <= self.maximum_seconds):
            raise ValueError("Require 0 < min <= baseline <= max")
        if not (0 < self.safety_fraction < 1):
            raise ValueError("safety_fraction must satisfy 0 < alpha < 1")
        if self.risk_sensitivity < 0:
            raise ValueError("risk_sensitivity cannot be negative")
        if not (0 < self.confidence < 1):
            raise ValueError("confidence must be between 0 and 1")
        if (not isinstance(self.prior_alpha, int) or self.prior_alpha <= 0 or
                not isinstance(self.prior_beta, int) or self.prior_beta <= 0):
            raise ValueError("Beta prior parameters must be positive integers")
        if self.posterior_samples < 256:
            raise ValueError("posterior_samples must be >= 256")
        if self.posterior_method not in _METHODS:
            raise ValueError("posterior_method must be 'mc' or 'exact'")
        if not (0 < self.decay <= 1):
            raise ValueError("decay must satisfy 0 < decay <= 1")
        if self.decay < 1 and self.posterior_method != "exact":
            raise ValueError("decay < 1 requires posterior_method='exact'")


class BayesianRiskEstimator:
    """Online Beta-Bernoulli model of *observed suspicious-event frequency*.

    The observation model is deliberately simple and assumes conditional
    exchangeability. Real security datasets are rarely iid; this is only a
    candidate model whose calibration and predictive performance must be
    evaluated on independent data before making scientific claims.

    With ``config.decay < 1`` older observations are exponentially
    discounted, so the posterior can recover after an attack has ended.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.anomalies = 0
        self.normal_events = 0

    def observe(self, event: Event) -> None:
        if event not in _EVENTS:
            raise ValueError(f"Unsupported event: {event!r}")
        if self.config.decay < 1.0:
            self.anomalies *= self.config.decay
            self.normal_events *= self.config.decay
        if event == "success":
            self.normal_events += 1
        else:
            self.anomalies += 1

    @property
    def alpha(self) -> float:
        return self.config.prior_alpha + self.anomalies

    @property
    def beta(self) -> float:
        return self.config.prior_beta + self.normal_events

    @property
    def posterior_mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def posterior_upper_bound(self) -> float:
        """Upper posterior quantile at ``config.confidence``.

        ``posterior_method="exact"`` (v2) is deterministic and exact up to
        floating-point precision. ``"mc"`` (default, as published) is a seeded
        Monte-Carlo approximation: fixed seed + counts make repeated calls
        reproducible but the Monte-Carlo error is not zero.
        """
        if self.config.posterior_method == "exact":
            return beta_ppf(self.config.confidence, self.alpha, self.beta)
        seed = (self.config.seed + 1000003 * self.alpha +
                1000033 * self.beta) & ((1 << 64) - 1)
        rng = random.Random(seed)
        draws = sorted(rng.betavariate(self.alpha, self.beta)
                       for _ in range(self.config.posterior_samples))
        index = max(0, min(len(draws) - 1,
                           math.ceil(self.config.confidence * len(draws)) - 1))
        return draws[index]


class SuspiciousEventLimiter:
    """Sliding-window cap on suspicious observations that may move the posterior.

    Mitigation for forged-alarm floods: at most ``max_events`` suspicious
    observations are accepted per ``window_seconds``; later ones are reported
    as suppressed so the caller can log them without changing the policy.
    The caller supplies a monotonic clock (``time.monotonic()``).
    """

    def __init__(self, max_events: int = 5, window_seconds: float = 60.0) -> None:
        if max_events < 1 or not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("max_events >= 1 and finite window_seconds > 0 required")
        self.max_events = int(max_events)
        self.window_seconds = float(window_seconds)
        self._stamps: deque[float] = deque()

    def allow(self, now: float) -> bool:
        if not math.isfinite(now):
            raise ValueError("now must be finite")
        while self._stamps and now - self._stamps[0] >= self.window_seconds:
            self._stamps.popleft()
        if len(self._stamps) >= self.max_events:
            return False
        self._stamps.append(now)
        return True


class AdaptiveRotationPolicy:
    """Selects the maximum usable key lifetime, never issues ECC operations.

    `assumed_break_horizon_seconds` is EXTERNALLY supplied for a specified
    classical/physical compromise scenario. It is not obtained from the risk
    model, and it does NOT describe time to quantum break an ECC key.
    """

    def __init__(self, config: PolicyConfig,
                 estimator: BayesianRiskEstimator) -> None:
        self.config = config
        self.estimator = estimator

    def select_interval(self, assumed_break_horizon_seconds: float | None) -> dict:
        horizon = assumed_break_horizon_seconds
        if horizon is None or not math.isfinite(horizon) or horizon <= 0:
            raise UnsafePolicyError(
                "No justified compromise-horizon scenario supplied: fail closed")
        risk_upper = self.estimator.posterior_upper_bound()
        risk_limited = self.config.baseline_seconds / (
            1.0 + self.config.risk_sensitivity * risk_upper)
        interval = min(self.config.maximum_seconds,
                       self.config.safety_fraction * horizon,
                       risk_limited)
        if interval < self.config.minimum_seconds:
            raise UnsafePolicyError(
                "Required rotation is faster than feasible minimum: fail closed")
        if not (0 < interval < horizon):
            raise UnsafePolicyError("The T_c < T_b constraint could not be met")
        return {
            "interval_seconds": round(interval, 6),
            "assumed_break_horizon_seconds": horizon,
            "risk_posterior_mean": round(self.estimator.posterior_mean, 6),
            # Key name kept for log compatibility; the value is exact when
            # posterior_method == "exact".
            "risk_posterior_upper_mc": round(risk_upper, 6),
            "events_normal": self.estimator.normal_events,
            "events_suspicious": self.estimator.anomalies,
            "horizon_source": "externally_provided_scenario_NOT_quantum_break_time",
            "model": "beta_bernoulli_online_risk_frequency",
            "posterior_method": self.config.posterior_method,
            "decay": self.config.decay,
        }


class EpochMonitor:
    """Fail-closed epoch monitor. Never claims keys were renewed on its own.

    A caller MUST perform an authenticated new X25519 handshake, derive fresh
    session keys, and retire old keys BEFORE calling confirm_rotation().
    """

    def __init__(self, policy: AdaptiveRotationPolicy, epoch_started_at: float,
                 initial_epoch: int = 0) -> None:
        if not math.isfinite(epoch_started_at):
            raise ValueError("epoch_started_at must be finite")
        if initial_epoch < 0:
            raise ValueError("epoch must be nonnegative")
        self.policy = policy
        self.epoch_started_at = epoch_started_at
        self.epoch = initial_epoch

    def state(self, now: float, assumed_break_horizon_seconds: float | None) -> dict:
        if not math.isfinite(now) or now < self.epoch_started_at:
            raise ValueError("clock must be monotonic and finite")
        policy_result = self.policy.select_interval(assumed_break_horizon_seconds)
        age = now - self.epoch_started_at
        due = age >= policy_result["interval_seconds"]
        return {
            **policy_result,
            "epoch": self.epoch,
            "epoch_age_seconds": round(age, 6),
            "rotation_due": due,
            "old_key_usable": not due,
            "state": "REKEY_REQUIRED_BLOCK_OLD_KEY" if due else "ACTIVE",
        }

    def confirm_rotation(self, now: float, *, new_authenticated_key_installed: bool) -> None:
        if not new_authenticated_key_installed:
            raise ValueError("Refusing to advance epoch without completed new handshake")
        if not math.isfinite(now) or now < self.epoch_started_at:
            raise ValueError("clock must be monotonic and finite")
        self.epoch += 1
        self.epoch_started_at = now


def _demo() -> None:
    # DEMO ONLY: chosen scenario horizon, artificial observations, no real IoT.
    cfg = PolicyConfig()
    model = BayesianRiskEstimator(cfg)
    policy = AdaptiveRotationPolicy(cfg, model)
    clock = 0.0
    monitor = EpochMonitor(policy, epoch_started_at=clock)
    horizon = 600.0  # illustrative scenario; NOT a quantum break measurement
    print("SIMULATION UNIQUEMENT — AUCUNE MESURE ESP8266 / QUANTIQUE")
    print(json.dumps(monitor.state(clock, horizon), indent=2))
    for _ in range(10):
        model.observe("success")
    for _ in range(5):
        model.observe("failed_auth")
    print("Après des observations SYNTHETIQUES :")
    print(json.dumps(monitor.state(clock + 60, horizon), indent=2))
    print("Aucune nouvelle clé ECC créée : le moniteur ne pilote pas encore dh1/dh2.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--demo", action="store_true", help="show an explicitly synthetic demo")
    args = p.parse_args()
    if args.demo:
        _demo()
    else:
        p.print_help()
