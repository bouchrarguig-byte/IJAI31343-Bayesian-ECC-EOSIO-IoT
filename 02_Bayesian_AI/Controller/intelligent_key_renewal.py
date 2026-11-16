"""IJ-AI 31343 -- independent, experimental key-rotation *policy*.

IMPORTANT: This module does not generate, store, distribute, or rotate ECC
keys; only a successful external authenticated handshake can complete a
rotation. The assumed compromise horizon is a supplied scenario parameter,
NOT a measured quantum cryptanalysis time or an AI estimate of such a time.

No third-party dependencies. Intended for controlled tests on a Raspberry Pi.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import random
from typing import Literal


class UnsafePolicyError(RuntimeError):
    """No admissible renewal period fits the supplied safety constraints."""


Event = Literal["success", "failed_auth", "replay", "invalid_proof"]
_EVENTS = {"success", "failed_auth", "replay", "invalid_proof"}


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

    def __post_init__(self) -> None:
        fields = (self.baseline_seconds, self.minimum_seconds,
                  self.maximum_seconds, self.safety_fraction,
                  self.risk_sensitivity, self.confidence)
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


class BayesianRiskEstimator:
    """Online Beta-Bernoulli model of *observed suspicious-event frequency*.

    The observation model is deliberately simple and assumes conditional
    exchangeability. Real security datasets are rarely iid; this is only a
    candidate model whose calibration and predictive performance must be
    evaluated on independent data before making scientific claims.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.anomalies = 0
        self.normal_events = 0

    def observe(self, event: Event) -> None:
        if event not in _EVENTS:
            raise ValueError(f"Unsupported event: {event!r}")
        if event == "success":
            self.normal_events += 1
        else:
            self.anomalies += 1

    @property
    def alpha(self) -> int:
        return self.config.prior_alpha + self.anomalies

    @property
    def beta(self) -> int:
        return self.config.prior_beta + self.normal_events

    @property
    def posterior_mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def posterior_upper_bound(self) -> float:
        """Deterministic Monte-Carlo approximation of posterior quantile.

        Not an exact credible bound; Monte-Carlo error should be quantified
        separately in a journal-grade evaluation. Fixed seed + counts make
        repeated calls reproducible.
        """
        seed = (self.config.seed + 1000003 * self.alpha +
                1000033 * self.beta) & ((1 << 64) - 1)
        rng = random.Random(seed)
        draws = sorted(rng.betavariate(self.alpha, self.beta)
                       for _ in range(self.config.posterior_samples))
        index = max(0, min(len(draws) - 1,
                           math.ceil(self.config.confidence * len(draws)) - 1))
        return draws[index]


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
            "risk_posterior_upper_mc": round(risk_upper, 6),
            "events_normal": self.estimator.normal_events,
            "events_suspicious": self.estimator.anomalies,
            "horizon_source": "externally_provided_scenario_NOT_quantum_break_time",
            "model": "beta_bernoulli_online_risk_frequency",
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
