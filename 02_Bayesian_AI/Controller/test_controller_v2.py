"""Tests for the v2 additions of intelligent_key_renewal.py.

All inputs are artificial or come from the archived Stage 4 replay CSV; none of
these tests touch hardware, EOSIO or real attack data.
"""
import csv
import math
import unittest
from pathlib import Path

from intelligent_key_renewal import (
    AdaptiveRotationPolicy, BayesianRiskEstimator, PolicyConfig,
    SuspiciousEventLimiter, beta_ppf, betainc,
)

REPO = Path(__file__).resolve().parents[2]
REPLAY_CSV = REPO / "05_Experimental_Results/Bayesian_AI/stage4_policy_decision_replay.csv"


class TestExactBeta(unittest.TestCase):
    def test_cdf_matches_closed_forms(self):
        # Beta(1, b): CDF = 1 - (1-x)^b ; Beta(a, 1): CDF = x^a
        for x in (0.01, 0.2, 0.5, 0.9):
            self.assertAlmostEqual(betainc(1, 19, x), 1 - (1 - x) ** 19, places=12)
            self.assertAlmostEqual(betainc(7, 1, x), x ** 7, places=12)

    def test_symmetry(self):
        for a, b, x in ((2.5, 7.0, 0.3), (30, 120, 0.15), (0.7, 0.9, 0.4)):
            self.assertAlmostEqual(betainc(a, b, x), 1 - betainc(b, a, 1 - x), places=12)

    def test_ppf_inverts_cdf(self):
        for a, b in ((1, 19), (6, 24), (35.5, 90.25), (200, 800)):
            for q in (0.05, 0.5, 0.95, 0.999):
                x = beta_ppf(q, a, b)
                self.assertAlmostEqual(betainc(a, b, x), q, places=9)

    def test_against_scipy_if_available(self):
        try:
            from scipy.stats import beta as sp
        except ImportError:  # pragma: no cover
            self.skipTest("scipy not installed")
        for a, b in ((1, 19), (3, 40), (12, 60), (80.5, 250.5)):
            self.assertAlmostEqual(beta_ppf(0.95, a, b), sp.ppf(0.95, a, b), places=9)

    def test_rejects_bad_arguments(self):
        with self.assertRaises(ValueError):
            beta_ppf(1.0, 1, 1)
        with self.assertRaises(ValueError):
            betainc(0, 1, 0.5)


class TestBackwardCompatibility(unittest.TestCase):
    @unittest.skipUnless(REPLAY_CSV.is_file(), "archived replay CSV not found")
    def test_default_mc_reproduces_archived_stage4_replay(self):
        """Default config must reproduce the published numbers exactly."""
        cfg = PolicyConfig(posterior_samples=1024)
        with REPLAY_CSV.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 21)
        for row in rows:
            model = BayesianRiskEstimator(cfg)
            model.normal_events = int(row["normal_events"])
            model.anomalies = int(row["suspicious_events"])
            self.assertAlmostEqual(model.posterior_upper_bound(),
                                   float(row["risk_upper_mc"]), places=6)

    def test_exact_close_to_monte_carlo(self):
        for n_ok, n_bad in ((1, 0), (10, 5), (40, 10), (20, 30)):
            mc = BayesianRiskEstimator(PolicyConfig(posterior_samples=16384))
            ex = BayesianRiskEstimator(PolicyConfig(posterior_method="exact"))
            for est in (mc, ex):
                est.normal_events, est.anomalies = n_ok, n_bad
            self.assertLess(abs(mc.posterior_upper_bound() - ex.posterior_upper_bound()), 0.01)


class TestDiscountedEstimator(unittest.TestCase):
    def test_decay_requires_exact(self):
        with self.assertRaises(ValueError):
            PolicyConfig(decay=0.95)
        PolicyConfig(decay=0.95, posterior_method="exact")
        with self.assertRaises(ValueError):
            PolicyConfig(decay=0.0, posterior_method="exact")
        with self.assertRaises(ValueError):
            PolicyConfig(decay=1.5, posterior_method="exact")

    def test_decay_one_is_cumulative(self):
        a = BayesianRiskEstimator(PolicyConfig(posterior_method="exact"))
        for ev in ["success"] * 5 + ["replay"] * 3:
            a.observe(ev)
        self.assertEqual((a.normal_events, a.anomalies), (5, 3))

    def test_discounting_recovers_after_attack(self):
        cum = BayesianRiskEstimator(PolicyConfig(posterior_method="exact"))
        dis = BayesianRiskEstimator(PolicyConfig(posterior_method="exact", decay=0.95))
        for est in (cum, dis):
            for _ in range(30):
                est.observe("invalid_proof")
            for _ in range(60):
                est.observe("success")
        self.assertLess(dis.posterior_upper_bound(), cum.posterior_upper_bound())
        pol_c = AdaptiveRotationPolicy(cum.config, cum).select_interval(600)
        pol_d = AdaptiveRotationPolicy(dis.config, dis).select_interval(600)
        self.assertGreater(pol_d["interval_seconds"], pol_c["interval_seconds"])

    def test_discounted_still_reacts_to_attack(self):
        dis = BayesianRiskEstimator(PolicyConfig(posterior_method="exact", decay=0.95))
        pol = AdaptiveRotationPolicy(dis.config, dis)
        before = pol.select_interval(600)["interval_seconds"]
        for _ in range(10):
            dis.observe("invalid_proof")
        self.assertLess(pol.select_interval(600)["interval_seconds"], before)

    def test_interval_stays_below_horizon(self):
        est = BayesianRiskEstimator(PolicyConfig(posterior_method="exact", decay=0.9))
        pol = AdaptiveRotationPolicy(est.config, est)
        for i in range(200):
            est.observe("invalid_proof" if i % 3 == 0 else "success")
            out = pol.select_interval(600)
            self.assertLess(out["interval_seconds"], 600)
            self.assertTrue(math.isfinite(out["risk_posterior_upper_mc"]))


class TestLimiter(unittest.TestCase):
    def test_caps_events_per_window(self):
        lim = SuspiciousEventLimiter(max_events=3, window_seconds=10)
        self.assertEqual([lim.allow(t) for t in (0, 1, 2, 3, 4)],
                         [True, True, True, False, False])
        self.assertTrue(lim.allow(10.0))   # first stamp left the window
        self.assertFalse(lim.allow(10.5))

    def test_rejects_bad_configuration_and_clock(self):
        with self.assertRaises(ValueError):
            SuspiciousEventLimiter(0, 10)
        with self.assertRaises(ValueError):
            SuspiciousEventLimiter(3, float("nan"))
        with self.assertRaises(ValueError):
            SuspiciousEventLimiter(3, 10).allow(float("inf"))

    def test_flood_cannot_push_policy_below_limited_floor(self):
        cfg = PolicyConfig(posterior_method="exact")
        est = BayesianRiskEstimator(cfg)
        pol = AdaptiveRotationPolicy(cfg, est)
        lim = SuspiciousEventLimiter(max_events=5, window_seconds=60)
        for step in range(1000):                       # 1000 forged alarms in 10 s
            if lim.allow(step * 0.01):
                est.observe("invalid_proof")
        self.assertEqual(est.anomalies, 5)
        unprotected = BayesianRiskEstimator(cfg)
        for _ in range(1000):
            unprotected.observe("invalid_proof")
        self.assertGreater(
            pol.select_interval(600)["interval_seconds"],
            AdaptiveRotationPolicy(cfg, unprotected).select_interval(600)["interval_seconds"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
