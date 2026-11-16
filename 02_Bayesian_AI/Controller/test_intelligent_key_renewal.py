"""Unit tests. All inputs are artificial; these are not hardware results."""
import unittest
from intelligent_key_renewal import (
    AdaptiveRotationPolicy, BayesianRiskEstimator, EpochMonitor,
    PolicyConfig, UnsafePolicyError,
)


class TestAdaptiveKeyRenewal(unittest.TestCase):
    def setUp(self):
        self.cfg = PolicyConfig(posterior_samples=1024)
        self.estimator = BayesianRiskEstimator(self.cfg)
        self.policy = AdaptiveRotationPolicy(self.cfg, self.estimator)

    def test_valid_configuration(self):
        with self.assertRaises(ValueError):
            PolicyConfig(safety_fraction=1)
        with self.assertRaises(ValueError):
            PolicyConfig(minimum_seconds=130)

    def test_fail_closed_without_scenario(self):
        with self.assertRaises(UnsafePolicyError):
            self.policy.select_interval(None)
        with self.assertRaises(UnsafePolicyError):
            self.policy.select_interval(float("nan"))

    def test_tc_strictly_less_than_tb(self):
        for tb in [20.0, 60.0, 100.0, 1000.0]:
            interval = self.policy.select_interval(tb)["interval_seconds"]
            self.assertLess(interval, tb)
            self.assertGreater(interval, 0)

    def test_events_increase_risk_and_decrease_interval(self):
        before = self.policy.select_interval(600)
        for _ in range(30):
            self.estimator.observe("replay")
        after = self.policy.select_interval(600)
        self.assertGreater(after["risk_posterior_mean"],
                           before["risk_posterior_mean"])
        self.assertLess(after["interval_seconds"], before["interval_seconds"])

    def test_results_reproducible(self):
        a = self.policy.select_interval(500)
        b = self.policy.select_interval(500)
        self.assertEqual(a, b)

    def test_small_break_horizon_causes_block(self):
        with self.assertRaises(UnsafePolicyError):
            self.policy.select_interval(2)

    def test_bad_event_rejected(self):
        with self.assertRaises(ValueError):
            self.estimator.observe("magic_attack")

    def test_epoch_blocking_and_ack(self):
        epoch = EpochMonitor(self.policy, epoch_started_at=100.0)
        state = epoch.state(100.0, 600.0)
        self.assertTrue(state["old_key_usable"])
        end = 100.0 + state["interval_seconds"] + 0.01
        state_due = epoch.state(end, 600.0)
        self.assertTrue(state_due["rotation_due"])
        self.assertFalse(state_due["old_key_usable"])
        with self.assertRaises(ValueError):
            epoch.confirm_rotation(end, new_authenticated_key_installed=False)
        self.assertEqual(epoch.epoch, 0)
        epoch.confirm_rotation(end, new_authenticated_key_installed=True)
        self.assertEqual(epoch.epoch, 1)
        self.assertTrue(epoch.state(end, 600.0)["old_key_usable"])

    def test_clock_cannot_run_backwards(self):
        epoch = EpochMonitor(self.policy, 100.0)
        with self.assertRaises(ValueError):
            epoch.state(99.0, 600.0)

    def test_low_risk_after_successes(self):
        original = self.estimator.posterior_mean
        for _ in range(50):
            self.estimator.observe("success")
        self.assertLess(self.estimator.posterior_mean, original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
