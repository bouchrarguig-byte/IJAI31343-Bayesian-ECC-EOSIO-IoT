"""IJ-AI 31343 / Stage 2: fail-closed epoch lifecycle *integration interface*.

Not a production authentication server. The real gateway must validate an
X25519 handshake, then validate a CLIENT ACK bound to the new session key
before invoking confirm_device_ack(). No test in this file uses ESP8266.

No ECC private keys or application session keys are stored here.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
import math
import sys

# v2: make the repository layout importable. A copy of the controller placed
# next to this file (as the loopback tests do) still wins over this fallback.
_CONTROLLER_DIR = Path(__file__).resolve().parents[2] / "02_Bayesian_AI" / "Controller"
if _CONTROLLER_DIR.is_dir() and str(_CONTROLLER_DIR) not in sys.path:
    sys.path.append(str(_CONTROLLER_DIR))

from intelligent_key_renewal import (
    AdaptiveRotationPolicy, BayesianRiskEstimator, EpochMonitor,
    PolicyConfig, UnsafePolicyError,
)

_SESSION = re.compile(r"[a-f0-9]{32}\Z")
_FINGERPRINT = re.compile(r"[a-f0-9]{64}\Z")

class RotationProtocolError(RuntimeError):
    pass

@dataclass(frozen=True)
class PendingHandshake:
    session_id: str
    public_key_sha256: str
    server_verified_at: float

class EpochCoordinator:
    """Orchestrates state only; actual key exchange and ACK are external.

    Call `stage_gateway_verified()` only after the gateway verifies the
    authenticated /finish proof. Call `confirm_device_ack()` only after
    verifying a third key-confirmation MAC from the *device* on /ack.

    A mere HTTP 200 /finish response is NOT a device ACK, and the unchanged
    legacy ESP8266 firmware does NOT implement /ack.
    """
    def __init__(self, horizon_seconds: float | None, config: PolicyConfig | None = None):
        self.cfg = config or PolicyConfig()
        self.model = BayesianRiskEstimator(self.cfg)
        self.policy = AdaptiveRotationPolicy(self.cfg, self.model)
        self.assumed_break_horizon_seconds = horizon_seconds
        self.monitor: EpochMonitor | None = None
        self.pending: PendingHandshake | None = None
        self.used_sessions: set[str] = set()
        self.used_pub_fingerprints: set[str] = set()

    def observe(self, event: str) -> None:
        self.model.observe(event)

    def stage_gateway_verified(self, session_id: str, public_key_sha256: str,
                               at_monotonic: float) -> None:
        if not (_SESSION.fullmatch(session_id) and
                _FINGERPRINT.fullmatch(public_key_sha256)):
            raise ValueError("Expected hex session ID (32) and public key SHA256 (64)")
        if not math.isfinite(at_monotonic):
            raise ValueError("Non-finite monotonic clock")
        if self.pending is not None:
            raise RotationProtocolError("Previous handshake pending device ACK")
        if session_id in self.used_sessions:
            raise RotationProtocolError("Session ID cannot be replayed")
        if public_key_sha256 in self.used_pub_fingerprints:
            raise RotationProtocolError("Refusing reuse of an observed ephemeral public key")
        # Fail closed if no admissible policy exists.
        self.policy.select_interval(self.assumed_break_horizon_seconds)
        if self.monitor is not None and at_monotonic < self.monitor.epoch_started_at:
            raise ValueError("Non-monotonic clock")
        self.pending = PendingHandshake(session_id, public_key_sha256, at_monotonic)

    def confirm_device_ack(self, session_id: str, at_monotonic: float, *,
                           cryptographic_ack_verified: bool) -> int:
        """Only a caller that verified the device's MAC may set flag True.

        This boolean is an API boundary, not a cryptographic proof. Do not
        expose this method as an unprotected HTTP endpoint.
        """
        if not cryptographic_ack_verified:
            raise RotationProtocolError("Client MAC acknowledgement not verified")
        if self.pending is None or self.pending.session_id != session_id:
            raise RotationProtocolError("Unknown or replayed ACK")
        if not math.isfinite(at_monotonic) or at_monotonic < self.pending.server_verified_at:
            raise ValueError("Non-monotonic ACK time")
        if self.monitor is not None and at_monotonic < self.monitor.epoch_started_at:
            raise ValueError("Non-monotonic epoch time")
        if self.monitor is None:
            self.monitor = EpochMonitor(self.policy, at_monotonic, initial_epoch=1)
        else:
            self.monitor.confirm_rotation(at_monotonic,
                                          new_authenticated_key_installed=True)
        self.used_sessions.add(session_id)
        self.used_pub_fingerprints.add(self.pending.public_key_sha256)
        self.pending = None
        self.model.observe("success")
        return self.monitor.epoch

    def state(self, at_monotonic: float) -> dict:
        if self.monitor is None:
            return {"state": "NO_CONFIRMED_EPOCH", "data_allowed": False,
                    "pending_gateway_verified": self.pending is not None}
        try:
            result = self.monitor.state(at_monotonic,
                                        self.assumed_break_horizon_seconds)
        except UnsafePolicyError:
            return {"state": "POLICY_UNSAFE_BLOCK", "data_allowed": False,
                    "epoch": self.monitor.epoch}
        return {**result, "data_allowed": result["old_key_usable"],
                "pending_gateway_verified": self.pending is not None}

    def authorize_payload(self, epoch: int, at_monotonic: float) -> bool:
        """Gate ONLY. Gateway must separately check data AEAD/MAC & counter."""
        status = self.state(at_monotonic)
        return (status.get("data_allowed") is True and
                status.get("epoch") == epoch)
