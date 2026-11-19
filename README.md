# IJ-AI 31343 — Reproducibility materials (release candidate)



This repository candidate supports the revised manuscript on authenticated
elliptic-curve key renewal, Bayesian risk-adaptive key lifetime decisions, and
EOSIO-assisted audit for constrained IoT. It is not a turnkey reproduction of
the unavailable original Fujitsu EOSIO installation.

## Scientific contributions

1. `01_ECC_Key_Renewal/`: ESP8266 and ESP32 firmware used in separate hardware
   experiments, plus an instrumented Stage7 gateway **software** implementation.
   Key freshness is obtained with ephemeral X25519 / NIST P-256 ECDH,
   PSK-authenticated handshake and transcript-bound epoch ACK. The Stage7
   authenticated lifetime change was tested in loopback and compiled, but not
   reflashed on the hardware in the documented evaluation.
2. `02_Bayesian_AI/`: online Beta-Bernoulli estimator and **offline** fixed/
   heuristic/Bayesian policy comparisons. Simulated feedback observations are
   synthetic, not a learned intrusion classifier or field attack measurements.
   The 600-second breakage horizon is an assumed policy limit, not a measured
   time-to-break.
3. `03_EOSIO_Blockchain/`: reconstructed EOSIO contract and client sources,
   plus scripts for retrospective attestation matching. The original EOSIO
   development environment ran on a Fujitsu computer that is unavailable.
   The subsequent HP ZBook reconstruction must not be described as the
   original hardware deployment. ESP devices do not store the blockchain.

## Verification and evidence

- `04_Security_Verification/Scyther/` contains *simplified symbolic* protocol
  models: a TTL-bound protocol and deliberately weakened TTL-unbound control.
  Successful bounded Scyther claims do **not** prove computational PFS,
  post-compromise security, resilience to compromised credentials or contracts.
- `04_Security_Verification/Tests/` contains software tests, including a lost
  ACK-response injection on a simulated client/loopback gateway. These are not
  physical packet-loss experiments.
- `05_Experimental_Results/Stage6/` provides ESP8266 ECC timing and heap
  statistics; the corresponding detailed ESP32 ECC timing series is unavailable.
  Separate ESP32/ESP8266 campaigns must not be compared as controlled latency
  benchmarks. Data-channel authentication in Stage6 was HMAC-based; do not
  infer AES-GCM/AEAD measurement from a linked third-party crypto library.
- `05_Experimental_Results/EOSIO/` provides archived chain information and
  *retrospective* matching of 18 ESP8266 and 21 ESP32 attestation records,
  not live blockchain enforcement of each key exchange.

## Reproducibility status

`REPRODUCIBILITY_STATUS.md` lists executable checks and limitations. The source
scripts in this archive were written for a particular laboratory folder layout;
not all scripts have yet been converted into a standalone, one-command build.
A correct scientific record distinguishes source-code availability, static
syntax checking, replay on archived input, simulated scenarios, and actual
hardware replication. Only results with directly corresponding supplied files
should be reported as replicated.

## Data integrity

From the candidate folder, check original scientific file digests with:

```bash
sha256sum -c SHA256SUMS.txt
```

The four corrected JSON files have new digests. The private backup and
redaction audit remain outside this repository candidate. Source inventories
with absolute machine paths, private configurations, device secrets and private
metadata backup files are intentionally excluded.

## Private EOSIO key configuration

The sanitized JavaScript client references `process.env.EOSIO_PRIVATE_KEY`.
No private key is bundled. Provide a **fresh non-production** key through the
execution environment when testing on an isolated node, following appropriate
wallet/credential protection. Syntax-checking alone is not an EOSIO test.

## Publication status and licensing

- Repository status: Publicly accessible on GitHub.
- Repository URL: https://github.com/bouchrarguig-byte/IJAI31343-Bayesian-ECC-EOSIO-IoT
- License: **NOT YET CHOSEN BY THE AUTHORS**. No reuse license is implied.
- Human review of all 45 files, dependency licenses and study data is required.
- No live blockchain, firmware flashing or server start is performed by the
  preflight generator. No file here grants publication approval.

## Reproducing the numbers in the revised manuscript

One command recomputes the archived hashes, the Stage 4 policy replay, the synthetic aggregates, the T_b sensitivity, the forged-alarm limiter, the EWMA comparison and runs all test suites:

```bash
pip install -r requirements.txt          # cryptography (SciPy optional, for the independent cross-check)
python tools/verify_release.py           # add --quick to skip the slowest step
```

| Manuscript item | Script / file |
|---|---|
| Stage 4 replay, 83.94 → 51.71 s | `02_Bayesian_AI/Reproduction/ijai31343_ai_policy_replay.py` |
| Six synthetic scenarios, Brier scores | `02_Bayesian_AI/Reproduction/ijai31343_adversarial_ai_stats.py` |
| EWMA baselines | `02_Bayesian_AI/Reproduction/ewma_baseline_comparison.py` |
| T_b sensitivity | `tb_sensitivity.py` (repository controller); independent check: `tb_sensitivity_scipy_crosscheck.py` |
| Forged-alarm limiter (offline) | `forged_alarm_flood_demo.py`; independent check: `forged_alarm_limiter.py` |
| Forged-alarm limiter (gateway, loopback) | `04_Security_Verification/Tests/test_gateway_hardening.py`; execution log: `05_Experimental_Results/Software_Tests/test_gateway_hardening_log.txt` |
| 39 EOSIO attestation hashes | recomputed by `tools/verify_release.py` |
| Scyther models | `04_Security_Verification/Scyther/` |

These are offline simulations and local software tests. They do not reproduce the hardware runs, EOSIO transactions or power traces. See `AUDIT_REPORT.md` and `README_REPRODUCTION.md`.

**Known gap:** the gateway in this repository (`gateway_epoch_stage7.py`) is the Stage 7 laboratory gateway (X25519 only, transcript `IJAI31343-v1`). The ESP8266/ESP32 firmware uses transcript `IJAI31343-v2` with an `algorithm` field (X25519 / P-256), and the Stage 6 hardware logs contain that field. The Stage 6 gateway that produced the hardware logs is therefore not in this repository yet; see `AUDIT_REPORT.md`, section 7.
