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

- GitHub URL: **NOT YET CREATED / VERIFIED**.
- License: **NOT YET CHOSEN BY THE AUTHORS**. No reuse license is implied.
- Human review of all 45 files, dependency licenses and study data is required.
- No live blockchain, firmware flashing or server start is performed by the
  preflight generator. No file here grants publication approval.
