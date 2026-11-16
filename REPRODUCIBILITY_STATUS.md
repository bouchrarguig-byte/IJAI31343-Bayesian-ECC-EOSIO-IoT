# Reproducibility and reviewer-evidence status

| Component | Evidence in this candidate | Boundary of the evidence |
| --- | --- | --- |
| C1: ESP8266 ECC/epoch protocol | Firmware + recorded epoch events, X25519/P-256 descriptive timing/heap table | n=9 each timing group; repeated epochs in one setup, not independent devices. No standalone ESP32 ECC latency measurements here. |
| C1: ESP32 protocol | Firmware + 21 logged epochs | Cross-platform functional evidence; not a controlled head-to-head speed or energy benchmark. |
| C2: Bayesian adaptation | Stage4 recorded events, offline replay, six synthetic scenarios with seeded replications | Event feedback/TTL policy learning; no trained IDS or measured cryptanalytic break horizon. |
| C3: EOSIO | Reconstructed contract source, ABI, JS client, audit scripts, chain archives | Historic Fujitsu EOSIO installation unavailable. 18+21 digest matches were retrospective, not end-to-end real-time on-chain enforcement. |
| Security: Scyther | 2 SPDL models, 2 result logs, original SHA256 manifest | Simplified Dolev-Yao symbolic abstraction and bounded run search. Unbound-TTL control intentionally weakened. |
| Security: lost ACK | Software-only injected response loss, six loopback tests reported | No hardware firmware reflash or real radio/packet-loss experiment. |

## Preflight performed by the preparation script

- Verified 45 allowlisted files and expected source-to-copy checksums.
- Verified four edited JSONs against PRIVATE backup copies (structural and
  non-string numerical/boolean fields preserved).
- Verified sanitized EOSIO JavaScript differs from original at only the
  authorized private-key assignment line; syntax checked if Node.js available.
- Parsed Python source with `ast.parse`, JSON/ABI files, JSONL and CSV files.
- Verified Scyther's four original file hashes via its manifest.
- Rescanned for the known secret-pattern signatures and local metadata patterns.
- Created `SHA256SUMS.txt` and `PROVENANCE_PUBLIC.csv` from candidate files.

These checks are NOT runtime experiment reproduction. Firmware compilation,
EOSIO deployment, live keys, authorized hardware, network connectivity,
source dependency versions and end-to-end measurements must be checked
separately before asserting a complete independent reproduction.

## Release decision (manual)

- [ ] Manually inspect every staged source and result for secrets/device IDs/PII.
- [ ] Confirm credential rotation where applicable; do not publish production keys.
- [ ] Decide and check source/data/dependency licensing.
- [ ] Confirm exact firmware/build/toolchain dependencies.
- [ ] Confirm all manuscript tables/claims against archived data.
- [ ] Check GitHub link after an explicitly authorized publication.
