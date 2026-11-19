# IJ-AI 31343 — Independent cross-check of the synthetic policy analyses

These two scripts re-implement, independently of `tb_sensitivity.py` and `forged_alarm_flood_demo.py` (which use the repository controller directly), the T_b sensitivity and the forged-alarm limiter calculation. Both implementations give the same numbers, and `tools/verify_release.py` compares them when SciPy is installed.

This folder contains two **offline simulation** reproductions of the numerical results in the revised manuscript. They do **not** reproduce original hardware runs, EOSIO transactions, power traces or attacks on deployed IoT devices.

## File placement

Upload these files to the public repository:

- `02_Bayesian_AI/Reproduction/tb_sensitivity_scipy_crosscheck.py`
- `02_Bayesian_AI/Reproduction/forged_alarm_limiter.py`
- `05_Experimental_Results/Bayesian_AI/tb_sensitivity_results.csv`
- `05_Experimental_Results/Bayesian_AI/tb_sensitivity_results.json`
- `05_Experimental_Results/Bayesian_AI/forged_alarm_limiter_results.json`

The first analysis uses the same six scenario definitions, pseudo-random seeds, lengths (12 × 120 per scenario) and Beta(1,19) prior as `ijai31343_adversarial_ai_stats.py`, but computes the *exact* posterior 95% quantile using SciPy rather than the Stage 7 Monte Carlo approximation (which uses 1,024 seeded draws in the manuscript). As specified in the paper's Tb sensitivity paragraph, this is a distinct offline calculation. This is a **new reproducibility implementation** of the described experiment; it was not taken from a historical measurement log.

The second analysis reproduces the numerical policy calculation for 50 artificial suspicious inputs in five seconds, with at most 10 counted inputs per 60-second sliding window. Its posterior quantile uses the seeded Stage 7 Monte Carlo formula (1,024 samples). The limiter is implemented in this **offline script**, not shown to have been installed or used on the actual Raspberry Pi, and **does not constitute a gateway loopback validation**.

## Requirements

Python 3.10+; the `tb_sensitivity.py` script requires SciPy (tested using SciPy 1.17.0); the limiter uses Python's standard library only.

```bash
python -m pip install scipy
python 02_Bayesian_AI/Reproduction/tb_sensitivity_scipy_crosscheck.py --output 05_Experimental_Results/Bayesian_AI/tb_sensitivity_results.csv
python 02_Bayesian_AI/Reproduction/forged_alarm_limiter.py --output 05_Experimental_Results/Bayesian_AI/forged_alarm_limiter_results.json
```

## Expected results

| Assumed Tb (s) | Mean lifetime (s) | Fraction capped |
|---:|---:|---:|
|100|64.1207|0.599884|
|150|73.9125|0.018056|
|200|73.9581|0|
|600|73.9581|0|
|1200|73.9581|0|

For the limiter: baseline 76.3667 s, unlimited 50-alert result 28.2266 s, 10-count window result 39.4172 s, 40 alerts excluded from the policy input.

## Scientific scope and important caveats

- `Tb` is an externally assumed scenario bound; it is **not** an AI-predicted cryptanalytic breaking time.
- Rates, windows, numbers of forged alerts and event distributions are **artificial test conditions**. They do not represent a measured deployment or demonstrate the limiter would stop a real denial-of-service attack.
- Rate limiting can delay legitimate alerts. Only the effect on the policy's output is evaluated here.
- The synthetic 8,640 observations are generated using the published scenario logic; bootstrap, real-network variability and authenticity of inputs are not tested in these two scripts.
- The `Tb` analysis uses an exact Beta quantile and thus is not numerically identical to evaluating Stage 7's 1,024-sample approximation at every step.
- Keeping the original scripts, manifests, and logs untouched supports provenance and avoids misrepresenting this analysis as an old hardware experiment.

## Manuscript consistency note

The limiter has two separate pieces of evidence, both local and software-only: (1) these offline controller simulations, and (2) `04_Security_Verification/Tests/test_gateway_hardening.py` (`TestFloodCap`), which starts the real gateway on the loopback interface, sends 50 forged messages with a wrong MAC and checks that only the configured cap of observations reaches the policy (the rest are logged as suppressed). Neither is a hardware, Raspberry Pi or network measurement, and neither shows that the limiter would stop a real denial-of-service attack.
