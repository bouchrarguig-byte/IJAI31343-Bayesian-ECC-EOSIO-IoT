#!/usr/bin/env python3
"""One-command verification of the IJ-AI 31343 release candidate.

Run from anywhere:  python tools/verify_release.py [--quick]

Checks (each prints PASS / FAIL / SKIP):
  1. SHA256SUMS of the archived files.
  2. Scyther SHA256_MANIFEST.
  3. The 39 EOSIO attestation hashes recomputed from the archived event logs.
  4. Stage 6 descriptive table recomputed from stage6_statistical_summary.json,
     and the headline numbers quoted in the manuscript.
  5. Stage 4 policy replay: the UNMODIFIED published script is run in a temporary
     layout and its CSV is compared with the archived CSV; 38.40 % recomputed.
  6. Synthetic scenarios: the UNMODIFIED published script is re-run (12 seeds x 6
     scenarios) and its aggregates compared with the archived CSVs.
  7. Unit, loopback and hardening tests.

Limits (printed at the end): raw ESP8266/ESP32 serial logs are not in the
repository, so Stage 6 timings are checked only from the archived summary, not
recomputed from raw per-epoch measurements. Nothing here touches hardware,
EOSIO or the network.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESULTS = []


def report(name, status, detail=""):
    RESULTS.append((name, status))
    print(f"[{status:<4}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_manifest(manifest: Path, base: Path, name: str):
    bad, n = [], 0
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        rel = rel.strip().lstrip("*")
        target = base / rel
        n += 1
        if not target.is_file() or sha256_file(target) != digest:
            bad.append(rel)
    if bad:
        report(name, "FAIL", f"{len(bad)}/{n} differ: {', '.join(bad[:4])}{'...' if len(bad) > 4 else ''}")
    else:
        report(name, "PASS", f"{n} files")


def rows_of(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def check_attestations():
    res = REPO / "05_Experimental_Results"
    total = 0
    for plat, att, experiment in (("ESP8266", "EOSIO/ESP8266_18_attestations.json", "Stage6_ESP8266_agility_run5"),
                                  ("ESP32", "EOSIO/ESP32_21_attestations.json", "Stage6_curve_agility_run2")):
        ev = rows_of(res / "Stage6" / f"{plat}_events.jsonl")
        acts = {int(e["epoch"]): e for e in ev
                if e.get("kind") == "epoch_activated" and e.get("experiment") == experiment}
        rows = json.loads((res / att).read_text())["rows"]
        ok = 0
        for r in rows:
            e = acts.get(int(r["epoch"]))
            if e is None:
                continue
            canon = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ok += hashlib.sha256(canon).hexdigest() == r["event_hash"].lower()
        total += ok
        report(f"EOSIO attestation hashes {plat}", "PASS" if ok == len(rows) else "FAIL", f"{ok}/{len(rows)} match")
    report("EOSIO attestation hashes total", "PASS" if total == 39 else "FAIL", f"{total}/39")


def check_stage6():
    res = REPO / "05_Experimental_Results/Stage6"
    summary = json.loads((res / "stage6_statistical_summary.json").read_text())
    groups = summary["platforms"]["ESP8266"]["serial"]["groups"]
    table = {(r["curve"], r["metric"]): r for r in csv.DictReader((res / "stage6_descriptive_table.csv").open())}
    ok = True
    for curve, key, label in (("X25519", "renewal_total_ms", "renewal_total"), ("P256", "renewal_total_ms", "renewal_total"),
                              ("X25519", "free_heap_after_b", "free_heap_after"), ("P256", "free_heap_after_b", "free_heap_after")):
        s, t = groups[curve][key], table[(curve, label)]
        ok &= int(t["n"]) == s["n"] and abs(float(t["mean"]) - s["mean"]) < 1e-3 and abs(float(t["sample_sd"]) - s["sd_sample"]) < 1e-3
    x, p = groups["X25519"]["renewal_total_ms"]["mean"], groups["P256"]["renewal_total_ms"]["mean"]
    pct = 100 * (p - x) / p
    headline = (abs(x - 522.67) < 0.01 and abs(p - 716.44) < 0.01 and abs(pct - 27.05) < 0.01)
    report("Stage 6 table matches summary JSON", "PASS" if ok else "FAIL")
    report("Manuscript headline 522.67 / 716.44 ms, 27.05 %", "PASS" if headline else "FAIL", f"{x:.2f} / {p:.2f} ms, {pct:.2f} %")


def compare_csv(produced: Path, archived: Path, tol=1e-6, key_cols=()):
    a = list(csv.DictReader(produced.open(encoding="utf-8")))
    b = list(csv.DictReader(archived.open(encoding="utf-8")))
    if len(a) != len(b):
        return False, f"row count {len(a)} != {len(b)}", None
    worst = 0.0
    for ra, rb in zip(a, b):
        for col in rb:
            if col not in ra:
                return False, f"missing column {col}", None
            va, vb = ra[col], rb[col]
            try:
                fa, fb = float(va), float(vb)
            except ValueError:
                if col in ("timestamp_utc",) or va == vb:
                    continue
                return False, f"text mismatch in {col}: {va!r} vs {vb!r}", None
            worst = max(worst, abs(fa - fb))
    return worst <= tol, f"max |difference| = {worst:.3g}", worst


def make_layout(tmp: Path) -> Path:
    """Recreate the folder layout the published scripts expect (copies, no symlinks)."""
    rev = tmp / "Revision_31343"
    pairs = {
        REPO / "05_Experimental_Results/Stage4/Stage4_ADAPTIVE_after.jsonl":
            rev / "Experimental_Results/Stage4/Adaptive/Stage4_ADAPTIVE_after_injection.jsonl",
        REPO / "02_Bayesian_AI/Controller/intelligent_key_renewal.py":
            rev / "IJAI_31343_Stage7_Instrumented/Pi_Gateway/intelligent_key_renewal.py",
    }
    for src, dst in pairs.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return tmp


def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def check_stage4_replay():
    with tempfile.TemporaryDirectory() as t:
        root = make_layout(Path(t))
        out = Path(t) / "out_replay"
        r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/ijai31343_ai_policy_replay.py"),
                 "--root", str(root), "--output", str(out)], 300)
        if r.returncode != 0:
            report("Stage 4 replay (published script)", "FAIL", (r.stdout + r.stderr).strip().splitlines()[-1][:200])
            return
        ok, detail, _ = compare_csv(out / "stage4_policy_decision_replay.csv",
                                    REPO / "05_Experimental_Results/Bayesian_AI/stage4_policy_decision_replay.csv")
        report("Stage 4 replay reproduces archived CSV", "PASS" if ok else "FAIL", detail)
        rows = list(csv.DictReader((out / "stage4_policy_decision_replay.csv").open()))
        risk = [i for i, x in enumerate(rows) if x["source_event"] == "risk_observation"]
        before = float(rows[risk[0] - 1]["bayes_upper_lambda4"])
        after = float(rows[risk[-1]]["bayes_upper_lambda4"])
        pct = 100 * (before - after) / before
        report("Stage 4: 83.94 s -> 51.71 s (38.40 %)", "PASS" if abs(pct - 38.40) < 0.01 else "FAIL",
               f"{before:.4f} -> {after:.4f} s = {pct:.2f} %")


def check_synthetic():
    with tempfile.TemporaryDirectory() as t:
        root = make_layout(Path(t))
        out = Path(t) / "out_synth"
        r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/ijai31343_adversarial_ai_stats.py"),
                 "--root", str(root), "--output", str(out), "--no-plots"], 1500)
        if r.returncode != 0:
            report("Synthetic scenarios (published script)", "FAIL", (r.stdout + r.stderr).strip().splitlines()[-1][:200])
            return
        arch = REPO / "05_Experimental_Results/Bayesian_AI"
        for name in ("synthetic_scenario_aggregates.csv", "synthetic_prequential_brier_aggregates.csv",
                     "paired_policy_differences.csv"):
            ok, detail, _ = compare_csv(out / name, arch / name)
            report(f"Synthetic re-run reproduces {name}", "PASS" if ok else "FAIL", detail)


def check_manuscript_additions():
    """Numbers added to the revised manuscript: T_b sensitivity and forged-alarm limiter."""
    import re
    r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/forged_alarm_flood_demo.py")], 120)
    nums = re.findall(r"interval ([0-9.]+) -> ([0-9.]+)", r.stdout)
    ok = r.returncode == 0 and len(nums) == 2 and round(float(nums[0][1]), 1) == 28.2 and round(float(nums[1][1]), 1) == 39.4
    report("Forged-alarm flood: 76.4 -> 28.2 s (no cap), 39.4 s (cap 10/60 s)", "PASS" if ok else "FAIL",
           "; ".join(f"{a}->{b}" for a, b in nums))
    r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/tb_sensitivity.py")], 300)
    rows = {int(m[0]): m[1:] for m in re.findall(r"^\s*(\d+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*$", r.stdout, re.M)}
    ok = (r.returncode == 0 and rows.get(600, (0, 0, 0))[2] == "73.96" and rows.get(150, (0, 0, 0))[1] == "1.8"
          and rows.get(100, (0, 0, 0))[1] == "60.0" and rows.get(100, (0, 0, 0))[2] == "64.12")
    report("T_b sensitivity: 73.96 s for T_b>=200; 1.8 % / 60 % capped at 150 / 100 s", "PASS" if ok else "FAIL")


def check_independent_crosscheck():
    """Two independent implementations (repository controller vs SciPy / standalone script) must agree."""
    try:
        import scipy  # noqa: F401
    except ImportError:
        report("Independent cross-check (SciPy implementation)", "SKIP", "SciPy not installed")
        return
    res = REPO / "05_Experimental_Results/Bayesian_AI"
    mine = {int(r["T_b_s"]): r for r in csv.DictReader((res / "tb_sensitivity.csv").open())}
    other = {int(r["assumed_tb_seconds"]): r for r in csv.DictReader((res / "tb_sensitivity_results.csv").open())}
    worst = max(max(abs(float(mine[k]["mean_accepted_interval_s"]) - float(v["mean_lifetime_seconds"])),
                    abs(float(mine[k]["capped_by_0.7Tb_pct"]) - 100 * float(v["fraction_capped_by_tb"])))
                for k, v in other.items())
    report("T_b sensitivity: two implementations agree", "PASS" if worst < 0.1 else "FAIL", f"max difference {worst:.3f}")
    ref = json.loads((res / "forged_alarm_limiter_results.json").read_text())["output"]
    r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/forged_alarm_flood_demo.py")], 120)
    import re
    nums = [float(x[1]) for x in re.findall(r"interval ([0-9.]+) -> ([0-9.]+)", r.stdout)]
    ok = (len(nums) == 2 and abs(nums[0] - ref["without_limiter_lifetime_s"]) < 0.01
          and abs(nums[1] - ref["with_limiter_lifetime_s"]) < 0.01)
    report("Forged-alarm limiter: two implementations agree", "PASS" if ok else "FAIL", f"{nums} vs "
           f"[{ref['without_limiter_lifetime_s']}, {ref['with_limiter_lifetime_s']}]")


def check_ewma():
    import re
    r = run([sys.executable, str(REPO / "02_Bayesian_AI/Reproduction/ewma_baseline_comparison.py")], 300)
    diff = re.search(r"archived table \(shared predictors\): ([0-9.e+-]+)", r.stdout)
    wins = re.search(r"\{.*\}", r.stdout)
    ok = (r.returncode == 0 and diff and float(diff.group(1)) < 1e-4 and wins and "'ewma0p10': 4" in wins.group(0))
    report("EWMA comparison: shared predictors match archive; EWMA 0.10 best in 4 of 6", "PASS" if ok else "FAIL")


def check_tests():
    jobs = (("Controller tests (v1 + v2)", REPO / "02_Bayesian_AI/Controller", ["-m", "unittest", "test_intelligent_key_renewal", "test_controller_v2"]),
            ("Gateway loopback tests", REPO / "04_Security_Verification/Tests", ["test_gateway_epoch_loopback.py"]),
            ("Lost-/ack fault-injection tests", REPO / "04_Security_Verification/Tests", ["loss_ack_fault_injection_runner.py"]),
            ("Gateway hardening tests", REPO / "04_Security_Verification/Tests", ["test_gateway_hardening.py"]))
    for name, cwd, args in jobs:
        r = run([sys.executable, *args], 600) if False else subprocess.run(
            [sys.executable, *args], cwd=cwd, capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()
        report(name, "PASS" if r.returncode == 0 else "FAIL", tail[-1] if tail else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="skip the synthetic-scenario re-run (slowest step)")
    args = ap.parse_args()
    sums = REPO / "SHA256SUMS.txt"
    if sums.is_file():
        check_manifest(sums, REPO, "SHA256SUMS.txt")
    else:
        report("SHA256SUMS.txt", "SKIP", "file not found")
    check_manifest(REPO / "04_Security_Verification/Scyther/SHA256_MANIFEST.txt",
                   REPO / "04_Security_Verification/Scyther", "Scyther manifest")
    check_attestations()
    check_stage6()
    check_stage4_replay()
    if args.quick:
        report("Synthetic scenarios re-run", "SKIP", "--quick")
    else:
        check_synthetic()
    check_manuscript_additions()
    check_independent_crosscheck()
    check_ewma()
    check_tests()
    failed = [n for n, s in RESULTS if s == "FAIL"]
    print("\n" + ("ALL CHECKS PASSED" if not failed else f"{len(failed)} CHECK(S) FAILED: " + "; ".join(failed)))
    print("Not verifiable here: raw serial logs (Stage 6 timings are checked from the archived summary only), "
          "EOSIO chain state, firmware builds, Scyther runs.")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
