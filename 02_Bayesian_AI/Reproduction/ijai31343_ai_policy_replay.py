#!/usr/bin/env python3
"""IJ-AI 31343: read-only Stage 4 policy decision replay & ablations.

This script DOES NOT run ESP hardware, cryptography, EOSIO, or measure energy.
It compares POLICY DECISIONS using a fixed recorded feedback stream from one
adaptive run. It is NOT a paired hardware experiment or valid estimate of
counterfactual key-installation counts, power, attack detection, or accuracy.

Reads the original Stage4 adaptive after-injection JSONL, dynamically imports
intelligent_key_renewal.py from the Stage7 copy, and creates only NEW reports.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import json
import math
from collections import deque
from datetime import datetime
from pathlib import Path
from statistics import mean

POLICIES = ["fixed_60", "fixed_90", "fixed_120", "heuristic_2of5",
            "bayes_upper_lambda2", "bayes_upper_lambda4", "bayes_upper_lambda8",
            "bayes_mean_lambda4"]
FIELDS = [
    "snapshot", "timestamp_utc", "source_event", "category", "epoch",
    "normal_events", "suspicious_events", "risk_upper_mc", "risk_mean",
    "logged_adaptive_interval_s", "replayed_bayesian_interval_s",
    "absolute_reconstruction_error_s", *POLICIES,
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_source(path: Path):
    spec = importlib.util.spec_from_file_location("ijai_s7_controller_for_policy_replay", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot import model: {path}")
    import sys
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_snapshots(path: Path):
    out = []
    observed_events = deque(maxlen=5)
    prev_time = None
    for lineno, rawline in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not rawline.strip():
            continue
        event = json.loads(rawline)
        if not isinstance(event, dict):
            raise ValueError(f"Unexpected nonobject row at {lineno}")
        kind = event.get("kind")
        if kind not in ("epoch_activated", "risk_observation"):
            continue
        ts = datetime.fromisoformat(event["ts_utc"])
        if ts.tzinfo is None:
            raise ValueError(f"Missing timezone at line {lineno}")
        if prev_time is not None and ts < prev_time:
            raise ValueError(f"Nonmonotonic event order at line {lineno}")
        prev_time = ts
        if kind == "epoch_activated":
            observed_events.append("success")
            logged_interval = event["interval_seconds"]
            category = "success"
        else:
            category = str(event.get("category", ""))
            if category not in {"invalid_proof", "failed_auth", "replay"}:
                raise ValueError(f"Unexpected suspicious category at line {lineno}: {category}")
            observed_events.append(category)
            logged_interval = event["interval_after_seconds"]
        n_ok = int(event["events_normal"])
        n_bad = int(event["events_suspicious"])
        if n_ok < 0 or n_bad < 0:
            raise ValueError("Negative event counts")
        if not math.isfinite(float(logged_interval)):
            raise ValueError("Nonfinite source interval")
        out.append({
            "timestamp_utc": ts.isoformat(),
            "source_event": kind,
            "category": category,
            "epoch": event.get("epoch", "") if kind == "epoch_activated" else "",
            "normal_events": n_ok,
            "suspicious_events": n_bad,
            "logged_adaptive_interval_s": float(logged_interval),
            "logged_risk_upper": (event.get("risk_posterior_upper_mc") if kind == "epoch_activated"
                                  else event.get("risk_upper_after")),
            "heuristic_recent_anomalies": sum(x != "success" for x in observed_events),
        })
    if not out:
        raise ValueError("No policy snapshots found in source log")
    # In this specific Stage4 recorded campaign, the file starts from epoch 1.
    # A partial log cannot reconstruct the last-five event heuristic unambiguously.
    if int(out[0]["normal_events"]) != 1 or out[0]["suspicious_events"] != 0:
        raise ValueError("Partial run: heuristic last-five history cannot be reconstructed safely")
    for idx, snap in enumerate(out):
        if snap["normal_events"] + snap["suspicious_events"] != idx + 1:
            raise ValueError("Feedback count mismatch in recorded sequence; refusing causal inference")
    return out


def get_estimations(mod, n_ok, n_bad):
    cfg = mod.PolicyConfig(posterior_samples=1024)
    model = mod.BayesianRiskEstimator(cfg)
    model.normal_events = n_ok
    model.anomalies = n_bad
    return model.posterior_mean, model.posterior_upper_bound()


def interval_value(risk, sensitivity, baseline=120.0, horizon=600.0,
                   safety_fraction=0.7, maximum=300.0, minimum=10.0):
    val = min(maximum, safety_fraction * horizon, baseline / (1 + sensitivity * risk))
    if not (minimum <= val < horizon):
        raise ValueError("Inadmissible counterfactual policy interval")
    return round(val, 6)


def summary(values):
    if not values:
        return None
    return {"n_snapshots": len(values), "mean_s": round(mean(values), 6),
            "min_s": round(min(values), 6), "max_s": round(max(values), 6)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home()/"IJAI_31343_Work")
    parser.add_argument("--output", type=Path, help="Separate output folder for new reports")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    revision = root/"Revision_31343"
    source = revision/"Experimental_Results/Stage4/Adaptive/Stage4_ADAPTIVE_after_injection.jsonl"
    model_path = revision/"IJAI_31343_Stage7_Instrumented/Pi_Gateway/intelligent_key_renewal.py"
    dest = (args.output.expanduser().resolve() if args.output else
            revision/"Experimental_Results/Stage7_Fixed_vs_Adaptive/AI_Policy_Replay")
    if not source.is_file() or not model_path.is_file():
        raise SystemExit(f"Missing input:\n  log={source} [{source.is_file()}]\n"
                         f"  controller={model_path} [{model_path.is_file()}]")
    if dest == source.parent or dest == model_path.parent:
        raise SystemExit("Output folder must not overlap with a source folder")
    mod = load_source(model_path)
    snaps = load_snapshots(source)
    rows = []
    mc_errors = []
    count_mismatches = 0
    for i, snap in enumerate(snaps, 1):
        n_ok = snap["normal_events"]
        n_bad = snap["suspicious_events"]
        posterior_mean, upper_mc = get_estimations(mod, n_ok, n_bad)
        if snap["logged_risk_upper"] is not None:
            mc_err = abs(float(snap["logged_risk_upper"]) - upper_mc)
            mc_errors.append(mc_err)
        b4 = interval_value(upper_mc, 4)
        difference = abs(b4 - snap["logged_adaptive_interval_s"])
        if difference > 0.02:
            count_mismatches += 1
        row = {
            "snapshot": i,
            "timestamp_utc": snap["timestamp_utc"],
            "source_event": snap["source_event"],
            "category": snap["category"],
            "epoch": snap["epoch"],
            "normal_events": n_ok,
            "suspicious_events": n_bad,
            "risk_upper_mc": round(upper_mc, 6),
            "risk_mean": round(posterior_mean, 6),
            "logged_adaptive_interval_s": round(snap["logged_adaptive_interval_s"], 6),
            "replayed_bayesian_interval_s": b4,
            "absolute_reconstruction_error_s": round(difference, 6),
            "fixed_60": interval_value(0, 0, baseline=60),
            "fixed_90": interval_value(0, 0, baseline=90),
            "fixed_120": interval_value(0, 0, baseline=120),
            "heuristic_2of5": (60 if snap["heuristic_recent_anomalies"] >= 2 else 120),
            "bayes_upper_lambda2": interval_value(upper_mc, 2),
            "bayes_upper_lambda4": b4,
            "bayes_upper_lambda8": interval_value(upper_mc, 8),
            "bayes_mean_lambda4": interval_value(posterior_mean, 4),
        }
        rows.append(row)
    if count_mismatches:
        raise SystemExit(
            f"ERROR: {count_mismatches} source-vs-model discrepancies > 0.02 s. "
            "Do not cite a replay; inspect config/version differences first. "
            f"Worst discrepancy={max(r['absolute_reconstruction_error_s'] for r in rows):.6f} s."
        )
    dest.mkdir(parents=True, exist_ok=True)
    csvpath = dest/"stage4_policy_decision_replay.csv"
    with csvpath.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    risk_rows = [r for r in rows if r["source_event"] == "risk_observation"]
    first_risk_index = next((i for i, s in enumerate(rows) if s["source_event"] == "risk_observation"), None)
    before_risk = rows[first_risk_index-1] if first_risk_index and first_risk_index > 0 else None
    report = {
        "status": "descriptive offline replay of policy decisions; NOT hardware/energy/attack-accuracy evidence",
        "source_file": str(source), "source_sha256": digest(source),
        "model_file": str(model_path), "model_sha256": digest(model_path),
        "config": {"prior_alpha":1,"prior_beta":19,"baseline_s":120,"horizon_s":600,
                   "minimum_s":10,"maximum_s":300,"safety_fraction":0.7,
                   "confidence":0.95,"posterior_samples":1024,"seed":31343},
        "n_snapshots": len(rows), "n_recorded_risk_observations": len(risk_rows),
        "n_logged_epoch_activations": sum(r["source_event"]=="epoch_activated" for r in rows),
        "reconstruction_max_absolute_error_s": max(r["absolute_reconstruction_error_s"] for r in rows),
        "reconstruction_max_risk_upper_error": max(mc_errors) if mc_errors else None,
        "policy_snapshot_summary_all": {p:summary([r[p] for r in rows]) for p in POLICIES},
        "policy_snapshot_summary_risk_only": {p:summary([r[p] for r in risk_rows]) for p in POLICIES},
        "risk_transition_first_vs_last": {
            "before_observations": {"risk_upper":before_risk["risk_upper_mc"],
                                    "interval_s": before_risk["bayes_upper_lambda4"]} if before_risk else None,
            "after_last_observation": {"risk_upper":risk_rows[-1]["risk_upper_mc"],
                                       "interval_s":risk_rows[-1]["bayes_upper_lambda4"]} if risk_rows else None,
        },
        "limitations": [
            "Recorded adaptive events are not an independent fixed-policy hardware arm.",
            "The heuristic consumes the observed success/invalid-event sequence, whose success events depend on the adaptive system's own epoch activations.",
            "Fixed/heuristic/ablation values represent calculations on the same recorded feedback; not executed rotations.",
            "The source event labels are not independent ground-truth attack labels.",
            "A change in renewal decisions does not demonstrate risk reduction, energy saving, FPR, TPR or calibrated prediction.",
            "T_b=600 s is a scenario assumption, not observed time-to-break, quantum time, or learned output.",
            "Snapshots are repeated, correlated observations, not independent trials; no significance p-values or CI from these rows.",
            "The heuristic 2-of-5 threshold is a declared illustrative baseline, not a previously validated industry standard.",
        ],
    }
    out_json = dest/"stage4_policy_replay_summary.json"
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n",encoding="utf-8")
    notes = dest/"README_INTERPRETATION.txt"
    notes.write_text(
        "IJ-AI 31343 / Stage4 offline policy decision replay\n"
        "SOURCE: recorded Stage4_ADAPTIVE_after_injection.jsonl, unchanged.\n"
        "DECISION STREAM: epoch_activated=observed success; risk_observation=suspicious evidence.\n"
        "POLICIES: fixed 60/90/120 s; heuristic 60 s iff >=2 suspicious among last 5\n"
        "recorded feedback events else 120 s; Bayesian risk posterior 95% Monte Carlo\n"
        "upper quantile with lambda 2/4/8; posterior-mean ablation with lambda 4.\n"
        "The model's simulated decisions are recomputed from source event counts.\n"
        "Comparators are NOT actual hardware runs. The replay is not a paired trial,\n"
        "and gives NO energy, attack efficacy or installed-key counts.\n"
        "Read the JSON limitations before using any numbers in a manuscript.\n",encoding="utf-8"
    )
    print("=== IJ-AI 31343: OFFLINE POLICY DECISION REPLAY ===")
    print("Snapshots:",len(rows),"| risk events:",len(risk_rows),
          "| gateway activation snapshots:",report["n_logged_epoch_activations"])
    print("Max model-to-log interval difference (s):",report["reconstruction_max_absolute_error_s"])
    if before_risk and risk_rows:
        before=before_risk["bayes_upper_lambda4"]
        after=risk_rows[-1]["bayes_upper_lambda4"]
        print(f"Bayesian λ=4: before injection {before:.6f} s -> after last risk event {after:.6f} s")
        print(f"Descriptive change: {(before-after)/before*100:.2f}% shorter")
    print("Policy snapshot means are in",out_json.name)
    print("CSV:",csvpath)
    print("JSON:",out_json)
    print("Notes:",notes)
    print("NOTE: replayed policy decisions only; no hardware or energy claims.")

if __name__ == "__main__":
    main()
