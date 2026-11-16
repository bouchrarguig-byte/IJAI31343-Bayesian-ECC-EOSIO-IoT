#!/usr/bin/env python3
"""IJ-AI 31343: prepare descriptive Stage 6 manuscript tables/figures.

Reads the existing stage6_statistical_summary.json only. Does not access hardware,
keys, private configuration, EOSIO RPC, or raw sources. Results are descriptive;
no independence, causal-effect, or energy-saving claim is made.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path

MEASURES = (
    ("ESP8266", "X25519", "renewal_total_ms", "renewal_total", "ms"),
    ("ESP8266", "P256", "renewal_total_ms", "renewal_total", "ms"),
    ("ESP8266", "X25519", "free_heap_after_b", "free_heap_after", "bytes"),
    ("ESP8266", "P256", "free_heap_after_b", "free_heap_after", "bytes"),
)
FIELDS = ["platform", "curve", "metric", "unit", "n", "mean", "sample_sd", "median", "min", "max", "p95_nearest_rank"]


def measure(platform, curve, metric, label, unit, data):
    group = (data.get("platforms", {}).get(platform, {}).get("serial") or {}).get("groups", {}).get(curve, {})
    s = group.get(metric) or {}
    return {
        "platform": platform, "curve": curve, "metric": label, "unit": unit,
        "n": s.get("n"), "mean": s.get("mean"), "sample_sd": s.get("sd_sample"),
        "median": s.get("median"), "min": s.get("min"), "max": s.get("max"),
        "p95_nearest_rank": s.get("p95_nearest_rank"),
    }


def plot_bar(rows, wanted_metric, title, ylabel, output, note):
    selected = [r for r in rows if r["metric"] == wanted_metric and r["mean"] is not None]
    if not selected:
        return False
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = [f"{r['platform']}\n{r['curve']} (n={r['n']})" for r in selected]
    means = [float(r["mean"]) for r in selected]
    deviations = [float(r["sample_sd"] or 0.0) for r in selected]
    fig, ax = plt.subplots(figsize=(7.6, 4.8))
    ax.bar(labels, means, yerr=deviations, capsize=7, width=0.52)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    fig.text(0.5, 0.025, note, ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.075, 1, 1))
    fig.savefig(output, dpi=220)
    plt.close(fig)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "IJAI_31343_Work")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    stage = root / "Revision_31343/Experimental_Results/Stage6/Statistical_Analysis"
    inp = stage / "stage6_statistical_summary.json"
    if not inp.is_file():
        parser.error("Rapport introuvable: " + str(inp))
    data = json.loads(inp.read_text(encoding="utf-8"))
    if not isinstance(data.get("platforms"), dict):
        parser.error("Format du rapport incorrect: manque platforms")
    out = stage / "Publication_Stage6"
    out.mkdir(parents=True, exist_ok=True)
    rows = [measure(*m, data) for m in MEASURES]
    for platform in ("ESP8266", "ESP32"):
        block = data["platforms"].get(platform, {})
        s = (block.get("eosio_submission") or {}).get("submission_latency_ms") or {}
        rows.append({
            "platform": platform, "curve": "all", "metric": "EOSIO_submission_latency",
            "unit": "ms", "n": s.get("n"), "mean": s.get("mean"), "sample_sd": s.get("sd_sample"),
            "median": s.get("median"), "min": s.get("min"), "max": s.get("max"),
            "p95_nearest_rank": s.get("p95_nearest_rank")
        })
    csv_path = out / "stage6_publication_descriptive_table.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=FIELDS)
        wr.writeheader(); wr.writerows(rows)

    print("=== IJ-AI 31343 / STAGE 6 PUBLICATION CHECK ===")
    print("Source JSON SHA256:", hashlib.sha256(inp.read_bytes()).hexdigest())
    print(f"{'Platform':<9} {'Curve':<10} {'Metric':<27} {'n':>4} {'Mean':>12} {'SD':>12}")
    print("-" * 83)
    for r in rows:
        mean = "N/A" if r['mean'] is None else f"{r['mean']:.3f}"
        sd = "N/A" if r['sample_sd'] is None else f"{r['sample_sd']:.3f}"
        print(f"{r['platform']:<9} {r['curve']:<10} {r['metric']:<27} {str(r['n']):>4} {mean:>12} {sd:>12}")

    x = next((r for r in rows if r['platform']=='ESP8266' and r['curve']=='X25519' and r['metric']=='renewal_total'), None)
    p = next((r for r in rows if r['platform']=='ESP8266' and r['curve']=='P256' and r['metric']=='renewal_total'), None)
    xf = next((r for r in rows if r['platform']=='ESP8266' and r['curve']=='X25519' and r['metric']=='free_heap_after'), None)
    pf = next((r for r in rows if r['platform']=='ESP8266' and r['curve']=='P256' and r['metric']=='free_heap_after'), None)
    if x and p and x['mean'] is not None and p['mean'] is not None:
        absolute = p['mean'] - x['mean']
        percent = 100 * absolute / p['mean']
        print(f"\nX25519 mean shorter than P256 by {absolute:.3f} ms ({percent:.2f}% relative to P256).")
        print(f"P256 mean longer than X25519 by {100*absolute/x['mean']:.2f}% relative to X25519.")
    if xf and pf and xf['mean'] is not None and pf['mean'] is not None:
        print(f"P256 mean free heap after renewal lower by {xf['mean']-pf['mean']:.1f} bytes (descriptive).")
    print("\nEOSIO audit:")
    total_att = 0
    all_match = True
    for platform in ("ESP8266", "ESP32"):
        b = data["platforms"].get(platform, {})
        eosio = (b.get('eosio_table') or {})
        n = eosio.get('attestations')
        matched = eosio.get('matches_local_event_hashes')
        total_att += n or 0
        all_match = all_match and (matched is True)
        print(f"  {platform}: attestations={n}, matching_hashes={matched}")
    print(f"  Total={total_att}, all_match={all_match}")

    figs = []
    if plot_bar(rows, "renewal_total", "ESP8266: observed ECC renewal durations", "Complete renewal time (ms)",
                out / "Fig_Stage6_ESP8266_ECC_renewal.png", "Mean ± 1 sample SD; successive epochs from one hardware campaign"):
        figs.append("Fig_Stage6_ESP8266_ECC_renewal.png")
    if plot_bar(rows, "free_heap_after", "ESP8266: available heap after renewal", "Free heap (bytes)",
                out / "Fig_Stage6_ESP8266_free_heap.png", "Mean ± 1 sample SD; only measured post-renewal heap"):
        figs.append("Fig_Stage6_ESP8266_free_heap.png")

    (out / "README_LIMITATIONS.txt").write_text(
        "IJ-AI 31343 | Stage6 descriptive summary\n\n"
        "Data source: already computed Stage6 statistical summary; no new hardware experiment.\n"
        "Figures display means +/- sample standard deviations, not confidence intervals.\n"
        "ECC renewal times include more than the bare elliptic-curve operation.\n"
        "The successive epochs in each experiment are correlated; do not treat them as independent trials\n"
        "for hypothesis testing or make causal superiority claims.\n"
        "ESP32 serial ECC latency and heap measurements are unavailable in this report.\n"
        "EOSIO submission latencies refer to separate experimental campaigns and cannot prove\n"
        "relative hardware speed. ESP8266 EOSIO latency has n=17, while 18 attestations exist.\n"
        "All 39 EOSIO hash matches are retrospective and do not demonstrate real-time chain integration\n"
        "or physical provenance. No measured whole-life-cycle energy data exist here.\n"
        "No claims of 20 percent energy saving, 0.99 ms full renewal, post-quantum security, or\n"
        "attack prevention are justified by this summary.\n",
        encoding="utf-8"
    )
    print("\nCSV:", csv_path)
    print("Figures:", ', '.join(figs) if figs else "Not generated (matplotlib unavailable?)")
    print("Notes:", out / "README_LIMITATIONS.txt")
    print("Read-only original data. New publication files only.")

if __name__ == '__main__':
    main()
