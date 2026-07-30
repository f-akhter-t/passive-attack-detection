"""
evaluate.py

Compares detect.py's output against your manually-logged attack windows
(ground truth) to compute:
  - Detection rate (recall): fraction of attack windows where at least one
    anomaly was flagged during the attack's active period
  - False positive rate: fraction of NON-attack windows incorrectly flagged
  - Time-to-detect: seconds between attack start and first flag, per tool
  - Precision: of all flags raised, what fraction fell inside an attack window

Requires an attack log CSV with columns: tool,start_time,end_time
(timestamps parseable by pandas, e.g. "2026-07-20 14:02:00")

Usage:
    python3 evaluate.py --detections results/detections.csv \
        --attack-log data/attack/attack_log.csv \
        --out results/evaluation_report.txt
"""

import argparse
import math
import os

import pandas as pd


def wilson_interval(successes, n, z=1.96):
    """Wilson score interval for a binomial proportion (default: 95% CI).

    More reliable than a normal approximation when n is small or the
    proportion is near 0 or 1 -- both apply to our thin false-positive
    sample, which is exactly why this was flagged as needed.
    """
    if n == 0:
        return float("nan"), float("nan")
    p = successes / n
    denom = 1 + z ** 2 / n
    center = p + z ** 2 / (2 * n)
    half_width = z * math.sqrt((p * (1 - p) / n) + (z ** 2 / (4 * n ** 2)))
    lower = (center - half_width) / denom
    upper = (center + half_width) / denom
    return max(0.0, lower), min(1.0, upper)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detections", required=True)
    ap.add_argument("--attack-log", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tz", default="America/New_York",
                     help="Local timezone your attack_log.csv timestamps are written in "
                          "(e.g. from the VM's `date` command). pcap timestamps are always "
                          "true UTC epoch seconds, so this must be set correctly or every "
                          "ground-truth window will silently fail to match.")
    args = ap.parse_args()

    det = pd.read_csv(args.detections)
    # Bug fix: pcap-derived window_start is UTC epoch seconds, but attack_log.csv is
    # logged in local wall-clock time (whatever `date` printed on the capturing VM,
    # e.g. EDT). Converting to that same local zone here is what lets the two
    # timestamp sources actually line up -- without it every ground-truth window
    # silently fails to match (this is the same failure mode flagged in a prior audit).
    det["window_start"] = (
        pd.to_datetime(det["window_start"], unit="s", utc=True)
        .dt.tz_convert(args.tz)
        .dt.tz_localize(None)
    )
    log = pd.read_csv(args.attack_log, parse_dates=["start_time", "end_time"])

    lines = []
    lines.append("=== Evaluation Report ===\n")

    def in_any_attack(ts):
        matches = log[(log["start_time"] <= ts) & (ts <= log["end_time"])]
        return matches["tool"].tolist()

    det["attack_tools_active"] = det["window_start"].apply(in_any_attack)
    det["ground_truth_attack"] = det["attack_tools_active"].apply(lambda x: len(x) > 0)

    total = len(det)
    flagged = det["is_anomaly"].sum()
    true_positive_rows = det[(det["is_anomaly"]) & (det["ground_truth_attack"])]
    false_positive_rows = det[(det["is_anomaly"]) & (~det["ground_truth_attack"])]

    n_attack_rows = det["ground_truth_attack"].sum()
    n_normal_rows = total - n_attack_rows

    recall = len(true_positive_rows) / n_attack_rows if n_attack_rows else float("nan")
    fpr = len(false_positive_rows) / n_normal_rows if n_normal_rows else float("nan")
    precision = len(true_positive_rows) / flagged if flagged else float("nan")

    lines.append(f"Total windows evaluated: {total}")
    lines.append(f"  Ground-truth attack windows : {n_attack_rows}")
    lines.append(f"  Ground-truth normal windows  : {n_normal_rows}")
    lines.append("")
    fpr_lo, fpr_hi = wilson_interval(len(false_positive_rows), n_normal_rows)
    recall_lo, recall_hi = wilson_interval(len(true_positive_rows), n_attack_rows)

    lines.append(f"Detection rate (recall)      : {recall:.1%}  (95% CI: {recall_lo:.1%}-{recall_hi:.1%}, n={n_attack_rows})")
    lines.append(f"False positive rate          : {fpr:.1%}  (95% CI: {fpr_lo:.1%}-{fpr_hi:.1%}, n={n_normal_rows})")
    lines.append(f"Precision                    : {precision:.1%}")
    lines.append("")
    if n_normal_rows < 30:
        lines.append(f"NOTE: only {n_normal_rows} ground-truth normal windows -- FPR CI is wide by necessity. "
                      f"Phase 1b's idle-window fix should substantially grow this once re-extracted from real pcaps.")
        lines.append("")

    lines.append("--- Time-to-detect per tool ---")
    for _, row in log.iterrows():
        tool, start, end = row["tool"], row["start_time"], row["end_time"]
        window = det[(det["window_start"] >= start) & (det["window_start"] <= end)]
        flagged_in_window = window[window["is_anomaly"]].sort_values("window_start")
        if len(flagged_in_window):
            first_flag = flagged_in_window.iloc[0]["window_start"]
            ttd = (first_flag - start).total_seconds()
            detect_rate_tool = window["is_anomaly"].mean()
            lines.append(
                f"  {tool:12s} | first flagged after {ttd:6.1f}s | "
                f"{detect_rate_tool:.1%} of windows during this attack flagged"
            )
        else:
            lines.append(f"  {tool:12s} | NOT DETECTED during its active window")

    lines.append("")
    lines.append("--- Per-device breakdown ---")
    lines.append("(Tests whether flags attribute to the specific device, or whether ALL devices")
    lines.append(" look anomalous once ARP poisoning starts on the segment -- a real question for")
    lines.append(" a per-device fingerprinting design, not just extra detail.)")
    for mac, grp in det.groupby("device_mac"):
        grp_attack = grp[grp["ground_truth_attack"]]
        grp_normal = grp[~grp["ground_truth_attack"]]
        dev_recall = grp_attack["is_anomaly"].mean() if len(grp_attack) else float("nan")
        dev_fpr = grp_normal["is_anomaly"].mean() if len(grp_normal) else float("nan")
        recall_str = f"{dev_recall:.1%}" if not pd.isna(dev_recall) else "n/a (no attack windows for this device)"
        fpr_str = f"{dev_fpr:.1%}" if not pd.isna(dev_fpr) else "n/a (no normal windows for this device)"
        lines.append(
            f"  {mac:20s} | recall during attacks: {recall_str:8s} (n={len(grp_attack):3d}) | "
            f"FPR during normal: {fpr_str:8s} (n={len(grp_normal):3d})"
        )
    lines.append("")

    report = "\n".join(lines)
    print(report)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(report + "\n")
    print(f"\nWrote report to {args.out}")


if __name__ == "__main__":
    main()
