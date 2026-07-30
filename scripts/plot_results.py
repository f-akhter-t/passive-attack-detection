"""
plot_results.py

Generates figures for the project report:
  1. anomaly_timeline.png   - anomaly score over time, per device, with any
                              flagged points highlighted
  2. feature_distributions.png - baseline vs attack distributions for each
                              feature (helps show *why* the model flagged things)
  3. detection_summary.png  - bar chart of flagged vs not-flagged windows

Usage:
    python3 plot_results.py --features data/baseline/features_baseline.csv \
        --attack-features data/attack/features_attack.csv \
        --detections results/detections.csv \
        --outdir results/plots/
"""

import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

FEATURE_COLS = [
    "pkt_count", "byte_count", "mean_iat", "std_iat",
    "arp_req_count", "arp_req_rate", "arp_reply_count", "arp_reply_rate",
    "broadcast_ratio", "avg_response_latency", "send_recv_ratio",
]


def plot_timeline(det_df, outdir, tz="UTC"):
    det_df = det_df.copy()
    det_df["window_start"] = (
        pd.to_datetime(det_df["window_start"], unit="s", utc=True)
        .dt.tz_convert(tz)
        .dt.tz_localize(None)
    )
    fig, ax = plt.subplots(figsize=(12, 5))
    for mac, grp in det_df.groupby("device_mac"):
        grp = grp.sort_values("window_start")
        ax.plot(grp["window_start"], grp["anomaly_score"], marker="o",
                markersize=3, label=str(mac), alpha=0.7)
    flagged = det_df[det_df["is_anomaly"]]
    ax.scatter(flagged["window_start"], flagged["anomaly_score"],
               color="red", zorder=5, label="Flagged anomaly", s=40)
    ax.set_xlabel("Time")
    ax.set_ylabel("Anomaly score (lower = more anomalous)")
    ax.set_title("Anomaly score over time by device")
    ax.legend(fontsize=8, loc="best")
    fig.tight_layout()
    path = os.path.join(outdir, "anomaly_timeline.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Wrote {path}")


def plot_feature_distributions(baseline_df, attack_df, outdir):
    baseline_df = baseline_df.copy()
    attack_df = attack_df.copy()
    baseline_df["label"] = "baseline"
    attack_df["label"] = "attack-period"
    combined = pd.concat([baseline_df, attack_df], ignore_index=True)

    n = len(FEATURE_COLS)
    ncols = 3
    nrows = (n + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(5 * ncols, 4 * nrows))
    axes = axes.flatten()
    for i, col in enumerate(FEATURE_COLS):
        if col not in combined.columns:
            continue
        sns.kdeplot(data=combined, x=col, hue="label", ax=axes[i], common_norm=False)
        axes[i].set_title(col)
    for j in range(i + 1, len(axes)):
        fig.delaxes(axes[j])
    fig.tight_layout()
    path = os.path.join(outdir, "feature_distributions.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Wrote {path}")


def plot_detection_summary(det_df, outdir):
    counts = det_df["is_anomaly"].value_counts().rename({True: "Flagged", False: "Not flagged"})
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.barplot(x=counts.index.astype(str), y=counts.values, ax=ax)
    ax.set_ylabel("Number of windows")
    ax.set_title("Detection summary")
    fig.tight_layout()
    path = os.path.join(outdir, "detection_summary.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Wrote {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features", required=True, help="baseline features CSV")
    ap.add_argument("--attack-features", required=True, help="attack-period features CSV")
    ap.add_argument("--detections", required=True, help="detect.py output CSV")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--tz", default="UTC",
                     help="timezone for x-axis display (e.g. Asia/Dhaka); "
                          "must match the timezone used in evaluate.py --tz")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    sns.set_theme(style="whitegrid")

    baseline_df = pd.read_csv(args.features)
    attack_df = pd.read_csv(args.attack_features)
    det_df = pd.read_csv(args.detections)

    plot_timeline(det_df, args.outdir, tz=args.tz)
    plot_feature_distributions(baseline_df, attack_df, args.outdir)
    plot_detection_summary(det_df, args.outdir)


if __name__ == "__main__":
    main()
