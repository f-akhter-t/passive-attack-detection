"""
plot_sweep.py

Reads the contamination sweep evaluation reports produced by run_full_pipeline.sh
(results/sweep/eval_c_*.txt) and generates a single summary figure:

  results/plots/contamination_sweep.png
    - Recall and FPR vs. contamination parameter (line plot, dual y-axis)
    - Shows the recall/FPR tradeoff as contamination is tuned
    - Vertical line at c=0.08 marks the default used in the main evaluation

Usage:
    python3 scripts/plot_sweep.py --sweep-dir results/sweep/ --outdir results/plots/

No extra dependencies beyond what is already in requirements.txt.
"""

import argparse
import glob
import os
import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


def parse_eval_file(path):
    """Extract recall and FPR from one eval_c_*.txt file.

    Returns (contamination_float, recall_float, fpr_float) or None on parse
    failure.  Parsing is deliberately simple: looks for the two labelled lines
    that evaluate.py writes, e.g.
        Detection rate (recall)      : 29.5%  (95% CI: 22.9%-37.1%, n=156)
        False positive rate          : 0.2%   (95% CI: 0.1%-0.4%, n=5100)
    """
    basename = os.path.basename(path)          # eval_c_0.08.txt
    m = re.search(r"eval_c_([\d.]+)\.txt$", basename)
    if not m:
        return None
    c = float(m.group(1))

    recall = fpr = None
    with open(path) as f:
        for line in f:
            if "Detection rate (recall)" in line:
                pct = re.search(r":\s+([\d.]+)%", line)
                if pct:
                    recall = float(pct.group(1)) / 100.0
            if "False positive rate" in line:
                pct = re.search(r":\s+([\d.]+)%", line)
                if pct:
                    fpr = float(pct.group(1)) / 100.0
    if recall is None or fpr is None:
        return None
    return c, recall, fpr


def plot_sweep(sweep_dir, outdir):
    paths = sorted(glob.glob(os.path.join(sweep_dir, "eval_c_*.txt")))
    if not paths:
        raise FileNotFoundError(
            f"No eval_c_*.txt files found in {sweep_dir}. "
            "Run run_full_pipeline.sh (Phase 5) first."
        )

    points = []
    for p in paths:
        result = parse_eval_file(p)
        if result:
            points.append(result)
        else:
            print(f"  WARNING: could not parse {p}, skipping.")

    if len(points) < 2:
        raise ValueError(f"Only {len(points)} parseable files found; need >= 2 to plot.")

    points.sort(key=lambda x: x[0])
    contaminations = [p[0] for p in points]
    recalls        = [p[1] for p in points]
    fprs           = [p[2] for p in points]

    # --- figure setup ---
    fig, ax1 = plt.subplots(figsize=(7, 4.5))
    ax2 = ax1.twinx()

    col_recall = "#2563EB"   # blue
    col_fpr    = "#DC2626"   # red
    default_c  = 0.08        # vertical reference line

    # Plot recall on left axis
    ax1.plot(contaminations, [r * 100 for r in recalls],
             color=col_recall, marker="o", linewidth=2, markersize=7,
             label="Recall (detection rate)")
    ax1.set_ylabel("Recall (%)", color=col_recall, fontsize=11)
    ax1.tick_params(axis="y", labelcolor=col_recall)
    ax1.set_ylim(0, 100)
    ax1.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.0f%%"))

    # Annotate recall values
    for c_val, r in zip(contaminations, recalls):
        ax1.annotate(f"{r*100:.1f}%",
                     xy=(c_val, r * 100),
                     xytext=(4, 6), textcoords="offset points",
                     fontsize=8, color=col_recall)

    # Plot FPR on right axis
    ax2.plot(contaminations, [f * 100 for f in fprs],
             color=col_fpr, marker="s", linewidth=2, markersize=7,
             linestyle="--", label="False positive rate")
    ax2.set_ylabel("False Positive Rate (%)", color=col_fpr, fontsize=11)
    ax2.tick_params(axis="y", labelcolor=col_fpr)
    ax2.set_ylim(0, max(f * 100 for f in fprs) * 3 + 0.1)
    ax2.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f%%"))

    # Annotate FPR values
    for c_val, f in zip(contaminations, fprs):
        ax2.annotate(f"{f*100:.1f}%",
                     xy=(c_val, f * 100),
                     xytext=(4, -14), textcoords="offset points",
                     fontsize=8, color=col_fpr)

    # Vertical reference line at the chosen default
    if default_c in contaminations:
        ax1.axvline(x=default_c, color="grey", linestyle=":", linewidth=1.4,
                    label=f"Default (c={default_c})")

    ax1.set_xlabel("Isolation Forest contamination parameter", fontsize=11)
    ax1.set_title("Contamination sweep: recall vs. false positive rate\n"
                  "(Isolation Forest, 10-second windows, all 6 attack scenarios)",
                  fontsize=10)
    ax1.set_xticks(contaminations)
    ax1.set_xticklabels([str(c) for c in contaminations])

    # Merged legend from both axes
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2,
               loc="upper left", fontsize=8, framealpha=0.85)

    fig.tight_layout()
    os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, "contamination_sweep.png")
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Wrote {out_path}")

    # Print a compact table to stdout as well
    print("\nContamination sweep summary:")
    print(f"  {'c':>6}  {'Recall':>8}  {'FPR':>8}")
    for c_val, r, f in zip(contaminations, recalls, fprs):
        marker = " ← default" if c_val == default_c else ""
        print(f"  {c_val:>6.2f}  {r*100:>7.1f}%  {f*100:>7.1f}%{marker}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sweep-dir", default="results/sweep/",
                     help="directory containing eval_c_*.txt files")
    ap.add_argument("--outdir", default="results/plots/",
                     help="output directory for the figure")
    args = ap.parse_args()
    plot_sweep(args.sweep_dir, args.outdir)


if __name__ == "__main__":
    main()
