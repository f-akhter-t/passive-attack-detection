"""
feature_importance.py

Answers: "which features are actually driving detection?" via permutation
importance -- for each feature, shuffle it across rows and measure how much
the model's ability to separate attack-vs-normal windows degrades (AUC drop).
A bigger drop = that feature matters more.

This treats detection as a labeled binary problem for EVALUATION PURPOSES
ONLY (ground truth from attack_log.csv) -- the model itself is still trained
unsupervised, only on baseline data, exactly as your proposal specifies.
This script just measures feature importance against known outcomes; it does
not change how the model is trained.

Usage:
    python3 feature_importance.py \
        --features data/attack/features_attack.csv \
        --attack-log data/attack/attack_log.csv \
        --model models/c08_fixed/isoforest_model.joblib \
        --scaler models/c08_fixed/scaler.joblib \
        --feature-cols models/c08_fixed/feature_cols.joblib \
        --out results/feature_importance.txt \
        --tz America/New_York
"""

import argparse
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score


def permutation_importance_manual(model, X, y_true, feature_names, n_repeats=30, seed=42):
    """Manual permutation importance: for each feature, shuffle that column
    across rows (breaking its relationship to the outcome while preserving
    its marginal distribution), recompute the model's anomaly scores, and
    measure how much AUC (attack vs normal separation) drops relative to the
    unshuffled baseline. Repeated n_repeats times per feature and averaged,
    since a single shuffle is noisy.

    Implemented directly (rather than via sklearn's permutation_importance)
    to avoid that function's classifier/regressor tagging requirements,
    which vary across scikit-learn versions and don't cleanly fit an
    unsupervised anomaly model being scored against post-hoc ground truth.
    """
    rng = np.random.default_rng(seed)
    baseline_scores = -model.decision_function(X)  # higher = more anomalous
    baseline_auc = roc_auc_score(y_true, baseline_scores)

    means = []
    stds = []
    for i in range(X.shape[1]):
        drops = []
        for _ in range(n_repeats):
            X_perm = X.copy()
            perm_idx = rng.permutation(X.shape[0])
            X_perm[:, i] = X_perm[perm_idx, i]
            scores = -model.decision_function(X_perm)
            auc = roc_auc_score(y_true, scores)
            drops.append(baseline_auc - auc)
        means.append(np.mean(drops))
        stds.append(np.std(drops))

    return baseline_auc, np.array(means), np.array(stds)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features", required=True, help="attack-period features CSV")
    ap.add_argument("--attack-log", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--scaler", required=True)
    ap.add_argument("--feature-cols", required=True,
                     help="feature_cols.joblib saved alongside --model")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tz", default="America/New_York")
    ap.add_argument("--n-repeats", type=int, default=30,
                     help="number of shuffles per feature (more = more stable estimate)")
    args = ap.parse_args()

    feature_cols = joblib.load(args.feature_cols)
    scaler = joblib.load(args.scaler)
    model = joblib.load(args.model)

    medians_path = os.path.join(os.path.dirname(args.model), "impute_medians.joblib")
    impute_medians = joblib.load(medians_path)

    df = pd.read_csv(args.features)
    X = df[feature_cols].copy()
    for col in feature_cols:
        if X[col].isna().any():
            X[col] = X[col].fillna(impute_medians[col])
    X_scaled = scaler.transform(X)

    # Build ground-truth labels the same way evaluate.py does: convert
    # epoch window_start to the local tz used in attack_log.csv, then check
    # whether each row falls inside any logged attack window.
    window_start = (
        pd.to_datetime(df["window_start"], unit="s", utc=True)
        .dt.tz_convert(args.tz)
        .dt.tz_localize(None)
    )
    log = pd.read_csv(args.attack_log, parse_dates=["start_time", "end_time"])

    def in_any_attack(ts):
        return ((log["start_time"] <= ts) & (ts <= log["end_time"])).any()

    y_true = window_start.apply(in_any_attack).astype(int).values

    if y_true.sum() == 0 or y_true.sum() == len(y_true):
        raise ValueError(
            "Ground truth is all-one-class (all attack or all normal) -- "
            "cannot compute AUC-based importance. Check --attack-log/--tz."
        )

    baseline_auc, means, stds = permutation_importance_manual(
        model, X_scaled, y_true, feature_cols, n_repeats=args.n_repeats, seed=42
    )

    order = np.argsort(means)[::-1]

    lines = []
    lines.append("=== Feature Importance (permutation, AUC-drop) ===\n")
    lines.append(f"Baseline AUC (attack vs normal, using model's raw anomaly score): {baseline_auc:.4f}\n")
    lines.append("Higher 'AUC drop' = shuffling this feature hurts detection more = feature matters more.\n")
    lines.append(f"{'feature':24s}  {'AUC drop (mean)':>16s}  {'std':>8s}")
    for i in order:
        lines.append(
            f"{feature_cols[i]:24s}  {means[i]:16.4f}  {stds[i]:8.4f}"
        )

    report = "\n".join(lines)
    print(report)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(report + "\n")
    print(f"\nWrote report to {args.out}")


if __name__ == "__main__":
    main()
