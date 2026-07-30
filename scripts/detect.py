"""
detect.py

Loads a trained model + scaler, scores feature rows extracted from
attack-period (or any test) traffic, and flags anomalies.

Usage:
    python3 detect.py --features data/attack/features_attack.csv \
        --model models/isoforest_model.joblib \
        --scaler models/scaler.joblib \
        --out results/detections.csv
"""

import argparse
import os

import joblib
import numpy as np
import pandas as pd


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--scaler", required=True)
    ap.add_argument("--feature-cols", default=None,
                     help="path to feature_cols.joblib saved by train_model.py; "
                          "defaults to a file named feature_cols.joblib next to --model")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    feature_cols_path = args.feature_cols or os.path.join(
        os.path.dirname(args.model), "feature_cols.joblib"
    )
    feature_cols = joblib.load(feature_cols_path)

    medians_path = os.path.join(os.path.dirname(args.model), "impute_medians.joblib")
    impute_medians = joblib.load(medians_path)

    df = pd.read_csv(args.features)
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Feature CSV missing columns: {missing}")

    X = df[feature_cols].copy()
    for col in feature_cols:
        if X[col].isna().any():
            X[col] = X[col].fillna(impute_medians[col])

    scaler = joblib.load(args.scaler)
    model = joblib.load(args.model)

    X_scaled = scaler.transform(X)

    # decision_function: higher = more normal, lower/negative = more anomalous
    # (this convention is shared by IsolationForest and OneClassSVM in sklearn)
    scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)  # 1 = normal (inlier), -1 = anomaly (outlier)

    out_df = df[["window_start", "device_mac"]].copy()
    out_df["anomaly_score"] = scores
    out_df["is_anomaly"] = (preds == -1)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out_df.to_csv(args.out, index=False)

    n_anom = out_df["is_anomaly"].sum()
    print(f"Scored {len(out_df)} rows. Flagged {n_anom} as anomalous "
          f"({n_anom / len(out_df):.1%}).")
    print(f"Wrote results to {args.out}")


if __name__ == "__main__":
    main()
