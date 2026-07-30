"""
train_model.py

Trains an Isolation Forest or One-Class SVM on BASELINE (normal-only) feature
data, and saves the fitted model + the feature scaler for later use in
detect.py.

Usage:
    python3 train_model.py --features data/baseline/features_baseline.csv \
        --algo isoforest --out models/
"""

import argparse
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

FEATURE_COLS = [
    "pkt_count", "byte_count", "mean_iat", "std_iat",
    "arp_req_count", "arp_req_rate", "arp_reply_count", "arp_reply_rate",
    "broadcast_ratio", "avg_response_latency", "send_recv_ratio",
]


def load_features(path, medians=None):
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Feature CSV is missing expected columns: {missing}")
    X = df[FEATURE_COLS].copy()
    computed_medians = {}
    for col in FEATURE_COLS:
        if medians is not None and col in medians:
            fill_value = medians[col]
        else:
            median = X[col].median()
            fill_value = median if not np.isnan(median) else 0.0
        computed_medians[col] = fill_value
        if X[col].isna().any():
            X[col] = X[col].fillna(fill_value)
    return df, X, computed_medians


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features", required=True, help="baseline features CSV")
    ap.add_argument("--algo", choices=["isoforest", "ocsvm"], default="isoforest")
    ap.add_argument("--out", required=True, help="output directory for model + scaler")
    ap.add_argument("--contamination", type=float, default=0.02,
                     help="expected fraction of outliers in baseline (isoforest only)")
    ap.add_argument("--nu", type=float, default=0.05,
                     help="nu parameter for One-Class SVM")
    args = ap.parse_args()

    _, X, medians = load_features(args.features)
    print(f"Loaded {len(X)} baseline feature rows, {X.shape[1]} features.")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    if args.algo == "isoforest":
        model = IsolationForest(
            n_estimators=200,
            contamination=args.contamination,
            random_state=42,
        )
    else:
        model = OneClassSVM(kernel="rbf", nu=args.nu, gamma="scale")

    model.fit(X_scaled)
    print(f"Trained {args.algo} on baseline data.")

    os.makedirs(args.out, exist_ok=True)
    model_path = os.path.join(args.out, f"{args.algo}_model.joblib")
    scaler_path = os.path.join(args.out, "scaler.joblib")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(FEATURE_COLS, os.path.join(args.out, "feature_cols.joblib"))
    joblib.dump(medians, os.path.join(args.out, "impute_medians.joblib"))

    print(f"Saved model to {model_path}")
    print(f"Saved scaler to {scaler_path}")


if __name__ == "__main__":
    main()
