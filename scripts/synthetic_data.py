"""
synthetic_data.py

Generates synthetic feature CSVs (same schema as extract_features.py's
output) plus a matching attack_log.csv, so you can test train_model.py,
detect.py, evaluate.py, and plot_results.py end-to-end BEFORE you have real
VM captures. This is for pipeline validation only -- it is not a substitute
for real traffic in your final report/results.

Usage:
    python3 synthetic_data.py --out data/
"""

import argparse
import os
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

DEVICES = [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(1, 5)]


def gen_normal_row(t, mac):
    return dict(
        window_start=t,
        device_mac=mac,
        pkt_count=max(0, int(RNG.normal(50, 10))),
        byte_count=max(0, int(RNG.normal(6000, 1500))),
        mean_iat=abs(RNG.normal(0.2, 0.05)),
        std_iat=abs(RNG.normal(0.05, 0.02)),
        arp_req_count=max(0, int(RNG.poisson(1))),
        arp_req_rate=abs(RNG.normal(0.1, 0.05)),
        arp_reply_count=0,
        arp_reply_rate=0.0,
        broadcast_ratio=abs(RNG.normal(0.05, 0.02)),
        avg_response_latency=abs(RNG.normal(0.01, 0.003)),
        send_recv_ratio=abs(RNG.normal(1.0, 0.2)),
    )


def gen_attack_row(t, mac, tool):
    # Simulate passive-sniffing side effects: more ARP activity, timing
    # irregularity, and skewed send/recv ratio (sniffer mostly receives).
    row = gen_normal_row(t, mac)
    row["arp_req_count"] = max(0, int(RNG.poisson(8)))
    row["arp_req_rate"] = abs(RNG.normal(0.9, 0.2))
    # Simulate ettercap-style unsolicited ARP replies (op==2) -- the primary
    # spoofing signal that the real pipeline now captures via arp_reply_count/rate.
    row["arp_reply_count"] = max(0, int(RNG.poisson(6)))
    row["arp_reply_rate"] = abs(RNG.normal(0.6, 0.15))
    row["std_iat"] = abs(RNG.normal(0.25, 0.05))
    row["broadcast_ratio"] = abs(RNG.normal(0.3, 0.05))
    row["send_recv_ratio"] = abs(RNG.normal(0.15, 0.05))
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="data/ directory (baseline/ and attack/ created inside)")
    ap.add_argument("--window", type=float, default=10.0)
    args = ap.parse_args()

    baseline_dir = os.path.join(args.out, "baseline")
    attack_dir = os.path.join(args.out, "attack")
    os.makedirs(baseline_dir, exist_ok=True)
    os.makedirs(attack_dir, exist_ok=True)

    # --- Baseline: 20 minutes of normal traffic ---
    t0 = datetime(2026, 7, 20, 13, 0, 0)
    n_windows = int(20 * 60 / args.window)
    rows = []
    for i in range(n_windows):
        t = t0 + timedelta(seconds=i * args.window)
        for mac in DEVICES:
            rows.append(gen_normal_row(t, mac))
    baseline_df = pd.DataFrame(rows)
    baseline_path = os.path.join(baseline_dir, "features_baseline_synthetic.csv")
    baseline_df.to_csv(baseline_path, index=False)
    print(f"Wrote {len(baseline_df)} synthetic baseline rows to {baseline_path}")

    # --- Attack period: 30 minutes, with 3 tool windows + normal gaps ---
    t1 = datetime(2026, 7, 20, 14, 0, 0)
    tools = [
        ("wireshark", t1 + timedelta(minutes=2), t1 + timedelta(minutes=7)),
        ("ettercap", t1 + timedelta(minutes=10), t1 + timedelta(minutes=16)),
        ("bettercap", t1 + timedelta(minutes=20), t1 + timedelta(minutes=25)),
    ]
    attacker_mac = DEVICES[0]  # pretend device 0 is the sniffer for this demo

    n_windows = int(30 * 60 / args.window)
    rows = []
    for i in range(n_windows):
        t = t1 + timedelta(seconds=i * args.window)
        active_tool = None
        for tool, start, end in tools:
            if start <= t <= end:
                active_tool = tool
                break
        for mac in DEVICES:
            if mac == attacker_mac and active_tool is not None:
                rows.append(gen_attack_row(t, mac, active_tool))
            else:
                rows.append(gen_normal_row(t, mac))
    attack_df = pd.DataFrame(rows)
    attack_path = os.path.join(attack_dir, "features_attack_synthetic.csv")
    attack_df.to_csv(attack_path, index=False)
    print(f"Wrote {len(attack_df)} synthetic attack-period rows to {attack_path}")

    log_df = pd.DataFrame(
        [{"tool": t, "start_time": s, "end_time": e} for t, s, e in tools]
    )
    log_path = os.path.join(attack_dir, "attack_log.csv")
    log_df.to_csv(log_path, index=False)
    print(f"Wrote synthetic attack log to {log_path}")

    print("\nTry the pipeline now with, e.g.:")
    print(f"  python3 scripts/train_model.py --features {baseline_path} --algo isoforest --out models/")
    print(f"  python3 scripts/detect.py --features {attack_path} --model models/isoforest_model.joblib "
          f"--scaler models/scaler.joblib --out results/detections.csv")
    print(f"  python3 scripts/evaluate.py --detections results/detections.csv --attack-log {log_path} "
          f"--out results/evaluation_report.txt")


if __name__ == "__main__":
    main()
