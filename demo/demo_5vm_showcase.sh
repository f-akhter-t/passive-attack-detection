#!/usr/bin/env bash
set -euo pipefail

DURATION=${1:-90}
IFACE=${2:-eth0}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP_DIR="$ROOT/demo/captures"
RES_DIR="$ROOT/demo/results"
MODEL_DIR="$ROOT/models/c08_fixed"

TS=$(date +%Y%m%d_%H%M%S)
PCAP="$CAP_DIR/showcase_${TS}.pcap"
FEATURES="$CAP_DIR/showcase_${TS}_features.csv"
DETECTIONS="$RES_DIR/showcase_${TS}_detections.csv"

mkdir -p "$CAP_DIR" "$RES_DIR"

echo "============================================================"
echo "  5-VM LIVE DEMO SHOWCASE"
echo "  Attacker-Kali: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "  Internal VMs:"
for ip in 192.168.50.11 192.168.50.12 192.168.50.13 192.168.50.14; do
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo "    $ip  [reachable]"
    else
        echo "    $ip  [NOT REACHABLE]"
    fi
done
echo "============================================================"
echo
echo "Start these on the other VMs before continuing:"
echo "  Client-1 : bash traffic_gen_client1.sh 1800 192.168.50.12"
echo "  Client-2 : bash traffic_gen_client2.sh 1800 192.168.50.11"
echo "  Client-3 : bash traffic_gen_client3.sh 1800 192.168.50.14 192.168.50.11"
echo "  Server   : bash traffic_gen_server.sh 1800 192.168.50.11 192.168.50.13"
echo
read -r -p "Press ENTER once all four generators are running..."

echo
echo "Capturing live 5-VM traffic for ${DURATION}s on ${IFACE} ..."
sudo timeout -k 5 "$DURATION" tcpdump -i "$IFACE" -w "$PCAP"

echo
echo "Extracting features ..."
python3 "$ROOT/scripts/extract_features.py" --pcap "$PCAP" --window 10 --out "$FEATURES"

echo
echo "Scoring against the trained baseline model ..."
python3 "$ROOT/scripts/detect.py" \
    --features "$FEATURES" \
    --model "$MODEL_DIR/isoforest_model.joblib" \
    --scaler "$MODEL_DIR/scaler.joblib" \
    --out "$DETECTIONS"

echo
echo "Live detection preview:"
python3 - <<PY
import pandas as pd
df = pd.read_csv("$DETECTIONS")
df["window_start"] = pd.to_datetime(df["window_start"], unit="s")
print(df.sort_values(["window_start", "device_mac"]).head(25).to_string(index=False))
print()
print(f"Unique devices seen: {df['device_mac'].nunique()}")
print(f"Flagged windows: {int(df['is_anomaly'].sum())} / {len(df)}")
PY

echo
echo "Done."