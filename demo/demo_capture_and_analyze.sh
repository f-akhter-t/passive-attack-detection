#!/usr/bin/env bash
# demo_capture_and_analyze.sh
# Live demo runbook: captures traffic for DURATION seconds, then immediately
# extracts features and scores them against your ALREADY-TRAINED baseline
# model -- so anomaly flags appear right after the capture window, live,
# in front of the professor.
#
# Run this from the project root: /media/sf_shared_Kali/passive-attack-detection
#
# Usage: sudo bash demo_capture_and_analyze.sh [duration_seconds] [interface]
#   Defaults: 90s, eth0

DURATION=${1:-90}
IFACE=${2:-eth0}
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p demo/captures demo/results
PCAP_OUT="demo/captures/demo_live_${TS}.pcap"
FEAT_OUT="demo/captures/demo_live_${TS}_features.csv"
DET_OUT="demo/results/demo_live_${TS}_detections.csv"

echo "============================================================"
echo "  LIVE DEMO CAPTURE -- ${DURATION}s on interface ${IFACE}"
echo "  Make sure client-1, client-2, client-3, and server"
echo "  traffic generators are already running."
echo "============================================================"

echo "Attacker-Kali: $(hostname) / $(hostname -I | awk '{print $1}')"
for ip in 192.168.50.11 192.168.50.12 192.168.50.13 192.168.50.14; do
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo "  $ip: OK"
    else
        echo "  $ip: FAIL"
    fi
done
echo
echo "Capturing to $PCAP_OUT ..."
sudo timeout -k 5 "$DURATION" tcpdump -i "$IFACE" -w "$PCAP_OUT"
rc=$?

if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    echo "tcpdump failed with exit code $rc"
    exit "$rc"
fi

echo
echo "############################################################"
echo "# Capture done. Extracting features from the live capture ..."
echo "############################################################"
python3 scripts/extract_features.py --pcap "$PCAP_OUT" --window 10 --out "$FEAT_OUT"

echo
echo "############################################################"
echo "# Scoring against the trained baseline model ..."
echo "############################################################"
python3 scripts/detect.py \
    --features "$FEAT_OUT" \
    --model models/c08_fixed/isoforest_model.joblib \
    --scaler models/c08_fixed/scaler.joblib \
    --out "$DET_OUT"

echo
echo "############################################################"
echo "# Live detection results:"
echo "# IIUC CSE-4744 -- RaspberryPies [C223256 Riktika Talukder, C223261 Meheri Monir, C223265 Farhana Akhter Talukder]"
echo "############################################################"
python3 -c "
import pandas as pd

df = pd.read_csv('$DET_OUT')
df['window_start'] = pd.to_datetime(df['window_start'], unit='s')
df = df.sort_values(['window_start', 'device_mac'])

print(df.to_string(index=False))
print()

print('Devices seen:', ', '.join(sorted(df['device_mac'].dropna().unique())))

flagged = df[df['is_anomaly']]
print(f'{len(flagged)} of {len(df)} windows flagged as anomalous.')
"