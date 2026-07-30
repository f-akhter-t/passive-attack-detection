#!/usr/bin/env bash
# ============================================================================
# baseline_rebuild_procedure.sh   (run on ATTACKER-KALI)
#
# Orchestrates the 5-VM baseline capture. Run this AFTER setting up VM4
# (client-3, 192.168.50.13) and VM5 (server, 192.168.50.14) per the
# VM_SETUP_INSTRUCTIONS.md, and AFTER all five traffic generators are
# already running on their respective VMs.
#
# What this script does:
#   1. Backs up the old baseline pcap and extracted features
#   2. Captures 25 minutes of LAN traffic (all 5 VMs active)
#   3. Copies the new pcap to data/baseline/baseline_long.pcap
#   4. Re-runs the full pipeline (feature extraction → training → evaluation)
#
# HOW TO START THE TRAFFIC GENERATORS BEFORE RUNNING THIS:
#
#   On CLIENT-1 (192.168.50.11) -- ssh or open terminal:
#     bash traffic_gen_client1.sh 1800 192.168.50.12
#
#   On CLIENT-2 (192.168.50.12):
#     bash traffic_gen_client2.sh 1800 192.168.50.11
#
#   On CLIENT-3 VM4 (192.168.50.13):
#     bash traffic_gen_client3.sh 1800 192.168.50.14 192.168.50.11
#
#   On SERVER VM5 (192.168.50.14):
#     bash traffic_gen_server.sh 1800 192.168.50.11 192.168.50.13
#
#   Then immediately run THIS script on attacker-kali. The 1800s (30 min)
#   duration is longer than the 1500s capture below, so traffic generators
#   are still running when the capture ends.
#
# Usage: bash baseline_rebuild_procedure.sh [capture_duration_seconds] [interface]
#   Defaults: 1500s (25 min), eth0
# ============================================================================
set -e

DURATION=${1:-1500}
IFACE=${2:-eth0}
SHARE_DIR="/media/sf_shared_Kali/passive-attack-detection"
NEW_PCAP="/tmp/baseline_5vm_$(date +%Y%m%d_%H%M%S).pcap"

echo "============================================================"
echo "  5-VM BASELINE REBUILD"
echo "  Duration: ${DURATION}s (~$(( DURATION / 60 )) min) on $IFACE"
echo "  CONFIRM: All 5 traffic generators are running on their VMs."
echo "  Press ENTER to start capture, or Ctrl+C to abort."
echo "============================================================"
read -r

# Step 1: Confirm all expected devices are reachable
echo "Pinging all VMs to confirm they are on the network ..."
for ip in 192.168.50.11 192.168.50.12 192.168.50.13 192.168.50.14; do
    if ping -c 2 -W 2 "$ip" > /dev/null 2>&1; then
        echo "  $ip: OK"
    else
        echo "  WARNING: $ip did not respond. Continue anyway? (Ctrl+C to abort)"
        read -r
    fi
done
echo ""

# Step 2: Back up old baseline
echo "Backing up old baseline ..."
TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${SHARE_DIR}/baseline_backup_${TS}"
mkdir -p "$BACKUP_DIR"
cp "${SHARE_DIR}/data/baseline/baseline_long.pcap" \
   "${BACKUP_DIR}/baseline_long_OLD.pcap" 2>/dev/null && \
   echo "  Old pcap backed up to $BACKUP_DIR" || echo "  No old pcap to back up."
cp "${SHARE_DIR}/data/baseline/features_baseline.csv" \
   "${BACKUP_DIR}/features_baseline_OLD.csv" 2>/dev/null || true
cp "${SHARE_DIR}/data/baseline/features_baseline_w5.csv" \
   "${BACKUP_DIR}/features_baseline_w5_OLD.csv" 2>/dev/null || true
echo "  Old models backed up (run_full_pipeline.sh will also make a results_backup_*)."
echo ""

# Step 3: Capture
echo "Starting ${DURATION}s capture on $IFACE ..."
echo "  Traffic generators should already be running. Let them run now."
echo "  Capture will end automatically."
CAPTURE_RC=0

sudo timeout -k 10 "$DURATION" \
    tcpdump -i "$IFACE" -w "$NEW_PCAP" < /dev/null || CAPTURE_RC=$?

# timeout exits with 124 when the timeout expires normally.
# Treat that as a successful capture.
if [ "$CAPTURE_RC" -ne 0 ] && [ "$CAPTURE_RC" -ne 124 ]; then
    echo "ERROR: tcpdump failed (exit code $CAPTURE_RC)"
    exit "$CAPTURE_RC"
fi
echo ""
echo "Capture complete. File: $NEW_PCAP"
SIZE=$(du -sh "$NEW_PCAP" | cut -f1)
echo "  Size: $SIZE"
echo ""

# Step 4: Copy to project
echo "Copying new pcap to data/baseline/baseline_long.pcap ..."
sudo cp "$NEW_PCAP" "${SHARE_DIR}/data/baseline/baseline_long.pcap"
sudo chmod 644 "${SHARE_DIR}/data/baseline/baseline_long.pcap"
echo "  Done."
echo ""

# Step 5: Sanity check -- how many unique MACs are in the new pcap?
echo "Sanity check: unique source MACs in new pcap ..."
sudo tcpdump -r "$NEW_PCAP" -e -l 2>/dev/null | \
    awk '{for(i=1;i<=NF;i++) if($i=="SA:"){print $(i+1)}}' 2>/dev/null | \
    sort -u | head -20 || \
    echo "  (tcpdump MAC listing requires root -- skipping; pipeline will show MACs)"
echo ""

# Step 6: Run the pipeline
echo "============================================================"
echo "  Running run_full_pipeline.sh on new 5-VM baseline ..."
echo "============================================================"
cd "$SHARE_DIR"
bash run_full_pipeline.sh

echo ""
echo "============================================================"
echo "  BASELINE REBUILD COMPLETE."
echo "  Old files are in: $BACKUP_DIR"
echo "  New baseline pcap: data/baseline/baseline_long.pcap  ($SIZE)"
echo "  Check results/evaluation_fixed_c08.txt for updated metrics."
echo "============================================================"
