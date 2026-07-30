#!/usr/bin/env bash
# ============================================================================
# client_traffic_for_evasion_tests.sh   (run on client-1)
#
# Continuous ping traffic for the FULL duration of
# evasion_and_passive_tool_tests.sh on attacker-kali (~3 segments x 90s +
# 2 gaps x 30s = ~330s). Defaults to 420s (7 min) for margin -- if
# attacker-kali's script finishes first, just Ctrl+C this one.
#
# Usage: bash client_traffic_for_evasion_tests.sh [duration_seconds] [peer_ip]
# ============================================================================
DURATION=${1:-420}
PEER_IP=${2:-192.168.50.12}

echo "Generating continuous ping traffic against $PEER_IP for up to ${DURATION}s ..."
echo "(Safe to Ctrl+C early once attacker-kali's script prints 'ALL SEGMENTS DONE')"
END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    ping -c 5 "$PEER_IP" > /dev/null
    sleep 1
done
echo "Done. Total elapsed: ${SECONDS}s"
