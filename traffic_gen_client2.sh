#!/usr/bin/env bash
# ============================================================================
# traffic_gen_client2.sh
#
# Same as traffic_gen_client1.sh, but targets client-1 instead. Run this on
# client-2 at roughly the same time as client-1 runs its script, so traffic
# flows in both directions during the capture.
#
# Usage: bash traffic_gen_client2.sh [duration_seconds] [peer_ip]
#   Defaults: 1200s (20 min), peer 192.168.50.11 (client-1)
# ============================================================================
DURATION=${1:-1200}
PEER_IP=${2:-192.168.50.11}

echo "Starting http.server in background on port 8000 (for client-1's curl requests) ..."
python3 -m http.server 8000 > /tmp/http_server_client2.log 2>&1 &
HTTP_PID=$!
echo "  http.server PID: $HTTP_PID (will be killed when this script ends)"

cleanup() {
    echo "Stopping http.server (PID $HTTP_PID) ..."
    kill $HTTP_PID 2>/dev/null
}
trap cleanup EXIT

echo "Starting randomized traffic generation for ${DURATION}s against $PEER_IP ..."
END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    action=$((RANDOM % 3))
    case $action in
        0)
            n=$((RANDOM % 15 + 3))
            echo "[$(date +%T)] ping burst: $n packets"
            ping -c $n "$PEER_IP" > /dev/null
            ;;
        1)
            echo "[$(date +%T)] curl request to peer"
            curl -s "http://$PEER_IP:8000/" -o /dev/null
            ;;
        2)
            idle=$((RANDOM % 40 + 10))
            echo "[$(date +%T)] idle for ${idle}s"
            sleep $idle
            ;;
    esac
    sleep 1
done
echo "Done. Total elapsed: ${SECONDS}s"
