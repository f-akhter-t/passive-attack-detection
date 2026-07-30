#!/usr/bin/env bash
# ============================================================================
# traffic_gen_client3.sh  (run on CLIENT-3, 192.168.50.13)
#
# Designed to generate RICHER traffic than client-1/2:
#   - Heavier HTTP downloads (wget of larger files served by VM5)
#   - scp file downloads from VM5 (large flows, bursty IAT)
#   - Ping bursts to multiple peers
#   - Lower idle rate (~10%) vs client-1/2 (~20%)
#
# This gives the 5-VM baseline more device-type diversity: the existing
# clients are medium-activity, this one is heavy-activity.
#
# Prerequisites on this VM:
#   - ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa  (run once before capture)
#   - ssh-copy-id kali@192.168.50.14             (run once before capture)
#   These let scp work without a password prompt during baseline capture.
#
# Usage: bash traffic_gen_client3.sh [duration_seconds] [server_ip] [peer_ip]
#   Defaults: 1800s (30 min), server=192.168.50.14, peer=192.168.50.11
# ============================================================================
DURATION=${1:-1800}
SERVER_IP=${2:-192.168.50.14}
PEER_IP=${3:-192.168.50.11}

echo "Starting http.server on port 8000 (for other clients to curl this VM) ..."
python3 -m http.server 8000 > /tmp/http_server_client3.log 2>&1 &
HTTP_PID=$!

cleanup() {
    echo "Stopping http.server (PID $HTTP_PID) ..."
    kill $HTTP_PID 2>/dev/null
    rm -f /tmp/scp_download_*
}
trap cleanup EXIT

echo "Client-3 traffic generator: ${DURATION}s | server=$SERVER_IP | peer=$PEER_IP"
echo "(HTTP + scp downloads + pings. Low idle rate for dense traffic profile.)"

END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    action=$((RANDOM % 10))
    case $action in
        0|1)
            # Ping burst to peer -- 5 to 20 packets
            n=$((RANDOM % 16 + 5))
            echo "[$(date +%T)] ping $PEER_IP x${n}"
            ping -c $n "$PEER_IP" > /dev/null 2>&1
            ;;
        2|3)
            # Ping burst to server
            n=$((RANDOM % 10 + 3))
            echo "[$(date +%T)] ping $SERVER_IP x${n}"
            ping -c $n "$SERVER_IP" > /dev/null 2>&1
            ;;
        4|5)
            # HTTP download from server (small file -- index listing)
            echo "[$(date +%T)] wget http://${SERVER_IP}:8080/small"
            wget -q -O /dev/null "http://${SERVER_IP}:8080/" 2>/dev/null || \
                curl -s "http://${SERVER_IP}:8080/" -o /dev/null 2>/dev/null
            ;;
        6|7)
            # HTTP download of a larger file from server
            echo "[$(date +%T)] wget http://${SERVER_IP}:8080/testfile.bin (large)"
            wget -q -O /dev/null "http://${SERVER_IP}:8080/testfile.bin" 2>/dev/null || \
                curl -s "http://${SERVER_IP}:8080/testfile.bin" -o /dev/null 2>/dev/null
            ;;
        8)
            # scp download from server (1MB file) -- creates large sustained flow
            tmpfile="/tmp/scp_download_$$"
            echo "[$(date +%T)] scp kali@${SERVER_IP}:/tmp/scp_testfile_1m.bin $tmpfile"
            scp -o StrictHostKeyChecking=no -o BatchMode=yes \
                "kali@${SERVER_IP}:/tmp/scp_testfile_1m.bin" "$tmpfile" > /dev/null 2>&1
            rm -f "$tmpfile"
            ;;
        9)
            # Short idle -- much less frequent than client-1/2 (~10% of windows)
            idle=$((RANDOM % 15 + 5))
            echo "[$(date +%T)] idle ${idle}s"
            sleep $idle
            ;;
    esac
    sleep $((RANDOM % 3 + 1))
done
echo "Done. Elapsed: ${SECONDS}s"
