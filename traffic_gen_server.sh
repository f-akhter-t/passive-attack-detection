#!/usr/bin/env bash
# ============================================================================
# traffic_gen_server.sh  (run on SERVER VM, 192.168.50.14)
#
# The server VM has a distinct behavioral fingerprint from client VMs:
#   - Primarily RECEIVES requests (small ARP + TCP SYN) and SENDS large responses
#   - High byte_count (serving files), high send_recv_ratio
#   - Low arp_req_count (ARP tables stay cached when serving consistently)
#   - Low idle rate (~5%) because the HTTP server runs continuously
#
# Also sends occasional pings to other VMs (keep the server "alive" on the
# network so extract_features.py sees it as an active device throughout).
#
# Prerequisites (run ONCE before starting baseline capture):
#   bash setup_server_files.sh
#   (creates the test files this server will serve)
#
# Usage: bash traffic_gen_server.sh [duration_seconds] [peer1_ip] [peer2_ip]
#   Defaults: 1800s, peer1=192.168.50.11, peer2=192.168.50.13
# ============================================================================
DURATION=${1:-1800}
PEER1=${2:-192.168.50.11}
PEER2=${3:-192.168.50.13}

# ---- Create test files if not already present ----
if [ ! -f /tmp/scp_testfile_1m.bin ]; then
    echo "Creating 1MB test file for scp (/tmp/scp_testfile_1m.bin) ..."
    dd if=/dev/urandom of=/tmp/scp_testfile_1m.bin bs=1M count=1 2>/dev/null
fi
if [ ! -f /tmp/http_serve/testfile.bin ]; then
    mkdir -p /tmp/http_serve
    echo "Creating 256KB HTTP test file (/tmp/http_serve/testfile.bin) ..."
    dd if=/dev/urandom of=/tmp/http_serve/testfile.bin bs=256K count=1 2>/dev/null
    # Also create a small listing page
    echo "<html><body><a href='testfile.bin'>testfile.bin (256KB)</a></body></html>" \
        > /tmp/http_serve/index.html
fi

# ---- Start HTTP server serving the test files ----
echo "Starting HTTP server on port 8080 (serving /tmp/http_serve/) ..."
cd /tmp/http_serve && python3 -m http.server 8080 > /tmp/http_server_vm5.log 2>&1 &
HTTP_PID=$!
cd - > /dev/null

# ---- Ensure SSH/sshd is running for scp from client-3 ----
if ! pgrep -x sshd > /dev/null 2>&1; then
    echo "Starting sshd ..."
    sudo service ssh start 2>/dev/null || sudo /usr/sbin/sshd 2>/dev/null
fi

cleanup() {
    echo "Stopping HTTP server (PID $HTTP_PID) ..."
    kill $HTTP_PID 2>/dev/null
}
trap cleanup EXIT

echo "Server traffic generator: ${DURATION}s | sending occasional pings to $PEER1, $PEER2"
echo "(HTTP server active on port 8080. sshd active for scp. Primarily passive.)"

END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    action=$((RANDOM % 10))
    case $action in
        0|1)
            # Ping peer1
            n=$((RANDOM % 8 + 3))
            echo "[$(date +%T)] ping $PEER1 x${n}"
            ping -c $n "$PEER1" > /dev/null 2>&1
            ;;
        2)
            # Ping peer2
            n=$((RANDOM % 8 + 3))
            echo "[$(date +%T)] ping $PEER2 x${n}"
            ping -c $n "$PEER2" > /dev/null 2>&1
            ;;
        3|4)
            # Curl something from peer1's HTTP server (bidirectional traffic)
            echo "[$(date +%T)] curl http://${PEER1}:8000/"
            curl -s "http://${PEER1}:8000/" -o /dev/null 2>/dev/null
            ;;
        5)
            # Short idle (very infrequent -- server is usually busy serving)
            idle=$((RANDOM % 10 + 3))
            echo "[$(date +%T)] idle ${idle}s"
            sleep $idle
            ;;
        6|7|8|9)
            # Server is mostly passive -- just wait while HTTP server handles requests
            # Sleep briefly before next proactive action
            sleep $((RANDOM % 5 + 2))
            ;;
    esac
    sleep 1
done
echo "Done. Elapsed: ${SECONDS}s"
