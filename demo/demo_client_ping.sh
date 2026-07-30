#!/usr/bin/env bash
# demo_client_ping.sh
# Purely cosmetic, visible ping traffic for the live demo -- lets the
# professor see real packets happening on screen while the monitor captures.
# Not randomized/hidden like traffic_gen_client*.sh; this is for visibility.
#
# Usage: bash demo_client_ping.sh <peer_ip>
#   client-1: bash demo_client_ping.sh 192.168.50.12
#   client-2: bash demo_client_ping.sh 192.168.50.11
# Stop with Ctrl+C when the demo capture window ends.

PEER_IP=${1:?"Usage: bash demo_client_ping.sh <peer_ip>"}

echo "============================================================"
echo "  LIVE DEMO TRAFFIC -- pinging $PEER_IP"
echo "  (this is the normal traffic the monitor VM is capturing)"
echo "# IIUC CSE-4744 -- RaspberryPies [C223256 Riktika Talukder, C223261 Meheri Monir, C223265 Farhana Akhter Talukder]"
echo "============================================================"
ping "$PEER_IP"