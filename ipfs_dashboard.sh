#!/usr/bin/env bash
# IPFS Dashboard - shows peers, bandwidth, and connections
export IPFS_PATH=/var/lib/ipfs

while true; do
    clear
    echo "=== IPFS Dashboard === $(date '+%H:%M:%S')"
    echo ""

    # Bandwidth stats
    echo "--- Bandwidth ---"
    sudo IPFS_PATH=$IPFS_PATH ipfs stats bw 2>/dev/null | head -5 || echo "IPFS not responding"
    echo ""

    # Peer count and list
    PEERS=$(sudo IPFS_PATH=$IPFS_PATH ipfs swarm peers 2>/dev/null)
    PEER_COUNT=$(echo "$PEERS" | grep -c . || echo 0)
    echo "--- Peers: $PEER_COUNT ---"
    echo "$PEERS" | head -10
    [ "$PEER_COUNT" -gt 10 ] && echo "... and $((PEER_COUNT - 10)) more"
    echo ""

    # TCP connections on port 4001
    CONNS=$(ss -tn | grep :4001 | wc -l)
    SYN=$(ss -tan state syn-sent | grep :4001 | wc -l)
    echo "--- Connections ---"
    echo "TCP on 4001: $CONNS"
    echo "SYN-SENT: $SYN"
    echo ""

    # Peerix status
    echo "--- Peerix ---"
    curl -s http://127.0.0.1:12304/scan-status 2>/dev/null | jq -r '"Scan: \(.percent // 0)% | Published: \(.published // 0) | From tracker: \(.from_tracker // 0)"' 2>/dev/null || echo "Not responding"

    sleep 2
done
