#!/usr/bin/env bash
LOG="/tmp/flood_monitor.log"
echo "=== Starting flood monitor at $(date) ===" >> $LOG

while true; do
    TS=$(date '+%H:%M:%S')
    SYN=$(ss -tan state syn-sent 2>/dev/null | wc -l)
    PEERS=$(ipfs swarm peers 2>/dev/null | wc -l)
    PING=$(ping -c1 -W1 8.8.8.8 2>/dev/null && echo "OK" || echo "FAIL")
    echo "$TS | SYN:$SYN PEERS:$PEERS PING:$PING" >> $LOG
    
    # If flood detected, capture state
    if [ "$SYN" -gt 50 ]; then
        echo "$TS | FLOOD DETECTED - capturing state" >> $LOG
        ss -tan state syn-sent >> $LOG 2>/dev/null
    fi
    
    sleep 2
done
