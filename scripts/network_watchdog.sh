#!/usr/bin/env bash
# Network watchdog - stops IPFS/peerix if network becomes unresponsive
# Checks sophronesis.dev every second, stops services after 3 consecutive failures

FAILURES=0
MAX_FAILURES=5

echo "Network watchdog started. Monitoring sophronesis.dev..."
echo "Will stop IPFS/peerix after $MAX_FAILURES consecutive failures."

while true; do
    if curl -s --max-time 1 -o /dev/null https://sophronesis.dev; then
        if [ $FAILURES -gt 0 ]; then
            echo "$(date '+%H:%M:%S') OK (recovered after $FAILURES failures)"
        fi
        FAILURES=0
    else
        FAILURES=$((FAILURES + 1))
        echo "$(date '+%H:%M:%S') FAIL ($FAILURES/$MAX_FAILURES)"

        if [ $FAILURES -ge $MAX_FAILURES ]; then
            echo "$(date '+%H:%M:%S') !!! Network unresponsive - stopping IPFS/peerix !!!"
            sudo systemctl stop ipfs ipfs-api.socket ipfs-gateway.socket peerix
            notify-send -u critical "Network Watchdog" "IPFS/peerix killed - network unresponsive"
            echo "$(date '+%H:%M:%S') Services stopped."
            #exit 1
        fi
    fi

    sleep 1
done
