#!/usr/bin/env bash
# Network diagnostic script - runs until connection drops, then captures state

LOG_FILE="/tmp/network_diag_$(date +%Y%m%d_%H%M%S).log"
PING_TARGET="8.8.8.8"
PING_TIMEOUT=2
FAIL_THRESHOLD=3  # consecutive failures before capturing

echo "Logging to: $LOG_FILE"
echo "Monitoring network... Press Ctrl+C to stop"
echo "Will capture diagnostics after $FAIL_THRESHOLD consecutive ping failures"

consecutive_fails=0
captured=false

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

capture_state() {
    log "=== CAPTURING STATE AT FAILURE ==="

    log "--- IPFS swarm peers ---"
    ipfs swarm peers 2>/dev/null | wc -l >> "$LOG_FILE"

    log "--- IPFS stats ---"
    ipfs stats bw 2>/dev/null >> "$LOG_FILE"

    log "--- Connection counts ---"
    echo "TCP ESTABLISHED to port 4001: $(ss -tn state established '( sport = :4001 or dport = :4001 )' 2>/dev/null | wc -l)" >> "$LOG_FILE"
    echo "UDP connections to port 4001: $(ss -un '( sport = :4001 or dport = :4001 )' 2>/dev/null | wc -l)" >> "$LOG_FILE"
    echo "Total TCP ESTABLISHED: $(ss -tn state established 2>/dev/null | wc -l)" >> "$LOG_FILE"
    echo "Total connections (all states): $(ss -tan 2>/dev/null | wc -l)" >> "$LOG_FILE"

    log "--- conntrack table usage ---"
    if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
        echo "conntrack entries: $(cat /proc/sys/net/netfilter/nf_conntrack_count) / $(cat /proc/sys/net/netfilter/nf_conntrack_max)" >> "$LOG_FILE"
    fi

    log "--- DNS test ---"
    timeout 3 nslookup google.com >> "$LOG_FILE" 2>&1 || echo "DNS FAILED" >> "$LOG_FILE"

    log "--- Top connections by state ---"
    ss -tan 2>/dev/null | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn >> "$LOG_FILE"

    log "--- Network interfaces TX/RX errors ---"
    ip -s link show | grep -A2 "^[0-9]:" >> "$LOG_FILE"

    log "--- dmesg last 20 lines (network related) ---"
    dmesg | grep -iE "net|eth|wl|drop|reject|overflow" | tail -20 >> "$LOG_FILE"

    log "=== STATE CAPTURED ==="
}

# Continuous monitoring with periodic stats
stats_counter=0
while true; do
    if ping -c1 -W$PING_TIMEOUT $PING_TARGET >/dev/null 2>&1; then
        if [ $consecutive_fails -gt 0 ]; then
            log "Connection RESTORED after $consecutive_fails failures"
        fi
        consecutive_fails=0
        captured=false

        # Log stats every 30 iterations (~30 sec)
        stats_counter=$((stats_counter + 1))
        if [ $((stats_counter % 30)) -eq 0 ]; then
            tcp_4001=$(ss -tn state established '( sport = :4001 or dport = :4001 )' 2>/dev/null | wc -l)
            udp_4001=$(ss -un '( sport = :4001 or dport = :4001 )' 2>/dev/null | wc -l)
            conntrack=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "?")
            log "OK | TCP:$tcp_4001 UDP:$udp_4001 conntrack:$conntrack"
        fi
    else
        consecutive_fails=$((consecutive_fails + 1))
        log "PING FAIL #$consecutive_fails"

        if [ $consecutive_fails -ge $FAIL_THRESHOLD ] && [ "$captured" = false ]; then
            capture_state
            captured=true
            log "Diagnostics saved to $LOG_FILE"
        fi
    fi

    sleep 1
done
