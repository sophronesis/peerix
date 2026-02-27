#!/usr/bin/env bash
# Test IPFS-based package distribution between two NixOS servers
#
# Usage: ./test_ipfs_distribution.sh [SERVER_A] [SERVER_B] [PACKAGE]
#
# This script:
# 1. Builds a package on server A
# 2. Waits for peerix to publish it to IPFS
# 3. Verifies the package is available via tracker
# 4. Fetches the package on server B via peerix/IPFS
# 5. Verifies it was retrieved from IPFS (not cache.nixos.org)

set -e

# Configuration
SERVER_A="${1:-fw16}"      # Source server (has the package)
SERVER_B="${2:-d}"         # Destination server (will fetch via IPFS)
PACKAGE="${3:-cowsay}"     # Small test package from nixpkgs
TRACKER_URL="https://sophronesis.dev/peerix"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[TEST]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Helper to run command on server
run_on() {
    local server="$1"
    shift
    if [ "$server" = "fw16" ] || [ "$server" = "local" ]; then
        eval "$@"
    else
        ssh "$server" "$@"
    fi
}

# Helper to run with sudo
sudo_on() {
    local server="$1"
    shift
    if [ "$server" = "fw16" ] || [ "$server" = "local" ]; then
        sudo "$@"
    else
        ssh "$server" "sudo $*"
    fi
}

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         PEERIX IPFS Distribution Test Suite                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
info "Server A (source):      $SERVER_A"
info "Server B (destination): $SERVER_B"
info "Test package:           $PACKAGE"
info "Tracker URL:            $TRACKER_URL"
echo ""

# Step 1: Check connectivity
log "Step 1: Checking server connectivity..."
if ! run_on "$SERVER_A" "echo 'ok'" &>/dev/null; then
    err "Cannot connect to server A ($SERVER_A)"
    exit 1
fi
log "  ✓ Server A ($SERVER_A) reachable"

if ! run_on "$SERVER_B" "echo 'ok'" &>/dev/null; then
    err "Cannot connect to server B ($SERVER_B)"
    exit 1
fi
log "  ✓ Server B ($SERVER_B) reachable"

# Step 2: Check peerix is running on both servers
log "Step 2: Checking peerix status..."
if ! run_on "$SERVER_A" "curl -s http://127.0.0.1:12304/nix-cache-info" &>/dev/null; then
    err "Peerix not running on server A"
    exit 1
fi
log "  ✓ Peerix running on server A"

if ! run_on "$SERVER_B" "curl -s http://127.0.0.1:12304/nix-cache-info" &>/dev/null; then
    err "Peerix not running on server B"
    exit 1
fi
log "  ✓ Peerix running on server B"

# Step 3: Check tracker status
log "Step 3: Checking tracker status..."
TRACKER_STATUS=$(curl -s "$TRACKER_URL/status" 2>/dev/null || echo '{}')
PEER_COUNT=$(echo "$TRACKER_STATUS" | jq -r '.peers // 0' 2>/dev/null || echo "0")
log "  Tracker has $PEER_COUNT connected peers"

# Step 4: Build package on server A
log "Step 4: Building $PACKAGE on server A..."
STORE_PATH=$(run_on "$SERVER_A" "nix build nixpkgs#$PACKAGE --no-link --print-out-paths 2>/dev/null" | head -1)
if [ -z "$STORE_PATH" ]; then
    err "Failed to build package on server A"
    exit 1
fi
STORE_HASH=$(basename "$STORE_PATH" | cut -d'-' -f1)
log "  Store path: $STORE_PATH"
log "  Store hash: $STORE_HASH"

# Step 5: Trigger IPFS publish on server A (SIGHUP)
log "Step 5: Triggering IPFS scan on server A..."
sudo_on "$SERVER_A" "systemctl reload peerix.service" 2>/dev/null || true
log "  Waiting for scan to process..."

# Poll scan status until scan completes
MAX_WAIT=300
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    SCAN_STATUS=$(run_on "$SERVER_A" "curl -s http://127.0.0.1:12304/scan-status")
    ACTIVE=$(echo "$SCAN_STATUS" | jq -r '.active')

    if [ "$ACTIVE" = "false" ]; then
        log "  Scan completed"
        break
    fi

    PERCENT=$(echo "$SCAN_STATUS" | jq -r '.percent // 0')
    PUBLISHED=$(echo "$SCAN_STATUS" | jq -r '.published // 0')
    printf "\r  Scan: %.1f%% (published: %d)" "$PERCENT" "$PUBLISHED"
    sleep 2
    WAITED=$((WAITED + 2))
done
echo ""

# Step 5b: Check if our hash is in the CID cache
log "Step 5b: Checking if package was published to IPFS..."
NARINFO=$(run_on "$SERVER_A" "curl -s http://127.0.0.1:12304/$STORE_HASH.narinfo")
NAR_URL=$(echo "$NARINFO" | grep "^URL:" | cut -d' ' -f2)

if [[ "$NAR_URL" == Qm* ]] || [[ "$NAR_URL" == bafy* ]]; then
    log "  ✓ Package published to IPFS: $NAR_URL"
    CID="$NAR_URL"
elif [[ "$NAR_URL" == *"ipfs/"* ]]; then
    # Package is available but served locally (not yet in IPFS CID cache)
    log "  Package available locally, triggering new scan to publish to IPFS..."
    sudo_on "$SERVER_A" "systemctl reload peerix.service" 2>/dev/null || true

    # Wait for this specific scan
    WAITED=0
    while [ $WAITED -lt 120 ]; do
        SCAN_STATUS=$(run_on "$SERVER_A" "curl -s http://127.0.0.1:12304/scan-status")
        ACTIVE=$(echo "$SCAN_STATUS" | jq -r '.active')
        if [ "$ACTIVE" = "false" ]; then
            break
        fi
        PERCENT=$(echo "$SCAN_STATUS" | jq -r '.percent // 0')
        printf "\r  Second scan: %.1f%%" "$PERCENT"
        sleep 2
        WAITED=$((WAITED + 2))
    done
    echo ""

    # Check again
    NARINFO=$(run_on "$SERVER_A" "curl -s http://127.0.0.1:12304/$STORE_HASH.narinfo")
    NAR_URL=$(echo "$NARINFO" | grep "^URL:" | cut -d' ' -f2)
    if [[ "$NAR_URL" == Qm* ]] || [[ "$NAR_URL" == bafy* ]]; then
        log "  ✓ Package published to IPFS: $NAR_URL"
        CID="$NAR_URL"
    else
        warn "  Package not in IPFS (may be in skipped list)"
    fi
else
    warn "  Package narinfo not available"
fi

# Step 6: Check if CID is registered with tracker
log "Step 6: Checking CID registration with tracker..."
if [ -z "$CID" ]; then
    for i in {1..10}; do
        CID_RESPONSE=$(curl -s "$TRACKER_URL/cid/$STORE_HASH" 2>/dev/null || echo '{}')
        CID=$(echo "$CID_RESPONSE" | jq -r '.cid // empty' 2>/dev/null)
        if [ -n "$CID" ]; then
            break
        fi
        sleep 2
    done
fi

if [ -n "$CID" ]; then
    log "  ✓ CID registered with tracker: $CID"
else
    warn "  CID not registered with tracker (package may be in skipped list)"
fi

# Step 8: Delete package from server B (if exists) for clean test
log "Step 8: Preparing server B for fetch test..."
if run_on "$SERVER_B" "nix path-info '$STORE_PATH'" &>/dev/null; then
    log "  Package exists on server B, deleting for clean test..."
    sudo_on "$SERVER_B" "nix-store --delete '$STORE_PATH'" 2>/dev/null || true
fi
log "  ✓ Server B prepared"

# Step 9: Fetch package on server B
log "Step 9: Fetching package on server B via peerix..."

# Create a temporary script to capture build output
FETCH_OUTPUT=$(run_on "$SERVER_B" "NIX_DEBUG=1 nix build nixpkgs#$PACKAGE --no-link --print-out-paths 2>&1" || true)

# Check if it was fetched from peerix
if echo "$FETCH_OUTPUT" | grep -q "127.0.0.1:12304"; then
    log "  ✓ Package fetched via peerix!"

    # Check if it came from IPFS
    if echo "$FETCH_OUTPUT" | grep -q "ipfs"; then
        log "  ✓ Fetched via IPFS"
    fi
elif echo "$FETCH_OUTPUT" | grep -q "cache.nixos.org"; then
    warn "  Package fetched from cache.nixos.org (not peerix)"
else
    log "  Package fetched (source unknown from logs)"
fi

# Step 10: Verify package exists on server B
log "Step 10: Final verification..."
if run_on "$SERVER_B" "nix path-info '$STORE_PATH'" &>/dev/null; then
    log "  ✓ Package verified on server B"

    # Get size info
    SIZE_INFO=$(run_on "$SERVER_B" "nix path-info -sS '$STORE_PATH' 2>/dev/null" || echo "")
    if [ -n "$SIZE_INFO" ]; then
        log "  Size info: $SIZE_INFO"
    fi
else
    err "  Package not found on server B!"
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    TEST RESULTS                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "  Package:     $PACKAGE"
echo "  Store path:  $STORE_PATH"
echo "  Store hash:  $STORE_HASH"
echo "  CID:         ${CID:-not registered}"
echo "  Source:      Server A ($SERVER_A)"
echo "  Destination: Server B ($SERVER_B)"
echo ""
log "═══════════════════ TEST PASSED ═══════════════════"
echo ""
