import os
import signal
import logging
import argparse
import json
import urllib.request
import urllib.error

import trio
from hypercorn import Config
from hypercorn.trio import serve

from peerix.app import app, setup_stores, ipfs_access


logger = logging.getLogger("peerix.main")

parser = argparse.ArgumentParser(description="Peerix nix binary cache.")
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12304, type=int)
parser.add_argument("--private-key", required=False)
parser.add_argument("--timeout", type=int, default=50)

# Mode selection
parser.add_argument("--mode", choices=["lan", "wan", "both", "libp2p", "hybrid", "ipfs"], default="ipfs",
                    help="Discovery mode: ipfs (IPFS-based P2P, default), lan (UDP broadcast), "
                         "wan (tracker-based), libp2p (P2P with NAT traversal), "
                         "hybrid (libp2p + tracker), or both (lan + wan)")

# WAN options
parser.add_argument("--tracker-url", default=None,
                    help="URL of the peerix tracker (required for wan/both/hybrid modes)")
parser.add_argument("--peer-id", default=None,
                    help="Unique peer ID (auto-generated if not set)")

# LibP2P options
parser.add_argument("--bootstrap-url", default=None,
                    help="URL to fetch bootstrap peer multiaddr dynamically (e.g., https://sophronesis.dev/peerix/bootstrap)")
parser.add_argument("--bootstrap-peers", nargs="*", default=None,
                    help="LibP2P bootstrap peer multiaddrs (e.g., /ip4/1.2.3.4/tcp/13304/p2p/QmPeerID)")
parser.add_argument("--relay-servers", nargs="*", default=None,
                    help="LibP2P relay server multiaddrs for NAT traversal fallback")
parser.add_argument("--network-id", default=None,
                    help="Network identifier for DHT peer discovery (peers with same ID discover each other)")
parser.add_argument("--listen-addrs", nargs="*", default=None,
                    help="LibP2P listen multiaddrs (default: /ip4/0.0.0.0/tcp/PORT+1000)")
parser.add_argument("--identity-file", default="/var/lib/peerix/identity.key",
                    help="Path to persistent identity key file (keeps peer ID stable across restarts)")
parser.add_argument("--enable-ipfs-compat", action="store_true",
                    help="Enable IPFS compatibility layer (announce NARs to IPFS DHT)")

# IPFS scan options
parser.add_argument("--scan-interval", type=int, default=3600,
                    help="Interval in seconds for periodic nix store scanning (default: 3600 = 1 hour, 0 to disable)")

# Cache options
parser.add_argument("--priority", type=int, default=5,
                    help="Cache priority (lower = higher priority, default: 5, cache.nixos.org is 10)")

# Verification options
parser.add_argument("--no-verify", action="store_true",
                    help="Disable hash verification against upstream cache")
parser.add_argument("--upstream-cache", default="https://cache.nixos.org",
                    help="Upstream cache URL for verification (default: cache.nixos.org)")

# Filtering options
parser.add_argument("--no-filter", action="store_true",
                    help="Disable heuristic filtering of system/sensitive derivations")
parser.add_argument("--filter-patterns", nargs="*", default=None,
                    help="Additional fnmatch patterns to exclude")
parser.add_argument("--no-default-filters", action="store_true",
                    help="Keep filtering enabled but skip built-in default patterns")


def fetch_bootstrap_peers(url: str) -> list:
    """Fetch bootstrap peer multiaddrs from a URL."""
    try:
        logger.info(f"Fetching bootstrap peers from {url}")
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            multiaddrs = data.get("multiaddrs", [])
            if multiaddrs:
                logger.info(f"Got bootstrap peers: {multiaddrs}")
                return multiaddrs
            else:
                logger.warning(f"No multiaddrs in bootstrap response: {data}")
                return []
    except urllib.error.URLError as e:
        logger.warning(f"Failed to fetch bootstrap peers from {url}: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON from bootstrap URL {url}: {e}")
        return []


def run():
    args = parser.parse_args()
    if args.private_key is not None:
        os.environ["NIX_SECRET_KEY_FILE"] = os.path.abspath(os.path.expanduser(args.private_key))

    # Validate mode requirements
    if args.mode in ("wan", "both") and not args.tracker_url:
        parser.error("--tracker-url is required for wan and both modes")

    if args.mode == "hybrid" and not args.tracker_url and not args.bootstrap_peers:
        parser.error("--tracker-url or --bootstrap-peers required for hybrid mode")

    logging.basicConfig(level=args.loglevel)

    # Fetch bootstrap peers from URL if needed
    if args.mode in ("libp2p", "hybrid") and not args.bootstrap_peers and args.bootstrap_url:
        args.bootstrap_peers = fetch_bootstrap_peers(args.bootstrap_url)

    trio.run(main, args)


async def handle_sighup(filter_patterns):
    """Handle SIGHUP signal by triggering a manual store rescan."""
    from peerix.app import ipfs_access

    logger.info("Received SIGHUP, triggering manual store rescan...")
    if ipfs_access is not None and "store" in ipfs_access:
        try:
            published, skipped = await ipfs_access["store"].scan_and_publish(filter_patterns)
            logger.info(f"Manual rescan complete: {published} published, {skipped} skipped")
            # Sync to tracker after manual scan
            if ipfs_access.get("tracker_client") is not None:
                await ipfs_access["store"].sync_cid_mappings_to_tracker()
        except Exception as e:
            logger.error(f"Manual rescan failed: {e}")
    else:
        logger.warning("SIGHUP received but IPFS mode not active, ignoring")


async def signal_handler_task(filter_patterns):
    """Background task to handle SIGHUP signals."""
    with trio.open_signal_receiver(signal.SIGHUP) as signal_aiter:
        async for signum in signal_aiter:
            await handle_sighup(filter_patterns)


async def main(args):
    config = Config()
    config.bind = [f"0.0.0.0:{args.port}"]

    async with setup_stores(
        local_port=args.port,
        timeout=args.timeout / 1000.0,
        mode=args.mode,
        tracker_url=args.tracker_url,
        no_verify=args.no_verify,
        upstream_cache=args.upstream_cache,
        no_filter=args.no_filter,
        filter_patterns=args.filter_patterns,
        no_default_filters=args.no_default_filters,
        peer_id=args.peer_id,
        # LibP2P options
        bootstrap_peers=args.bootstrap_peers,
        relay_servers=args.relay_servers,
        network_id=args.network_id,
        listen_addrs=args.listen_addrs,
        identity_file=args.identity_file,
        enable_ipfs_compat=args.enable_ipfs_compat,
        # IPFS scan options
        scan_interval=args.scan_interval,
        # Cache options
        priority=args.priority,
    ):
        async with trio.open_nursery() as nursery:
            # Start SIGHUP handler for manual cache refresh
            nursery.start_soon(signal_handler_task, args.filter_patterns)
            # Run the HTTP server
            await serve(app, config)
            nursery.cancel_scope.cancel()


if __name__ == "__main__":
    run()
