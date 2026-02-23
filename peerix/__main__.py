import os
import logging
import argparse

import trio
from hypercorn import Config
from hypercorn.trio import serve

from peerix.app import app, setup_stores


parser = argparse.ArgumentParser(description="Peerix nix binary cache.")
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12304, type=int)
parser.add_argument("--private-key", required=False)
parser.add_argument("--timeout", type=int, default=50)

# Mode selection
parser.add_argument("--mode", choices=["lan", "wan", "both", "libp2p", "hybrid"], default="lan",
                    help="Discovery mode: lan (UDP broadcast), wan (tracker-based), "
                         "libp2p (P2P with NAT traversal), hybrid (libp2p + tracker), or both (lan + wan)")

# WAN options
parser.add_argument("--tracker-url", default=None,
                    help="URL of the peerix tracker (required for wan/both/hybrid modes)")
parser.add_argument("--peer-id", default=None,
                    help="Unique peer ID (auto-generated if not set)")

# LibP2P options
parser.add_argument("--bootstrap-peers", nargs="*", default=None,
                    help="LibP2P bootstrap peer multiaddrs (e.g., /ip4/1.2.3.4/tcp/12304/p2p/QmPeerID)")
parser.add_argument("--relay-servers", nargs="*", default=None,
                    help="LibP2P relay server multiaddrs for NAT traversal fallback")
parser.add_argument("--network-id", default=None,
                    help="Network identifier for DHT peer discovery (peers with same ID discover each other)")
parser.add_argument("--listen-addrs", nargs="*", default=None,
                    help="LibP2P listen multiaddrs (default: /ip4/0.0.0.0/tcp/PORT)")
parser.add_argument("--enable-ipfs-compat", action="store_true",
                    help="Enable IPFS compatibility layer (announce NARs to IPFS DHT)")

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

    trio.run(main, args)


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
        enable_ipfs_compat=args.enable_ipfs_compat,
    ):
        await serve(app, config)


if __name__ == "__main__":
    run()
