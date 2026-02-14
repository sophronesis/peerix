import os
import logging
import asyncio
import argparse

import uvloop
from hypercorn import Config
from hypercorn.asyncio import serve

from peerix.app import app, setup_stores


parser = argparse.ArgumentParser(description="Peerix nix binary cache.")
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12304, type=int)
parser.add_argument("--private-key", required=False)
parser.add_argument("--timeout", type=int, default=50)

# Mode selection
parser.add_argument("--mode", choices=["lan", "wan", "both"], default="lan",
                    help="Discovery mode: lan (UDP broadcast), wan (tracker-based), or both")

# WAN options
parser.add_argument("--tracker-url", default=None,
                    help="URL of the peerix tracker (required for wan/both modes)")
parser.add_argument("--peer-id", default=None,
                    help="Unique peer ID (auto-generated if not set)")
parser.add_argument("--announce-addr", default=None,
                    help="Address to announce to the tracker (overrides auto-detected IP)")

# SSH key authentication
parser.add_argument("--ssh-public-key", nargs="?", const="auto", default=None,
                    help="Path to SSH ed25519 public key for peer identity (omit path for auto-detect)")
parser.add_argument("--ssh-private-key", default=None,
                    help="Path to SSH ed25519 private key for request signing")

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

    if args.mode in ("wan", "both") and not args.tracker_url:
        parser.error("--tracker-url is required for wan and both modes")

    logging.basicConfig(level=args.loglevel)
    uvloop.install()

    # Load SSH key identity if configured
    identity = None
    if args.ssh_public_key is not None:
        from peerix.peer_identity import get_peer_id_from_ssh_key, load_signing_identity

        pub_path = None if args.ssh_public_key == "auto" else args.ssh_public_key

        if args.ssh_private_key is not None:
            # Full signing identity
            if pub_path is None:
                # Auto-detect public key from private key path
                pub_path = args.ssh_private_key + ".pub"
                if not os.path.exists(pub_path):
                    parser.error(f"Could not find public key at {pub_path}. "
                                 f"Specify --ssh-public-key explicitly.")
            identity = load_signing_identity(pub_path, args.ssh_private_key)
            if args.peer_id is None:
                args.peer_id = identity.peer_id
            logging.info(f"SSH signing identity loaded, peer_id={identity.peer_id}")
        else:
            # Public key only — derive peer_id but no signing
            peer_id = get_peer_id_from_ssh_key(pub_path)
            if peer_id is not None:
                if args.peer_id is None:
                    args.peer_id = peer_id
                logging.info(f"SSH peer_id derived: {peer_id}")
            else:
                logging.warning("Could not find or parse SSH ed25519 public key")

    asyncio.run(main(args, identity))


async def main(args, identity=None):
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
        announce_addr=args.announce_addr,
        identity=identity,
    ):
        await serve(app, config)


if __name__ == "__main__":
    run()
