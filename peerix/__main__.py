import os
import sys
import signal
import logging
import argparse

import trio
import psutil
import httpx
from hypercorn import Config
from hypercorn.trio import serve

from peerix.app import app, setup_stores
from peerix.config import load_config, merge_args_with_config


logger = logging.getLogger("peerix.main")


def status_command(args):
    """Query the running peerix daemon for scan status."""
    url = f"http://127.0.0.1:{args.port}/scan-status"
    try:
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code != 200:
            print(f"Error: {resp.text}")
            sys.exit(1)

        data = resp.json()

        if not data.get("active", False):
            print("No scan currently running.")
            if data.get("total", 0) > 0:
                print(f"Last scan: {data['processed']}/{data['total']} paths")
                print(f"  Published: {data.get('published', 0)}")
                print(f"  From tracker: {data.get('from_tracker', 0)}")
                print(f"  Skipped: {data.get('skipped', 0)}")
                print(f"  Already cached: {data.get('already_cached', 0)}")
            return

        # Active scan
        percent = data.get("percent", 0)
        processed = data.get("processed", 0)
        total = data.get("total", 0)
        current_path = data.get("current_path") or data.get("current_hash") or "unknown"

        # Truncate path for display
        if len(current_path) > 60:
            current_path = "..." + current_path[-57:]

        print(f"Scan progress: {percent:.1f}% ({processed}/{total})")
        print(f"  Published: {data.get('published', 0)}")
        print(f"  From tracker: {data.get('from_tracker', 0)}")
        print(f"  Skipped: {data.get('skipped', 0)}")
        print(f"  Already cached: {data.get('already_cached', 0)}")
        print(f"  Current: {current_path}")

    except httpx.ConnectError:
        print(f"Error: Cannot connect to peerix daemon at {url}")
        print("Is peerix running?")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


async def memory_monitor_task(interval: int = 600):
    """Log memory usage every interval seconds (default 10 min)."""
    while True:
        await trio.sleep(interval)
        mem = psutil.virtual_memory()
        proc = psutil.Process()
        proc_mem = proc.memory_info()
        logger.info(
            f"Memory: system {mem.percent:.1f}% used "
            f"({mem.used // 1024 // 1024}MB/{mem.total // 1024 // 1024}MB), "
            f"peerix {proc_mem.rss // 1024 // 1024}MB RSS"
        )

parser = argparse.ArgumentParser(description="Peerix nix binary cache.")
subparsers = parser.add_subparsers(dest="command", help="Commands")

# Main daemon command (default)
serve_parser = subparsers.add_parser("serve", help="Run the peerix daemon (default)")
serve_parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
serve_parser.add_argument("--port", default=12304, type=int)
serve_parser.add_argument("--private-key", required=False)
serve_parser.add_argument("--timeout", type=int, default=50)
serve_parser.add_argument("--mode", choices=["lan", "ipfs"], default="ipfs",
                    help="Discovery mode: ipfs (IPFS-based, default) or lan (UDP broadcast)")
serve_parser.add_argument("--tracker-url", default="https://sophronesis.dev/peerix",
                    help="URL of the peerix tracker for CID registry (used in IPFS mode)")
serve_parser.add_argument("--scan-interval", type=int, default=3600,
                    help="Interval in seconds for periodic nix store scanning (default: 3600 = 1 hour, 0 to disable)")
serve_parser.add_argument("--ipfs-concurrency", type=int, default=10,
                    help="Number of parallel IPFS uploads (default: 10)")
serve_parser.add_argument("--priority", type=int, default=5,
                    help="Cache priority (lower = higher priority, default: 5, cache.nixos.org is 10)")
serve_parser.add_argument("--filter-mode", choices=["nixpkgs", "rules"], default="nixpkgs",
                    help="Package filter mode: nixpkgs (only serve packages in cache.nixos.org, default) or rules (heuristic patterns)")
serve_parser.add_argument("--homeostasis", action="store_true", default=False,
                    help="Enable homeostasis daemon for automatic IPFS peer management")
serve_parser.add_argument("--homeostasis-min-peers", type=int, default=2,
                    help="Minimum IPFS peers to maintain (default: 2)")
serve_parser.add_argument("--homeostasis-max-peers", type=int, default=5,
                    help="Maximum IPFS peers allowed (default: 5)")

# Status command
status_parser = subparsers.add_parser("status", help="Show current scan progress")
status_parser.add_argument("--port", default=12304, type=int, help="Port of the running peerix daemon")

# Also support legacy (no subcommand) usage
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12304, type=int)
parser.add_argument("--private-key", required=False)
parser.add_argument("--timeout", type=int, default=50)
parser.add_argument("--mode", choices=["lan", "ipfs"], default="ipfs",
                    help="Discovery mode: ipfs (IPFS-based, default) or lan (UDP broadcast)")
parser.add_argument("--tracker-url", default="https://sophronesis.dev/peerix",
                    help="URL of the peerix tracker for CID registry (used in IPFS mode)")
parser.add_argument("--scan-interval", type=int, default=3600,
                    help="Interval in seconds for periodic nix store scanning (default: 3600 = 1 hour, 0 to disable)")
parser.add_argument("--ipfs-concurrency", type=int, default=10,
                    help="Number of parallel IPFS uploads (default: 10)")
parser.add_argument("--priority", type=int, default=5,
                    help="Cache priority (lower = higher priority, default: 5, cache.nixos.org is 10)")
parser.add_argument("--filter-mode", choices=["nixpkgs", "rules"], default="nixpkgs",
                    help="Package filter mode: nixpkgs (only serve packages in cache.nixos.org, default) or rules (heuristic patterns)")
parser.add_argument("--homeostasis", action="store_true", default=False,
                    help="Enable homeostasis daemon for automatic IPFS peer management")
parser.add_argument("--homeostasis-min-peers", type=int, default=2,
                    help="Minimum IPFS peers to maintain (default: 2)")
parser.add_argument("--homeostasis-max-peers", type=int, default=5,
                    help="Maximum IPFS peers allowed (default: 5)")


def run():
    args = parser.parse_args()

    # Handle subcommands
    if args.command == "status":
        status_command(args)
        return

    # Load config file and merge with CLI args (CLI takes precedence)
    config = load_config()
    merge_args_with_config(args, config)

    # Default: run the daemon (serve command or no command)
    if args.private_key is not None:
        os.environ["NIX_SECRET_KEY_FILE"] = os.path.abspath(os.path.expanduser(args.private_key))

    logging.basicConfig(level=args.loglevel)
    trio.run(main, args)


async def handle_sighup():
    """Handle SIGHUP signal by triggering a manual store rescan."""
    from peerix.app import ipfs_access

    logger.info("Received SIGHUP, triggering manual store rescan...")
    if ipfs_access is not None and "store" in ipfs_access:
        try:
            concurrency = ipfs_access.get("concurrency", 10)
            published, skipped = await ipfs_access["store"].scan_and_publish(
                concurrency=concurrency
            )
            logger.info(f"Manual rescan complete: {published} published, {skipped} skipped")
        except Exception as e:
            logger.error(f"Manual rescan failed: {e}")
    else:
        logger.warning("SIGHUP received but IPFS mode not active, ignoring")


async def signal_handler_task():
    """Background task to handle SIGHUP signals."""
    with trio.open_signal_receiver(signal.SIGHUP) as signal_aiter:
        async for signum in signal_aiter:
            await handle_sighup()


async def main(args):
    config = Config()
    config.bind = [f"0.0.0.0:{args.port}"]

    async with setup_stores(
        local_port=args.port,
        timeout=args.timeout / 1000.0,
        mode=args.mode,
        tracker_url=args.tracker_url,
        scan_interval=args.scan_interval,
        ipfs_concurrency=args.ipfs_concurrency,
        priority=args.priority,
        filter_mode=args.filter_mode,
        homeostasis_enabled=args.homeostasis,
        homeostasis_min_peers=args.homeostasis_min_peers,
        homeostasis_max_peers=args.homeostasis_max_peers,
    ):
        async with trio.open_nursery() as nursery:
            # Start memory monitor (logs every 10 min)
            nursery.start_soon(memory_monitor_task)
            # Start SIGHUP handler for manual cache refresh (IPFS mode)
            if args.mode == "ipfs":
                nursery.start_soon(signal_handler_task)
            # Run the HTTP server
            await serve(app, config)
            nursery.cancel_scope.cancel()


if __name__ == "__main__":
    run()
