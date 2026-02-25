import os
import signal
import logging
import argparse

import trio
import psutil
from hypercorn import Config
from hypercorn.trio import serve

from peerix.app import app, setup_stores


logger = logging.getLogger("peerix.main")


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
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12304, type=int)
parser.add_argument("--private-key", required=False)
parser.add_argument("--timeout", type=int, default=50)

# Mode selection
parser.add_argument("--mode", choices=["lan", "ipfs"], default="ipfs",
                    help="Discovery mode: ipfs (IPFS-based, default) or lan (UDP broadcast)")

# IPFS options
parser.add_argument("--tracker-url", default=None,
                    help="URL of the peerix tracker for CID registry (used in IPFS mode)")
parser.add_argument("--scan-interval", type=int, default=3600,
                    help="Interval in seconds for periodic nix store scanning (default: 3600 = 1 hour, 0 to disable)")
parser.add_argument("--ipfs-concurrency", type=int, default=10,
                    help="Number of parallel IPFS uploads (default: 10)")

# Cache options
parser.add_argument("--priority", type=int, default=5,
                    help="Cache priority (lower = higher priority, default: 5, cache.nixos.org is 10)")


def run():
    args = parser.parse_args()
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
