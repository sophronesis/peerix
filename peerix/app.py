import logging
import contextlib
import uuid
import typing as t

import trio
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.applications import Starlette

from peerix.local import local
from peerix.remote import remote
from peerix.prefix import PrefixStore
from peerix.filtered import FilteredStore
from peerix.verified import VerifiedStore
from peerix.tracker_client import TrackerClient
from peerix.store_scanner import scan_store_paths


logger = logging.getLogger("peerix.app")

# Global store references
l_access = None
r_access = None
ipfs_access = None  # IPFS store access
cache_priority = 5  # Default cache priority (lower = higher priority)


@contextlib.asynccontextmanager
async def setup_stores(
    local_port: int,
    timeout: float,
    mode: str = "lan",
    tracker_url: str = None,
    no_verify: bool = False,
    upstream_cache: str = "https://cache.nixos.org",
    no_filter: bool = False,
    filter_patterns: list = None,
    no_default_filters: bool = False,
    peer_id: str = None,
    # IPFS scan options
    scan_interval: int = 3600,
    # Cache options
    priority: int = 5,
):
    global l_access, r_access, ipfs_access, cache_priority
    cache_priority = priority
    ipfs_access = None

    async with local() as l:
        l_access = PrefixStore("local/nar", l)

        if mode == "lan":
            lp = PrefixStore("local", l)
            async with remote(lp, local_port, "0.0.0.0", lp.prefix, timeout) as r:
                r_access = PrefixStore("v2/remote", r)
                yield

        elif mode == "ipfs":
            # IPFS mode - uses IPFS for P2P NAR distribution
            r_access = None
            ipfs_info = await _setup_ipfs(
                l, local_port, tracker_url, no_verify, upstream_cache,
                no_filter, filter_patterns, no_default_filters, peer_id,
                scan_interval,
            )
            ipfs_access = ipfs_info
            try:
                # Start background tasks: heartbeat, CID sync, and periodic scan
                async with trio.open_nursery() as nursery:
                    ipfs_info["_nursery"] = nursery
                    # Start tracker heartbeat if tracker is configured
                    tracker_client = ipfs_info.get("tracker_client")
                    if tracker_client is not None:
                        nursery.start_soon(tracker_client.run_heartbeat)
                        # Sync CID mappings in background (non-blocking)
                        nursery.start_soon(
                            ipfs_info["store"].sync_cid_mappings_to_tracker
                        )
                    # Start periodic scan if enabled
                    if scan_interval > 0:
                        nursery.start_soon(
                            ipfs_info["store"].run_periodic_scan,
                            scan_interval,
                            filter_patterns,
                        )
                    yield
                    nursery.cancel_scope.cancel()
            finally:
                await _cleanup_ipfs(ipfs_info)
                ipfs_access = None


async def _setup_ipfs(local_store, local_port, tracker_url, no_verify, upstream_cache,
                      no_filter, filter_patterns, no_default_filters, peer_id,
                      scan_interval=3600):
    """Setup IPFS-based NAR sharing with tracker integration."""
    from peerix.ipfs_store import IPFSStore

    if peer_id is None:
        peer_id = str(uuid.uuid4())

    # Build the serving chain: local → verified → filtered
    serving_store = local_store
    verified_store = None
    if not no_verify:
        verified_store = VerifiedStore(serving_store, upstream_cache)
        serving_store = verified_store
    if not no_filter:
        serving_store = FilteredStore(
            serving_store,
            extra_patterns=filter_patterns or [],
            use_defaults=not no_default_filters,
        )

    # Create tracker client for CID lookups
    tracker_client = None
    if tracker_url:
        tracker_client = TrackerClient(tracker_url, peer_id, local_port)
        # Scan and announce store paths
        logger.info("Scanning local store paths for tracker announcement...")
        store_hashes = scan_store_paths(limit=0)
        tracker_client.set_package_hashes(store_hashes)
        logger.info(f"Will announce {len(store_hashes)} store paths to tracker")
        # Do initial announce
        try:
            await tracker_client.announce()
            logger.info(f"Announced to tracker as peer {peer_id}")
        except Exception as e:
            logger.warning(f"Initial tracker announce failed: {e}")

    ipfs_store = IPFSStore(serving_store, tracker_client=tracker_client)
    ipfs_prefix = PrefixStore("v5/ipfs", ipfs_store)

    # Note: CID sync moved to background task to avoid blocking startup
    logger.info("IPFS store initialized" + (" with tracker" if tracker_client else ""))

    return {
        "access": ipfs_prefix,
        "store": ipfs_store,
        "verified_store": verified_store,
        "serving_store": serving_store,
        "tracker_client": tracker_client,
    }


async def _cleanup_ipfs(ipfs_info):
    """Cleanup IPFS resources."""
    if ipfs_info is None:
        return

    store = ipfs_info.get("store")
    if store is not None:
        await store.close()

    vs = ipfs_info.get("verified_store")
    if vs is not None:
        await vs.close()

    tracker_client = ipfs_info.get("tracker_client")
    if tracker_client is not None:
        await tracker_client.close()

    logger.info("IPFS store stopped")


app = Starlette()


@app.route("/nix-cache-info")
async def cache_info(_: Request) -> Response:
    ci = await l_access.cache_info()
    ci = ci._replace(priority=cache_priority)  # Lower number = higher priority (default cache.nixos.org is 10)
    return Response(content=ci.dump())


@app.route("/{hash:str}.narinfo")
async def narinfo(req: Request) -> Response:

    if req.client.host != "127.0.0.1":
        return Response(content="Permission denied.", status_code=403)

    hsh = req.path_params["hash"]

    # Try LAN remote store first
    if r_access is not None:
        ni = await r_access.narinfo(hsh)
        if ni is not None:
            return Response(content=ni.dump(), status_code=200, media_type="text/x-nix-narinfo")

    # Try IPFS store
    if ipfs_access is not None:
        ni = await ipfs_access["access"].narinfo(hsh)
        if ni is not None:
            return Response(content=ni.dump(), status_code=200, media_type="text/x-nix-narinfo")

    return Response(content="Not found", status_code=404)


@app.route("/local/{hash:str}.narinfo")
async def access_narinfo(req: Request) -> Response:
    ni = await l_access.narinfo(req.path_params["hash"])
    if ni is None:
        return Response(content="Not found", status_code=404)
    return Response(content=ni.dump(), status_code=200, media_type="text/x-nix-narinfo")


@app.route("/local/nar/{path:str}")
async def push_nar(req: Request) -> Response:
    try:
        return StreamingResponse(
                await l_access.nar(f"local/nar/{req.path_params['path']}"),
                media_type="text/plain"
        )
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# LAN remote NARs
@app.route("/v2/remote/{path:path}")
async def pull_nar(req: Request) -> Response:
    if r_access is None:
        return Response(content="LAN mode not enabled", status_code=404)
    try:
        return StreamingResponse(await r_access.nar(f"v2/remote/{req.path_params['path']}"), media_type="text/plain")
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# IPFS NARs
@app.route("/v5/ipfs/{path:path}")
async def pull_ipfs_nar(req: Request) -> Response:
    if ipfs_access is None:
        return Response(content="IPFS mode not enabled", status_code=404)
    try:
        async def stream_nar():
            # Path is the CID directly (e.g., QmfTgh... or bafyb...)
            async for chunk in ipfs_access["store"].nar(req.path_params['path']):
                yield chunk
        return StreamingResponse(stream_nar(), media_type="text/plain")
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)
