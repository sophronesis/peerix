import logging
import contextlib
import uuid
import typing as t

import trio
import httpx
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.applications import Starlette

from peerix.local import local
from peerix.remote import remote
from peerix.prefix import PrefixStore
from peerix.filtered import FilteredStore
from peerix.verified import VerifiedStore
from peerix.wan import TrackerStore
from peerix.tracker_client import TrackerClient
from peerix.store_scanner import scan_recent_paths


logger = logging.getLogger("peerix.app")

# Global store references
l_access = None
r_access = None
w_access = None
p2p_access = None  # LibP2P store access
ipfs_access = None  # IPFS store access


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
    # LibP2P options
    bootstrap_peers: t.List[str] = None,
    relay_servers: t.List[str] = None,
    network_id: str = None,
    listen_addrs: t.List[str] = None,
    identity_file: str = "/var/lib/peerix/identity.key",
    enable_ipfs_compat: bool = False,
    # IPFS scan options
    scan_interval: int = 3600,
):
    global l_access, r_access, w_access, p2p_access, ipfs_access
    w_access = None
    p2p_access = None
    ipfs_access = None

    async with local() as l:
        l_access = PrefixStore("local/nar", l)

        if mode in ("lan", "both"):
            lp = PrefixStore("local", l)
            async with remote(lp, local_port, "0.0.0.0", lp.prefix, timeout) as r:
                r_access = PrefixStore("v2/remote", r)

                if mode == "both" and tracker_url:
                    w_access = await _setup_wan(
                        l, local_port, tracker_url, no_verify, upstream_cache,
                        no_filter, filter_patterns, no_default_filters, peer_id,
                    )
                    try:
                        yield
                    finally:
                        await _cleanup_wan(w_access)
                else:
                    yield

        elif mode == "wan":
            # In WAN-only mode, set r_access to None — the /{hash}.narinfo
            # endpoint will use WAN store instead.
            r_access = None
            w_access = await _setup_wan(
                l, local_port, tracker_url, no_verify, upstream_cache,
                no_filter, filter_patterns, no_default_filters, peer_id,
            )
            try:
                yield
            finally:
                await _cleanup_wan(w_access)

        elif mode == "libp2p":
            # Pure libp2p mode - no LAN broadcast, no HTTP tracker
            r_access = None
            p2p_access = await _setup_libp2p(
                l, local_port, no_verify, upstream_cache,
                no_filter, filter_patterns, no_default_filters,
                bootstrap_peers or [], relay_servers or [],
                network_id, listen_addrs, identity_file, enable_ipfs_compat,
            )
            try:
                yield
            finally:
                await _cleanup_libp2p(p2p_access)

        elif mode == "hybrid":
            # Hybrid mode - combines libp2p with HTTP tracker
            lp = PrefixStore("local", l)
            async with remote(lp, local_port, "0.0.0.0", lp.prefix, timeout) as r:
                r_access = PrefixStore("v2/remote", r)

                # Setup libp2p first to get the peer ID
                p2p_access = await _setup_libp2p(
                    l, local_port, no_verify, upstream_cache,
                    no_filter, filter_patterns, no_default_filters,
                    bootstrap_peers or [], relay_servers or [],
                    network_id, listen_addrs, identity_file, enable_ipfs_compat,
                )

                # Get libp2p peer ID to register with tracker
                libp2p_peer_id = None
                if p2p_access and p2p_access.get("host"):
                    libp2p_peer_id = str(p2p_access["host"].peer_id)

                if tracker_url:
                    w_access = await _setup_wan(
                        l, local_port, tracker_url, no_verify, upstream_cache,
                        no_filter, filter_patterns, no_default_filters, peer_id,
                        libp2p_peer_id=libp2p_peer_id,
                    )
                    # Set tracker_client on libp2p_store for provider lookups
                    if p2p_access and p2p_access.get("store"):
                        p2p_access["store"].set_tracker_client(w_access["tracker_client"])
                        p2p_access["tracker_client"] = w_access["tracker_client"]

                try:
                    yield
                finally:
                    await _cleanup_libp2p(p2p_access)
                    if w_access:
                        await _cleanup_wan(w_access)

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
                # Start periodic scan in background if enabled
                if scan_interval > 0:
                    async with trio.open_nursery() as nursery:
                        ipfs_info["_scan_nursery"] = nursery
                        nursery.start_soon(
                            ipfs_info["store"].run_periodic_scan,
                            scan_interval,
                            filter_patterns,
                        )
                        yield
                        nursery.cancel_scope.cancel()
                else:
                    yield
            finally:
                await _cleanup_ipfs(ipfs_info)
                ipfs_access = None


async def _setup_ipfs(local_store, local_port, tracker_url, no_verify, upstream_cache,
                      no_filter, filter_patterns, no_default_filters, peer_id,
                      scan_interval=3600):
    """Setup IPFS-based NAR sharing with tracker integration."""
    from peerix.ipfs_store import IPFSStore
    from peerix.store_scanner import scan_recent_paths

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
        store_hashes = scan_recent_paths(limit=500)
        tracker_client.set_package_hashes(store_hashes)
        logger.info(f"Will announce {len(store_hashes)} store paths to tracker")
        # Do initial announce
        try:
            await tracker_client.announce()
            logger.info(f"Announced to tracker as peer {peer_id}")
        except Exception as e:
            logger.warning(f"Initial tracker announce failed: {e}")

    ipfs_store = IPFSStore(serving_store, tracker_client=tracker_client)
    ipfs_access = PrefixStore("v5/ipfs", ipfs_store)

    # Sync local CID mappings to tracker on startup
    if tracker_client is not None:
        try:
            registered = await ipfs_store.sync_cid_mappings_to_tracker()
            if registered > 0:
                logger.info(f"Pre-registered {registered} CID mappings with tracker")
        except Exception as e:
            logger.warning(f"Failed to sync CID mappings to tracker: {e}")

    logger.info("IPFS store initialized" + (" with tracker" if tracker_client else ""))

    return {
        "access": ipfs_access,
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


async def _setup_wan(local_store, local_port, tracker_url, no_verify,
                     upstream_cache, no_filter, filter_patterns,
                     no_default_filters, peer_id, libp2p_peer_id=None):
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

    tracker_client = TrackerClient(tracker_url, peer_id, local_port,
                                   libp2p_peer_id=libp2p_peer_id)

    # Scan and announce store paths
    logger.info("Scanning local store paths for tracker announcement...")
    store_hashes = scan_recent_paths(limit=500)
    tracker_client.set_package_hashes(store_hashes)
    logger.info(f"Will announce {len(store_hashes)} store paths to tracker")

    await tracker_client.start_heartbeat()

    client = httpx.AsyncClient()
    tracker_store = TrackerStore(serving_store, tracker_client, client)
    wan_access = PrefixStore("v3/wan", tracker_store)

    return {
        "access": wan_access,
        "tracker_client": tracker_client,
        "client": client,
        "verified_store": verified_store,
        "serving_store": serving_store,
    }


async def _cleanup_wan(wan_info):
    if wan_info is None:
        return
    await wan_info["tracker_client"].close()
    client = wan_info.get("client")
    if client is not None and not client.is_closed:
        await client.aclose()
    vs = wan_info.get("verified_store")
    if vs is not None:
        await vs.close()


async def _setup_libp2p(
    local_store,
    local_port,
    no_verify,
    upstream_cache,
    no_filter,
    filter_patterns,
    no_default_filters,
    bootstrap_peers,
    relay_servers,
    network_id,
    listen_addrs,
    identity_file,
    enable_ipfs_compat,
):
    """Setup libp2p-based peer discovery and NAR sharing."""
    from peerix.libp2p_host import LibP2PHost, LibP2PConfig
    from peerix.libp2p_dht import PeerixDHT, DHTConfig
    from peerix.libp2p_store import LibP2PStore
    from peerix.libp2p_protocols import (
        PROTOCOL_NARINFO,
        PROTOCOL_NAR,
        NarinfoProtocolHandler,
        NarProtocolHandler,
    )
    from peerix.ipfs_compat import IPFSBridge

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

    # Configure libp2p host
    # Note: py-libp2p 0.6.0 only supports TCP, not QUIC
    # Use a different port for libp2p to avoid conflict with HTTP server
    libp2p_port = local_port + 1000  # e.g., 12304 -> 13304
    config = LibP2PConfig(
        listen_addrs=listen_addrs or [
            f"/ip4/0.0.0.0/tcp/{libp2p_port}",
        ],
        bootstrap_peers=bootstrap_peers,
        relay_servers=relay_servers,
        network_id=network_id,
        enable_mdns=True,
        enable_dht=True,
        enable_relay=len(relay_servers) > 0,
        enable_autonat=True,
        enable_hole_punching=True,
        identity_file=identity_file,
    )

    host = LibP2PHost(config)

    # Create protocol handlers
    narinfo_handler = NarinfoProtocolHandler(serving_store)
    nar_handler = NarProtocolHandler(serving_store)

    # Register protocol handlers before starting
    host.set_stream_handler(PROTOCOL_NARINFO, narinfo_handler.handle)
    host.set_stream_handler(PROTOCOL_NAR, nar_handler.handle)

    # Start the host
    await host.start()

    # Setup DHT
    dht_config = DHTConfig(network_id=network_id)
    dht = PeerixDHT(host, dht_config)
    await dht.start()

    # Create the libp2p store
    libp2p_store = LibP2PStore(local_store, host, dht)
    libp2p_access = PrefixStore("v4/libp2p", libp2p_store)

    # Setup IPFS bridge if enabled
    ipfs_bridge = None
    if enable_ipfs_compat:
        ipfs_bridge = IPFSBridge(host, announce_to_ipfs=True)

    logger.info(f"LibP2P host started: peer_id={host.peer_id}")
    logger.info(f"LibP2P listening on: {host.addrs}")

    return {
        "access": libp2p_access,
        "host": host,
        "dht": dht,
        "store": libp2p_store,
        "verified_store": verified_store,
        "serving_store": serving_store,
        "ipfs_bridge": ipfs_bridge,
    }


async def _cleanup_libp2p(p2p_info):
    """Cleanup libp2p resources."""
    if p2p_info is None:
        return

    logger.info("Stopping LibP2P...")

    dht = p2p_info.get("dht")
    if dht is not None:
        await dht.stop()

    host = p2p_info.get("host")
    if host is not None:
        await host.stop()

    vs = p2p_info.get("verified_store")
    if vs is not None:
        await vs.close()

    logger.info("LibP2P stopped")


app = Starlette()


@app.route("/nix-cache-info")
async def cache_info(_: Request) -> Response:
    ci = await l_access.cache_info()
    ci = ci._replace(priority=20)
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

    # Try LibP2P store
    if p2p_access is not None:
        ni = await p2p_access["access"].narinfo(hsh)
        if ni is not None:
            return Response(content=ni.dump(), status_code=200, media_type="text/x-nix-narinfo")

    # Try WAN store
    if w_access is not None:
        ni = await w_access["access"].narinfo(hsh)
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


# WAN remote NARs
@app.route("/v3/wan/{path:path}")
async def pull_wan_nar(req: Request) -> Response:
    if w_access is None:
        return Response(content="WAN mode not enabled", status_code=404)
    try:
        return StreamingResponse(
            await w_access["access"].nar(f"v3/wan/{req.path_params['path']}"),
            media_type="text/plain",
        )
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# IPFS NARs
@app.route("/v5/ipfs/{path:path}")
async def pull_ipfs_nar(req: Request) -> Response:
    if ipfs_access is None:
        return Response(content="IPFS mode not enabled", status_code=404)
    try:
        async def stream_nar():
            async for chunk in ipfs_access["store"].nar(req.path_params['path']):
                yield chunk
        return StreamingResponse(stream_nar(), media_type="text/plain")
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# LibP2P bootstrap endpoint - returns multiaddr for peer discovery
@app.route("/bootstrap")
async def bootstrap(req: Request) -> Response:
    """Return bootstrap peer multiaddr for libp2p peer discovery."""
    if p2p_access is None:
        return Response(content='{"error": "LibP2P not enabled"}', status_code=404,
                       media_type="application/json")

    host = p2p_access.get("host")
    if host is None:
        return Response(content='{"error": "LibP2P host not available"}', status_code=503,
                       media_type="application/json")

    peer_id = str(host.peer_id)
    # Get public addresses (filter out 0.0.0.0 and 127.0.0.1)
    addrs = []
    for addr in host.addrs:
        addr_str = str(addr)
        if "/0.0.0.0/" not in addr_str and "/127.0.0.1/" not in addr_str:
            addrs.append(addr_str)

    # If no public addrs, try to get server's actual public IP
    if not addrs:
        import urllib.request
        try:
            # Fetch server's public IP (not client's)
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
                public_ip = resp.read().decode().strip()
                if public_ip:
                    addrs.append(f"/ip4/{public_ip}/tcp/13304/p2p/{peer_id}")
        except Exception:
            pass

    import json
    return Response(
        content=json.dumps({
            "peer_id": peer_id,
            "multiaddrs": addrs,
            "network_id": p2p_access.get("dht").config.network_id if p2p_access.get("dht") else None,
        }),
        status_code=200,
        media_type="application/json"
    )


# LibP2P status endpoint (must be before the catch-all path route)
@app.route("/v4/libp2p/status")
async def libp2p_status(req: Request) -> Response:
    if p2p_access is None:
        return Response(content='{"error": "LibP2P not enabled"}', status_code=404,
                       media_type="application/json")

    host = p2p_access.get("host")
    dht = p2p_access.get("dht")

    # Get connected peers directly from host
    connected_peers = []
    try:
        if host:
            peers = host.get_peers()
            connected_peers = [str(p.peer_id) for p in peers]
    except Exception as e:
        logger.debug(f"Failed to get peers: {e}")

    status = {
        "peer_id": str(host.peer_id) if host else None,
        "addrs": [str(a) for a in host.addrs] if host else [],
        "nat_status": host.nat_status if host else "unknown",
        "network_id": dht.config.network_id if dht else None,
        "peer_count": len(connected_peers),
        "peers": connected_peers,
    }

    import json
    return Response(content=json.dumps(status), status_code=200,
                   media_type="application/json")


# LibP2P remote NARs
@app.route("/v4/libp2p/{path:path}")
async def pull_libp2p_nar(req: Request) -> Response:
    if p2p_access is None:
        return Response(content="LibP2P mode not enabled", status_code=404)
    try:
        # The path is libp2p/peer_id/hash/url - use store directly (not PrefixStore)
        return StreamingResponse(
            await p2p_access["store"].nar(req.path_params['path']),
            media_type="text/plain",
        )
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)
