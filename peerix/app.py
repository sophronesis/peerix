import logging
import contextlib
import uuid
import typing as t

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


logger = logging.getLogger("peerix.app")

# Global store references
l_access = None
r_access = None
w_access = None
p2p_access = None  # LibP2P store access


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
    enable_ipfs_compat: bool = False,
):
    global l_access, r_access, w_access, p2p_access
    w_access = None
    p2p_access = None

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
                network_id, listen_addrs, enable_ipfs_compat,
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

                # Setup both libp2p and tracker
                p2p_access = await _setup_libp2p(
                    l, local_port, no_verify, upstream_cache,
                    no_filter, filter_patterns, no_default_filters,
                    bootstrap_peers or [], relay_servers or [],
                    network_id, listen_addrs, enable_ipfs_compat,
                )

                if tracker_url:
                    w_access = await _setup_wan(
                        l, local_port, tracker_url, no_verify, upstream_cache,
                        no_filter, filter_patterns, no_default_filters, peer_id,
                    )

                try:
                    yield
                finally:
                    await _cleanup_libp2p(p2p_access)
                    if w_access:
                        await _cleanup_wan(w_access)


async def _setup_wan(local_store, local_port, tracker_url, no_verify,
                     upstream_cache, no_filter, filter_patterns,
                     no_default_filters, peer_id):
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

    tracker_client = TrackerClient(tracker_url, peer_id, local_port)
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
    config = LibP2PConfig(
        listen_addrs=listen_addrs or [
            f"/ip4/0.0.0.0/tcp/{local_port}",
            f"/ip4/0.0.0.0/udp/{local_port}/quic-v1",
        ],
        bootstrap_peers=bootstrap_peers,
        relay_servers=relay_servers,
        network_id=network_id,
        enable_mdns=True,
        enable_dht=True,
        enable_relay=len(relay_servers) > 0,
        enable_autonat=True,
        enable_hole_punching=True,
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


# LibP2P remote NARs
@app.route("/v4/libp2p/{path:path}")
async def pull_libp2p_nar(req: Request) -> Response:
    if p2p_access is None:
        return Response(content="LibP2P mode not enabled", status_code=404)
    try:
        return StreamingResponse(
            await p2p_access["access"].nar(f"v4/libp2p/{req.path_params['path']}"),
            media_type="text/plain",
        )
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# LibP2P status endpoint
@app.route("/v4/libp2p/status")
async def libp2p_status(req: Request) -> Response:
    if p2p_access is None:
        return Response(content='{"error": "LibP2P not enabled"}', status_code=404,
                       media_type="application/json")

    host = p2p_access.get("host")
    dht = p2p_access.get("dht")

    status = {
        "peer_id": str(host.peer_id) if host else None,
        "addrs": [str(a) for a in host.addrs] if host else [],
        "nat_status": host.nat_status if host else "unknown",
        "peers": len(host.get_peers()) if host else 0,
        "discovered": list(dht.get_discovered_peers()) if dht else [],
    }

    import json
    return Response(content=json.dumps(status), status_code=200,
                   media_type="application/json")
