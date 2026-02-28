import logging
import contextlib
import uuid
import typing as t

import trio
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse, JSONResponse
from starlette.applications import Starlette

from peerix.local import local
from peerix.remote import remote
from peerix.prefix import PrefixStore
from peerix.filtered import FilteredStore, NixpkgsFilteredStore
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
    filter_mode: str = "nixpkgs",  # "nixpkgs" or "rules"
    filter_patterns: list = None,
    no_default_filters: bool = False,
    peer_id: str = None,
    # IPFS scan options
    scan_interval: int = 3600,
    ipfs_concurrency: int = 10,
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
                no_filter, filter_mode, filter_patterns, no_default_filters, peer_id,
                scan_interval, ipfs_concurrency,
            )
            ipfs_access = ipfs_info
            try:
                # Start background tasks: heartbeat, delta sync, and periodic scan
                async with trio.open_nursery() as nursery:
                    ipfs_info["_nursery"] = nursery
                    # Start tracker heartbeat if tracker is configured
                    tracker_client = ipfs_info.get("tracker_client")
                    if tracker_client is not None:
                        nursery.start_soon(tracker_client.run_heartbeat)
                        # Start periodic delta sync (every 5 minutes)
                        nursery.start_soon(_run_periodic_delta_sync, tracker_client, 300)
                    # Start periodic scan if enabled
                    if scan_interval > 0:
                        nursery.start_soon(
                            ipfs_info["store"].run_periodic_scan,
                            scan_interval,
                            filter_patterns,
                            ipfs_concurrency,
                        )
                    # Start periodic DHT re-announcement (starts PAUSED by default)
                    nursery.start_soon(
                        ipfs_info["store"].run_periodic_reannounce,
                        1,    # concurrency (1 at a time)
                        1,    # batch_size (1 CID at a time)
                        10.0, # batch_delay (10s between announcements)
                    )
                    yield
                    nursery.cancel_scope.cancel()
            finally:
                await _cleanup_ipfs(ipfs_info)
                ipfs_access = None


async def _run_periodic_delta_sync(tracker_client: TrackerClient, interval: float):
    """
    Run periodic delta sync of store path hashes to tracker.

    Scans the local store and sends only added/removed hashes since last sync.

    Args:
        tracker_client: The tracker client to sync with
        interval: Seconds between syncs
    """
    logger.info(f"Starting periodic delta sync (interval={interval}s)")

    # Do initial sync immediately
    try:
        store_hashes = scan_store_paths(limit=0)
        current_hashes = set(store_hashes)
        await tracker_client.delta_sync_packages(current_hashes)
        logger.info(f"Initial delta sync: {len(current_hashes)} packages")
    except Exception as e:
        logger.warning(f"Initial delta sync failed: {e}")

    while True:
        await trio.sleep(interval)
        try:
            store_hashes = scan_store_paths(limit=0)
            current_hashes = set(store_hashes)
            await tracker_client.delta_sync_packages(current_hashes)
        except Exception as e:
            logger.warning(f"Delta sync failed: {e}")


async def _setup_ipfs(local_store, local_port, tracker_url, no_verify, upstream_cache,
                      no_filter, filter_mode, filter_patterns, no_default_filters, peer_id,
                      scan_interval=3600, ipfs_concurrency=10):
    """Setup IPFS-based NAR sharing with tracker integration."""
    from peerix.ipfs_store import IPFSStore

    if peer_id is None:
        peer_id = str(uuid.uuid4())

    # Build the serving chain: local → verified → filtered
    serving_store = local_store
    verified_store = None
    nixpkgs_filter = None
    if not no_verify:
        verified_store = VerifiedStore(serving_store, upstream_cache)
        serving_store = verified_store
    if not no_filter:
        if filter_mode == "nixpkgs":
            nixpkgs_filter = NixpkgsFilteredStore(serving_store, cache_url=upstream_cache)
            serving_store = nixpkgs_filter
            logger.info("Using nixpkgs filter (only serving packages in cache.nixos.org)")
        else:  # "rules"
            serving_store = FilteredStore(
                serving_store,
                extra_patterns=filter_patterns or [],
                use_defaults=not no_default_filters,
            )
            logger.info("Using rules-based filter")

    # Create tracker client for package lookups
    tracker_client = None
    if tracker_url:
        tracker_client = TrackerClient(tracker_url, peer_id, local_port)
        # Do initial announce (without packages - delta sync handles that)
        try:
            await tracker_client.announce()
            logger.info(f"Announced to tracker as peer {peer_id}")
        except Exception as e:
            logger.warning(f"Initial tracker announce failed: {e}")

    ipfs_store = IPFSStore(serving_store, tracker_client=tracker_client)
    ipfs_prefix = PrefixStore("v5/ipfs", ipfs_store)

    # Note: Delta sync moved to background task to avoid blocking startup
    logger.info("IPFS store initialized" + (" with tracker" if tracker_client else ""))

    return {
        "access": ipfs_prefix,
        "store": ipfs_store,
        "verified_store": verified_store,
        "nixpkgs_filter": nixpkgs_filter,
        "serving_store": serving_store,
        "tracker_client": tracker_client,
        "concurrency": ipfs_concurrency,
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

    nf = ipfs_info.get("nixpkgs_filter")
    if nf is not None:
        await nf.close()

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


@app.route("/scan-status")
async def scan_status(req: Request) -> Response:
    """Get current IPFS scan progress."""
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled", "active": False}, status_code=404)

    progress = ipfs_access["store"].get_scan_progress()
    return JSONResponse(progress)


@app.route("/announce-status")
async def announce_status(req: Request) -> Response:
    """Get current DHT announcement progress."""
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled", "active": False}, status_code=404)

    progress = ipfs_access["store"].get_announce_progress()
    return JSONResponse(progress)


@app.route("/scan/pause", methods=["POST"])
async def pause_scan(req: Request) -> Response:
    """Pause the scan process. Localhost only."""
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)
    ipfs_access["store"].pause_scan()
    return JSONResponse({"status": "paused"})


@app.route("/scan/resume", methods=["POST"])
async def resume_scan(req: Request) -> Response:
    """Resume the scan process. Localhost only."""
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)
    ipfs_access["store"].resume_scan()
    return JSONResponse({"status": "resumed"})


@app.route("/reannounce/pause", methods=["POST"])
async def pause_reannounce(req: Request) -> Response:
    """Pause the DHT re-announcement process. Localhost only."""
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)
    ipfs_access["store"].pause_reannounce()
    return JSONResponse({"status": "paused"})


@app.route("/reannounce/resume", methods=["POST"])
async def resume_reannounce(req: Request) -> Response:
    """Resume the DHT re-announcement process. Localhost only."""
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)
    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)
    ipfs_access["store"].resume_reannounce()
    return JSONResponse({"status": "resumed"})


@app.route("/announce", methods=["POST"])
async def start_dht_announce(req: Request) -> Response:
    """
    Start DHT announcement phase for all cached CIDs.

    Localhost only. Announces all CIDs to DHT for discoverability.
    Query params:
        force: Re-announce even if already announced (default: false)
        concurrency: Max parallel announcements (default: 5)
    """
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)

    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)

    store = ipfs_access["store"]

    # Check if already running
    if store._announce_progress.get("active"):
        return JSONResponse({
            "error": "Announcement already in progress",
            "progress": store.get_announce_progress(),
        }, status_code=409)

    # Parse params
    force = req.query_params.get("force", "false").lower() == "true"
    concurrency = int(req.query_params.get("concurrency", "5"))

    # Start announcement in background
    async def run_announce():
        await store.announce_all_to_dht(concurrency=concurrency, force=force)

    import trio
    nursery = ipfs_access.get("nursery")
    if nursery:
        nursery.start_soon(run_announce)
        return JSONResponse({
            "status": "started",
            "force": force,
            "concurrency": concurrency,
        })
    else:
        # No nursery, run synchronously
        announced, failed, skipped = await store.announce_all_to_dht(
            concurrency=concurrency, force=force
        )
        return JSONResponse({
            "status": "completed",
            "announced": announced,
            "failed": failed,
            "skipped": skipped,
        })


@app.route("/publish/{hash:str}", methods=["POST"])
async def publish_to_ipfs(req: Request) -> Response:
    """
    Manually publish a single store path to IPFS.

    Localhost only. Returns the CID if successful.
    """
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)

    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)

    hsh = req.path_params["hash"]
    store = ipfs_access["store"]

    # Check if already in cache
    if hsh in store._cid_cache:
        cid = store._cid_cache[hsh]
        # Still announce to DHT (may have been cached before DHT announcement was added)
        await store.announce_to_dht(cid)
        return JSONResponse({
            "status": "already_cached",
            "hash": hsh,
            "cid": cid,
            "dht_announced": True,
        })

    # Publish to IPFS
    try:
        cid = await store.publish_nar(hsh)
        if cid:
            # Register with tracker if available
            tracker_client = ipfs_access.get("tracker_client")
            if tracker_client is not None:
                try:
                    await tracker_client.register_cid(hsh, cid)
                except Exception as e:
                    logger.warning(f"Failed to register CID with tracker: {e}")

            return JSONResponse({
                "status": "published",
                "hash": hsh,
                "cid": cid,
            })
        else:
            return JSONResponse({
                "status": "failed",
                "hash": hsh,
                "error": "publish_nar returned None",
            }, status_code=500)
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "hash": hsh,
            "error": str(e),
        }, status_code=500)


DASHBOARD_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Peerix Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            min-height: 100vh;
        }
        h1 { margin-bottom: 24px; font-weight: 300; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            max-width: 1400px;
        }
        .card {
            background: #16213e;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        .card h2 {
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #888;
            margin-bottom: 12px;
        }
        .value {
            font-size: 36px;
            font-weight: bold;
            color: #00d9ff;
        }
        .value.success { color: #00ff88; }
        .value.warning { color: #ffaa00; }
        .value.error { color: #ff4444; }
        .progress-bar {
            background: #0f3460;
            border-radius: 8px;
            height: 8px;
            margin-top: 12px;
            overflow: hidden;
        }
        .progress-bar .fill {
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            height: 100%;
            transition: width 0.3s ease;
        }
        .status-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #0f3460;
        }
        .status-row:last-child { border-bottom: none; }
        .status-label { color: #888; }
        .status-value { font-weight: 500; }
        .mode-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .mode-badge.ipfs { background: #00d9ff33; color: #00d9ff; }
        .mode-badge.lan { background: #00ff8833; color: #00ff88; }
        .current-path {
            font-size: 12px;
            color: #666;
            margin-top: 8px;
            word-break: break-all;
            font-family: monospace;
        }
        .eta {
            font-size: 14px;
            color: #00d9ff;
            margin-top: 8px;
        }
        .ctrl-btn {
            background: #1a1a2e;
            border: 1px solid #333;
            color: #fff;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 8px;
        }
        .ctrl-btn:hover { background: #2a2a3e; }
        .ctrl-btn.danger { border-color: #ff4444; color: #ff4444; }
        .ctrl-btn.danger:hover { background: #ff444422; }
        .ctrl-btn.paused { color: #ff9500; border-color: #ff9500; }
        .ctrl-btn.running { color: #00ff88; border-color: #00ff88; }
        .error-msg {
            background: #ff444433;
            border: 1px solid #ff4444;
            border-radius: 8px;
            padding: 16px;
            color: #ff4444;
        }
        .peers-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .peers-table th, .peers-table td {
            padding: 6px 8px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        .peers-table th {
            color: #888;
            font-weight: normal;
        }
        .peers-table td:first-child {
            width: 30px;
            text-align: center;
        }
        .peers-table .peer-id {
            font-family: monospace;
            color: #666;
        }
    </style>
</head>
<body>
    <h1>Peerix Dashboard</h1>
    <div id="error" class="error-msg" style="display: none; margin-bottom: 20px;"></div>
    <div class="grid">
        <div class="card">
            <h2>Progress</h2>
            <div style="margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="color: #888;"><button class="ctrl-btn" id="scan-toggle" onclick="toggleScan()" title="Pause/Resume">▶</button> Scan</span>
                    <span id="percent">--</span>
                </div>
                <div class="progress-bar"><div class="fill" id="bar" style="width: 0%"></div></div>
                <div class="eta" id="eta"></div>
                <div class="current-path" id="current-path"></div>
            </div>
            <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="color: #888;"><button class="ctrl-btn" id="dht-toggle" onclick="toggleDHT()" title="Pause/Resume">▶</button> DHT Announce</span>
                    <span id="announce-percent">--</span>
                </div>
                <div class="progress-bar"><div class="fill" id="announce-bar" style="width: 0%; background: linear-gradient(90deg, #ff9500, #ff5500);"></div></div>
                <div class="eta" id="announce-eta"></div>
                <div style="font-size: 12px; color: #666; margin-top: 4px;">
                    <span id="announce-announced">0</span> announced,
                    <span id="announce-pending">0</span> pending
                </div>
            </div>
        </div>
        <div class="card">
            <h2>Controls</h2>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button class="ctrl-btn danger" onclick="stopIPFS()" title="Stop IPFS daemon">Stop IPFS</button>
            </div>
        </div>
        <div class="card">
            <h2>Status</h2>
            <div class="status-row">
                <span class="status-label">Mode</span>
                <span id="mode"><span class="mode-badge">--</span></span>
            </div>
            <div class="status-row">
                <span class="status-label">IPFS Daemon</span>
                <span class="status-value" id="ipfs-status">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Scan Active</span>
                <span class="status-value" id="scan-active">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Announcing</span>
                <span class="status-value" id="announce-active">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Tracker</span>
                <span class="status-value" id="tracker-url" style="font-size: 0.8em;">--</span>
            </div>
        </div>
        <div class="card">
            <h2>Stats</h2>
            <div class="status-row">
                <span class="status-label">CID Cache</span>
                <span class="status-value" id="cache-size">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Published</span>
                <span class="status-value" id="published">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">From Tracker</span>
                <span class="status-value" id="tracker">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Already Cached</span>
                <span class="status-value" id="cached">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Skipped</span>
                <span class="status-value" id="skipped">--</span>
            </div>
            <div class="status-row" style="margin-top: 12px; border-top: 1px solid #333; padding-top: 12px;">
                <span class="status-label">IPFS Peers</span>
                <span class="status-value" id="ipfs-peers">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">IPFS In</span>
                <span class="status-value" id="ipfs-rate-in">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">IPFS Out</span>
                <span class="status-value" id="ipfs-rate-out">--</span>
            </div>
        </div>
        <div class="card" id="tracker-card" style="display: none;">
            <h2>Tracker Peers</h2>
            <table class="peers-table">
                <thead>
                    <tr>
                        <th></th>
                        <th>IP</th>
                        <th>Peer ID</th>
                    </tr>
                </thead>
                <tbody id="peers-body">
                </tbody>
            </table>
        </div>
        <div class="card" id="ipfs-peers-card" style="display: none;">
            <h2>IPFS Swarm Peers</h2>
            <div class="status-row" style="margin-bottom: 8px;">
                <span class="status-label">Inbound</span>
                <span class="status-value" id="ipfs-inbound-count" style="color: #00ff88;">--</span>
            </div>
            <div class="status-row" style="margin-bottom: 12px;">
                <span class="status-label">Outbound</span>
                <span class="status-value" id="ipfs-outbound-count" style="color: #00d9ff;">--</span>
            </div>
            <table class="peers-table" style="font-size: 11px;">
                <thead>
                    <tr>
                        <th></th>
                        <th>IP</th>
                        <th>In</th>
                        <th>Out</th>
                    </tr>
                </thead>
                <tbody id="ipfs-peers-body">
                </tbody>
            </table>
        </div>
    </div>
    <script>
        // Country code to flag emoji
        function countryToFlag(code) {
            if (!code || code.length !== 2) return '';
            const offset = 127397;
            return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
        }

        let lastVersion = null;
        let scanPaused = false;
        let dhtPaused = false;

        async function toggleScan() {
            const endpoint = scanPaused ? '/scan/resume' : '/scan/pause';
            await fetch(endpoint, { method: 'POST' });
        }

        async function toggleDHT() {
            const endpoint = dhtPaused ? '/reannounce/resume' : '/reannounce/pause';
            await fetch(endpoint, { method: 'POST' });
        }

        async function stopIPFS() {
            if (confirm('Stop IPFS daemon? This will disable all IPFS functionality.')) {
                try {
                    await fetch('http://127.0.0.1:5001/api/v0/shutdown', { method: 'POST' });
                    alert('IPFS shutdown requested');
                } catch (e) {
                    alert('Failed to stop IPFS: ' + e.message);
                }
            }
        }

        async function update() {
            try {
                const [scanResp, statsResp, announceResp] = await Promise.all([
                    fetch('/scan-status'),
                    fetch('/dashboard-stats'),
                    fetch('/announce-status')
                ]);

                if (!scanResp.ok || !statsResp.ok || !announceResp.ok) {
                    throw new Error('Failed to fetch data');
                }

                const scan = await scanResp.json();
                const stats = await statsResp.json();
                const announce = await announceResp.json();

                // Auto-reload on version change
                if (stats.dashboard_version) {
                    if (lastVersion && lastVersion !== stats.dashboard_version) {
                        location.reload();
                        return;
                    }
                    lastVersion = stats.dashboard_version;
                }

                document.getElementById('error').style.display = 'none';

                // Scan progress (cap at 100%)
                const percent = Math.min(100, scan.percent || 0);
                document.getElementById('percent').textContent = percent.toFixed(1) + '%';
                document.getElementById('bar').style.width = percent + '%';

                // Scan stats
                document.getElementById('published').textContent = scan.published || 0;
                document.getElementById('tracker').textContent = scan.from_tracker || 0;
                document.getElementById('cached').textContent = scan.already_cached || 0;
                document.getElementById('skipped').textContent = scan.skipped || 0;

                // Announcement progress (cap at 100%)
                const announcePercent = Math.min(100, announce.percent || 0);
                document.getElementById('announce-percent').textContent = announcePercent.toFixed(1) + '%';
                document.getElementById('announce-bar').style.width = announcePercent + '%';
                document.getElementById('announce-announced').textContent = announce.fresh_announced || 0;
                document.getElementById('announce-pending').textContent = announce.pending || 0;

                // Announcement ETA
                const announceEtaEl = document.getElementById('announce-eta');
                const eta = announce.active ? announce.eta_seconds : announce.reannounce_eta_seconds;
                if (eta) {
                    let etaText;
                    if (eta < 60) {
                        etaText = Math.round(eta) + 's remaining';
                    } else if (eta < 3600) {
                        const mins = Math.floor(eta / 60);
                        const secs = Math.round(eta % 60);
                        etaText = mins + 'm ' + secs + 's remaining';
                    } else if (eta < 86400) {
                        const hours = Math.floor(eta / 3600);
                        const mins = Math.floor((eta % 3600) / 60);
                        etaText = hours + 'h ' + mins + 'm remaining';
                    } else {
                        const days = Math.floor(eta / 86400);
                        const hours = Math.floor((eta % 86400) / 3600);
                        etaText = days + 'd ' + hours + 'h remaining';
                    }
                    announceEtaEl.textContent = announce.paused ? '' : etaText;
                } else {
                    announceEtaEl.textContent = announce.active ? 'Starting...' : '';
                }

                // ETA
                const etaEl = document.getElementById('eta');
                if (scan.active && scan.eta_seconds) {
                    const eta = scan.eta_seconds;
                    let etaText;
                    if (eta < 60) {
                        etaText = Math.round(eta) + 's remaining';
                    } else if (eta < 3600) {
                        const mins = Math.floor(eta / 60);
                        const secs = Math.round(eta % 60);
                        etaText = mins + 'm ' + secs + 's remaining';
                    } else {
                        const hours = Math.floor(eta / 3600);
                        const mins = Math.floor((eta % 3600) / 60);
                        etaText = hours + 'h ' + mins + 'm remaining';
                    }
                    etaEl.textContent = etaText;
                } else {
                    etaEl.textContent = '';
                }

                // Current path
                const currentPath = scan.current_path || '';
                document.getElementById('current-path').textContent = currentPath ?
                    'Processing: ' + currentPath : (scan.active ? 'Starting...' : '');

                // Dashboard stats
                document.getElementById('cache-size').textContent = stats.cid_cache_size || 0;

                // Mode badge
                const mode = stats.mode || 'unknown';
                const modeEl = document.getElementById('mode');
                modeEl.innerHTML = '<span class="mode-badge ' + mode + '">' + mode + '</span>';

                // IPFS status
                const ipfsEl = document.getElementById('ipfs-status');
                if (stats.ipfs_available) {
                    ipfsEl.textContent = 'Connected';
                    ipfsEl.style.color = '#00ff88';
                } else {
                    ipfsEl.textContent = 'Disconnected';
                    ipfsEl.style.color = '#ff4444';
                }

                // Scan active
                const activeEl = document.getElementById('scan-active');
                if (scan.active) {
                    activeEl.textContent = 'Yes';
                    activeEl.style.color = '#00ff88';
                } else {
                    activeEl.textContent = 'No';
                    activeEl.style.color = '#888';
                }

                // Announce active
                const announceActiveEl = document.getElementById('announce-active');
                if (announce.active) {
                    announceActiveEl.textContent = 'Yes';
                    announceActiveEl.style.color = '#ff9500';
                } else {
                    announceActiveEl.textContent = 'No';
                    announceActiveEl.style.color = '#888';
                }

                // Update pause states and buttons
                scanPaused = scan.paused || false;
                dhtPaused = announce.paused || false;

                const scanToggle = document.getElementById('scan-toggle');
                const dhtToggle = document.getElementById('dht-toggle');

                if (scanPaused) {
                    scanToggle.textContent = '▶';
                    scanToggle.className = 'ctrl-btn paused';
                    scanToggle.title = 'Resume scan';
                } else {
                    scanToggle.textContent = '⏸';
                    scanToggle.className = 'ctrl-btn running';
                    scanToggle.title = 'Pause scan';
                }

                if (dhtPaused) {
                    dhtToggle.textContent = '▶';
                    dhtToggle.className = 'ctrl-btn paused';
                    dhtToggle.title = 'Resume DHT announce';
                } else {
                    dhtToggle.textContent = '⏸';
                    dhtToggle.className = 'ctrl-btn running';
                    dhtToggle.title = 'Pause DHT announce';
                }

                // IPFS Peers and Bandwidth
                document.getElementById('ipfs-peers').textContent = stats.ipfs_peers ?? '--';
                if (stats.ipfs_bandwidth) {
                    const formatRate = (rate) => {
                        if (rate > 1024 * 1024) return (rate / 1024 / 1024).toFixed(1) + ' MB/s';
                        if (rate > 1024) return (rate / 1024).toFixed(1) + ' KB/s';
                        return rate.toFixed(0) + ' B/s';
                    };
                    document.getElementById('ipfs-rate-in').textContent = formatRate(stats.ipfs_bandwidth.rate_in);
                    document.getElementById('ipfs-rate-out').textContent = formatRate(stats.ipfs_bandwidth.rate_out);
                }

                // Tracker URL
                const trackerEl = document.getElementById('tracker-url');
                const trackerCard = document.getElementById('tracker-card');
                if (stats.tracker_url) {
                    trackerEl.textContent = stats.tracker_url;
                    trackerEl.style.color = '#00d9ff';

                    // Fetch tracker peers (via local proxy to avoid CORS)
                    try {
                        const peersResp = await fetch('/tracker-peers');
                        if (peersResp.ok) {
                            const peersData = await peersResp.json();
                            const peers = peersData.peers || [];
                            trackerCard.style.display = 'block';

                            const tbody = document.getElementById('peers-body');
                            tbody.innerHTML = '';

                            for (const peer of peers) {
                                const tr = document.createElement('tr');

                                // Flag cell (from server-side lookup)
                                const flagTd = document.createElement('td');
                                flagTd.textContent = countryToFlag(peer.country || '');
                                tr.appendChild(flagTd);

                                // IP cell
                                const ipTd = document.createElement('td');
                                ipTd.textContent = peer.addr;
                                tr.appendChild(ipTd);

                                // Peer ID cell
                                const peerTd = document.createElement('td');
                                peerTd.className = 'peer-id';
                                peerTd.textContent = peer.peer_id.substring(0, 8) + '...';
                                tr.appendChild(peerTd);

                                tbody.appendChild(tr);
                            }
                        }
                    } catch (e) {
                        // Tracker fetch failed, hide card
                        trackerCard.style.display = 'none';
                    }
                } else {
                    trackerEl.textContent = 'Not configured';
                    trackerEl.style.color = '#888';
                    trackerCard.style.display = 'none';
                }

                // Fetch IPFS swarm peers
                const ipfsPeersCard = document.getElementById('ipfs-peers-card');
                try {
                    const ipfsPeersResp = await fetch('/ipfs-peers');
                    if (ipfsPeersResp.ok) {
                        const ipfsPeersData = await ipfsPeersResp.json();
                        const ipfsPeers = ipfsPeersData.peers || [];

                        if (ipfsPeers.length > 0) {
                            ipfsPeersCard.style.display = 'block';

                            // Update counts
                            document.getElementById('ipfs-inbound-count').textContent = ipfsPeersData.inbound || 0;
                            document.getElementById('ipfs-outbound-count').textContent = ipfsPeersData.outbound || 0;

                            const ipfsTbody = document.getElementById('ipfs-peers-body');
                            ipfsTbody.innerHTML = '';

                            // Format bytes
                            const formatBytes = (bytes) => {
                                if (bytes >= 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(1) + 'G';
                                if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + 'M';
                                if (bytes >= 1024) return (bytes / 1024).toFixed(1) + 'K';
                                return bytes + 'B';
                            };

                            // Truncate IP to max 15 chars
                            const truncateIp = (ip) => {
                                if (!ip || ip.length <= 15) return ip;
                                return ip.substring(0, 12) + '...';
                            };

                            // Show first 15 peers
                            for (const peer of ipfsPeers.slice(0, 15)) {
                                const tr = document.createElement('tr');

                                // Flag cell
                                const flagTd = document.createElement('td');
                                flagTd.textContent = countryToFlag(peer.country || '');
                                tr.appendChild(flagTd);

                                // IP cell (truncated)
                                const ipTd = document.createElement('td');
                                ipTd.textContent = truncateIp(peer.ip);
                                if (peer.ip && peer.ip.length > 15) {
                                    ipTd.title = peer.ip;
                                }
                                tr.appendChild(ipTd);

                                // In bandwidth cell
                                const inTd = document.createElement('td');
                                inTd.textContent = formatBytes(peer.total_in || 0);
                                inTd.style.color = '#00ff88';
                                tr.appendChild(inTd);

                                // Out bandwidth cell
                                const outTd = document.createElement('td');
                                outTd.textContent = formatBytes(peer.total_out || 0);
                                outTd.style.color = '#00d9ff';
                                tr.appendChild(outTd);

                                ipfsTbody.appendChild(tr);
                            }

                            // Show "more" indicator if truncated
                            if (ipfsPeers.length > 15) {
                                const tr = document.createElement('tr');
                                const td = document.createElement('td');
                                td.colSpan = 4;
                                td.textContent = '... and ' + (ipfsPeers.length - 15) + ' more';
                                td.style.color = '#666';
                                td.style.textAlign = 'center';
                                tr.appendChild(td);
                                ipfsTbody.appendChild(tr);
                            }
                        } else {
                            ipfsPeersCard.style.display = 'none';
                        }
                    }
                } catch (e) {
                    ipfsPeersCard.style.display = 'none';
                }

            } catch (e) {
                document.getElementById('error').textContent = 'Error: ' + e.message;
                document.getElementById('error').style.display = 'block';
            }
        }

        update();
        setInterval(update, 2000);
    </script>
</body>
</html>'''


@app.route("/dashboard")
async def dashboard(req: Request) -> Response:
    """Serve the peerix dashboard HTML page."""
    return Response(content=DASHBOARD_HTML, media_type="text/html")


@app.route("/dashboard-stats")
async def dashboard_stats(req: Request) -> Response:
    """Get dashboard statistics as JSON."""
    import hashlib
    stats = {
        "mode": "ipfs" if ipfs_access else "lan",
        "dashboard_version": hashlib.md5(DASHBOARD_HTML.encode()).hexdigest()[:8],
        "cid_cache_size": 0,
        "skipped_cache_size": 0,
        "total_dht_announced": 0,
        "ipfs_available": False,
        "tracker_url": None,
    }

    if ipfs_access is not None:
        store = ipfs_access["store"]
        stats["cid_cache_size"] = len(store._cid_cache)
        stats["skipped_cache_size"] = len(store._skipped_cache)
        stats["total_dht_announced"] = store._total_dht_announced

        # Get tracker URL if configured
        tracker_client = ipfs_access.get("tracker_client")
        if tracker_client is not None:
            stats["tracker_url"] = tracker_client.tracker_url

        # Check IPFS daemon connectivity and get stats
        try:
            client = await store._get_client()
            resp = await client.post(f"{store.api_url}/id", timeout=5.0)
            stats["ipfs_available"] = resp.status_code == 200

            # Get bandwidth stats
            bw_resp = await client.post(f"{store.api_url}/stats/bw", timeout=5.0)
            if bw_resp.status_code == 200:
                bw = bw_resp.json()
                stats["ipfs_bandwidth"] = {
                    "total_in": bw.get("TotalIn", 0),
                    "total_out": bw.get("TotalOut", 0),
                    "rate_in": bw.get("RateIn", 0),
                    "rate_out": bw.get("RateOut", 0),
                }

            # Get peer count
            peers_resp = await client.post(f"{store.api_url}/swarm/peers", timeout=5.0)
            if peers_resp.status_code == 200:
                peers = peers_resp.json()
                stats["ipfs_peers"] = len(peers.get("Peers") or [])
        except Exception:
            stats["ipfs_available"] = False

    return JSONResponse(stats)


# Cache for IP -> country code lookups
_ip_country_cache: dict = {}


@app.route("/tracker-peers")
async def tracker_peers(req: Request) -> Response:
    """Proxy tracker peers endpoint and add country codes."""
    if ipfs_access is None:
        return JSONResponse({"peers": []})

    tracker_client = ipfs_access.get("tracker_client")
    if tracker_client is None:
        return JSONResponse({"peers": []})

    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{tracker_client.tracker_url}/peers")
            if resp.status_code == 200:
                data = resp.json()
                peers = data.get("peers", [])

                # Get unique IPs that need lookup
                ips_to_lookup = [
                    p["addr"] for p in peers
                    if p["addr"] not in _ip_country_cache
                ]

                # Batch lookup country codes (ip-api.com allows batch via POST)
                if ips_to_lookup:
                    try:
                        geo_resp = await client.post(
                            "http://ip-api.com/batch?fields=query,countryCode",
                            json=[{"query": ip} for ip in ips_to_lookup[:100]],
                            timeout=5.0,
                        )
                        if geo_resp.status_code == 200:
                            for item in geo_resp.json():
                                _ip_country_cache[item.get("query", "")] = item.get("countryCode", "")
                    except Exception:
                        pass

                # Add country code to each peer
                for peer in peers:
                    peer["country"] = _ip_country_cache.get(peer["addr"], "")

                return JSONResponse({"peers": peers})
    except Exception:
        pass

    return JSONResponse({"peers": []})


@app.route("/ipfs-peers")
async def ipfs_peers(req: Request) -> Response:
    """Get IPFS swarm peers with direction, latency, and bandwidth."""
    if ipfs_access is None:
        return JSONResponse({"peers": [], "inbound": 0, "outbound": 0})

    store = ipfs_access.get("store")
    if store is None:
        return JSONResponse({"peers": [], "inbound": 0, "outbound": 0})

    try:
        client = await store._get_client()
        resp = await client.post(
            f"{store.api_url}/swarm/peers?direction=true&latency=true",
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            raw_peers = data.get("Peers") or []

            # Parse and format peers
            peers = []
            inbound_count = 0
            outbound_count = 0

            # Get unique IPs that need lookup
            ips_to_lookup = []
            for p in raw_peers:
                addr = p.get("Addr", "")
                # Extract IP from multiaddr like /ip4/1.2.3.4/tcp/4001
                parts = addr.split("/")
                ip = ""
                for i, part in enumerate(parts):
                    if part in ("ip4", "ip6") and i + 1 < len(parts):
                        ip = parts[i + 1]
                        break

                if ip and ip not in _ip_country_cache:
                    ips_to_lookup.append(ip)

            # Batch lookup country codes
            if ips_to_lookup:
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=5.0) as geo_client:
                        geo_resp = await geo_client.post(
                            "http://ip-api.com/batch?fields=query,countryCode",
                            json=[{"query": ip} for ip in ips_to_lookup[:100]],
                            timeout=5.0,
                        )
                        if geo_resp.status_code == 200:
                            for item in geo_resp.json():
                                _ip_country_cache[item.get("query", "")] = item.get("countryCode", "")
                except Exception:
                    pass

            # Fetch per-peer bandwidth stats in parallel (limit to 20 peers)
            peer_bw = {}
            peer_ids_to_query = [p.get("Peer", "") for p in raw_peers[:20] if p.get("Peer")]

            async def fetch_peer_bw(peer_id: str) -> None:
                try:
                    bw_resp = await client.post(
                        f"{store.api_url}/stats/bw?peer={peer_id}",
                        timeout=2.0,
                    )
                    if bw_resp.status_code == 200:
                        bw_data = bw_resp.json()
                        peer_bw[peer_id] = {
                            "total_in": bw_data.get("TotalIn", 0),
                            "total_out": bw_data.get("TotalOut", 0),
                            "rate_in": bw_data.get("RateIn", 0),
                            "rate_out": bw_data.get("RateOut", 0),
                        }
                except Exception:
                    pass

            # Run bandwidth queries in parallel
            import trio
            async with trio.open_nursery() as nursery:
                for peer_id in peer_ids_to_query:
                    nursery.start_soon(fetch_peer_bw, peer_id)

            for p in raw_peers:
                addr = p.get("Addr", "")
                peer_id = p.get("Peer", "")
                latency = p.get("Latency", "n/a")
                direction = p.get("Direction", 0)  # 1=inbound, 2=outbound

                # Extract IP from multiaddr
                parts = addr.split("/")
                ip = ""
                for i, part in enumerate(parts):
                    if part in ("ip4", "ip6") and i + 1 < len(parts):
                        ip = parts[i + 1]
                        break

                # Format latency
                if latency and latency != "n/a":
                    # Convert from "2.470056507s" to "2.5s"
                    if latency.endswith("ms"):
                        lat_val = float(latency[:-2])
                        latency = f"{lat_val:.0f}ms"
                    elif latency.endswith("s"):
                        lat_val = float(latency[:-1])
                        if lat_val < 1:
                            latency = f"{lat_val*1000:.0f}ms"
                        else:
                            latency = f"{lat_val:.1f}s"

                if direction == 1:
                    inbound_count += 1
                    dir_str = "in"
                elif direction == 2:
                    outbound_count += 1
                    dir_str = "out"
                else:
                    dir_str = "?"

                # Get bandwidth for this peer
                bw = peer_bw.get(peer_id, {})

                peers.append({
                    "ip": ip,
                    "peer_id": peer_id,
                    "latency": latency,
                    "direction": dir_str,
                    "country": _ip_country_cache.get(ip, ""),
                    "total_in": bw.get("total_in", 0),
                    "total_out": bw.get("total_out", 0),
                    "rate_in": bw.get("rate_in", 0),
                    "rate_out": bw.get("rate_out", 0),
                })

            # Sort by total bandwidth (highest first)
            peers.sort(key=lambda x: -(x["total_in"] + x["total_out"]))

            return JSONResponse({
                "peers": peers,
                "inbound": inbound_count,
                "outbound": outbound_count,
            })
    except Exception:
        pass

    return JSONResponse({"peers": [], "inbound": 0, "outbound": 0})


@app.route("/batch-narinfo", methods=["POST"])
async def batch_narinfo(req: Request) -> Response:
    """
    Fetch narinfo for multiple hashes in parallel.

    Localhost only. Accepts {"hashes": ["hash1", "hash2", ...]}.
    Returns {"hash1": <narinfo_dict>, "hash2": null, ...}.
    Limited to 100 hashes per request.
    """
    # Restrict to localhost
    if req.client.host not in ("127.0.0.1", "::1"):
        return Response(content="Permission denied.", status_code=403)

    if ipfs_access is None:
        return JSONResponse({"error": "IPFS mode not enabled"}, status_code=404)

    try:
        body = await req.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    hashes = body.get("hashes", [])
    if not isinstance(hashes, list):
        return JSONResponse({"error": "hashes must be a list"}, status_code=400)

    # Limit batch size to prevent abuse
    hashes = hashes[:100]

    results = await ipfs_access["store"].batch_narinfo(hashes)

    # Convert NarInfo to dict for JSON serialization
    output = {}
    for h, ni in results.items():
        if ni is not None:
            output[h] = {
                "storePath": ni.storePath,
                "url": ni.url,
                "compression": ni.compression,
                "narHash": ni.narHash,
                "narSize": ni.narSize,
                "references": list(ni.references),
                "deriver": ni.deriver,
                "signatures": list(ni.signatures),
            }
        else:
            output[h] = None

    return JSONResponse(output)
