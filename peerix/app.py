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
                no_filter, filter_patterns, no_default_filters, peer_id,
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
                      no_filter, filter_patterns, no_default_filters, peer_id,
                      scan_interval=3600, ipfs_concurrency=10):
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
        .error-msg {
            background: #ff444433;
            border: 1px solid #ff4444;
            border-radius: 8px;
            padding: 16px;
            color: #ff4444;
        }
    </style>
</head>
<body>
    <h1>Peerix Dashboard</h1>
    <div id="error" class="error-msg" style="display: none; margin-bottom: 20px;"></div>
    <div class="grid">
        <div class="card">
            <h2>Scan Progress</h2>
            <div class="value" id="percent">--</div>
            <div class="progress-bar"><div class="fill" id="bar" style="width: 0%"></div></div>
            <div class="current-path" id="current-path"></div>
        </div>
        <div class="card">
            <h2>Published to IPFS</h2>
            <div class="value success" id="published">--</div>
        </div>
        <div class="card">
            <h2>From Tracker</h2>
            <div class="value" id="tracker">--</div>
        </div>
        <div class="card">
            <h2>Already Cached</h2>
            <div class="value" id="cached">--</div>
        </div>
        <div class="card">
            <h2>Skipped</h2>
            <div class="value warning" id="skipped">--</div>
        </div>
        <div class="card">
            <h2>CID Cache Size</h2>
            <div class="value" id="cache-size">--</div>
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
        </div>
    </div>
    <script>
        async function update() {
            try {
                const [scanResp, statsResp] = await Promise.all([
                    fetch('/scan-status'),
                    fetch('/dashboard-stats')
                ]);

                if (!scanResp.ok || !statsResp.ok) {
                    throw new Error('Failed to fetch data');
                }

                const scan = await scanResp.json();
                const stats = await statsResp.json();

                document.getElementById('error').style.display = 'none';

                // Scan progress
                const percent = scan.percent || 0;
                document.getElementById('percent').textContent = percent.toFixed(1) + '%';
                document.getElementById('bar').style.width = percent + '%';

                // Scan stats
                document.getElementById('published').textContent = scan.published || 0;
                document.getElementById('tracker').textContent = scan.from_tracker || 0;
                document.getElementById('cached').textContent = scan.already_cached || 0;
                document.getElementById('skipped').textContent = scan.skipped || 0;

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
    stats = {
        "mode": "ipfs" if ipfs_access else "lan",
        "cid_cache_size": 0,
        "ipfs_available": False,
    }

    if ipfs_access is not None:
        store = ipfs_access["store"]
        stats["cid_cache_size"] = len(store._cid_cache)

        # Check IPFS daemon connectivity
        try:
            client = await store._get_client()
            resp = await client.post(f"{store.api_url}/id", timeout=5.0)
            stats["ipfs_available"] = resp.status_code == 200
        except Exception:
            stats["ipfs_available"] = False

    return JSONResponse(stats)


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
                "fileHash": ni.fileHash,
                "fileSize": ni.fileSize,
                "narHash": ni.narHash,
                "narSize": ni.narSize,
                "references": ni.references,
                "deriver": ni.deriver,
                "sig": ni.sig,
            }
        else:
            output[h] = None

    return JSONResponse(output)
