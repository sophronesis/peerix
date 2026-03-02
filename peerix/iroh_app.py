"""
Asyncio-based Peerix application using Iroh P2P.

This is a cleaner implementation that replaces trio with asyncio
and uses Iroh for NAT-traversing P2P connectivity.
"""

import asyncio
import logging
import socket
import signal
import typing as t
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse, JSONResponse
from starlette.routing import Route

import json
import os

import httpx

from .local_asyncio import local_async, LocalStoreAsync
from .iroh_proto import IrohNode, NARINFO_PROTOCOL
from .store import NarInfo, Store
from .signing import init_signer, sign_narinfo
from .store_scanner import scan_store_paths
from .filtered import FilteredStore, NixpkgsFilteredStore
from .verified import VerifiedStore

# Default path for persisting announced state
DEFAULT_STATE_FILE = "/var/lib/peerix/announced_state.json"

logger = logging.getLogger("peerix.iroh_app")

# Global state
_iroh_node: t.Optional[IrohNode] = None
_local_store: t.Optional[LocalStoreAsync] = None
_cache_priority: int = 5
_store_manager: t.Optional["StoreManager"] = None


class StoreManager:
    """
    Manages local store scanning and tracks available hashes.

    This replaces the IPFS publish step - NARs are generated on-the-fly
    when requested. The manager just tracks what's available.
    """

    def __init__(
        self,
        scan_interval: int = 3600,
        tracker_url: t.Optional[str] = None,
        peer_id: t.Optional[str] = None,
        state_file: str = DEFAULT_STATE_FILE,
        nixpkgs_filter: t.Optional["NixpkgsFilteredStore"] = None,
        filter_concurrency: int = 50,
    ):
        self.scan_interval = scan_interval
        self.tracker_url = tracker_url.rstrip("/") if tracker_url else None
        self.peer_id = peer_id
        self._state_file = state_file
        self._nixpkgs_filter = nixpkgs_filter
        self._filter_concurrency = filter_concurrency
        self._available_hashes: t.Set[str] = set()
        self._last_announced_hashes: t.Set[str] = set()
        self._scan_progress: t.Dict[str, t.Any] = {
            "active": False,
            "total": 0,
            "scanned": 0,
            "filtered": 0,
            "last_scan": None,
            "paused": False,
        }
        self._running = False
        self._http_client: t.Optional[httpx.AsyncClient] = None

        # Load previously announced state
        self._load_announced_state()

    def _load_announced_state(self) -> None:
        """Load the set of previously announced hashes from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    data = json.load(f)
                    self._last_announced_hashes = set(data.get("hashes", []))
                    logger.info(f"Loaded {len(self._last_announced_hashes)} announced hashes from state")
        except Exception as e:
            logger.warning(f"Failed to load announced state: {e}")
            self._last_announced_hashes = set()

    def _save_announced_state(self) -> None:
        """Save the set of announced hashes to disk."""
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            with open(self._state_file, "w") as f:
                json.dump({"hashes": list(self._last_announced_hashes)}, f)
        except Exception as e:
            logger.warning(f"Failed to save announced state: {e}")

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=10.0)
            )
        return self._http_client

    @property
    def available_hashes(self) -> t.Set[str]:
        """Get the set of available store path hashes."""
        return self._available_hashes

    def get_scan_progress(self) -> t.Dict[str, t.Any]:
        """Get current scan progress."""
        progress = self._scan_progress.copy()
        progress["announced_hashes"] = len(self._last_announced_hashes)
        progress["filtering_enabled"] = self._nixpkgs_filter is not None
        return progress

    def pause(self):
        """Pause scanning."""
        self._scan_progress["paused"] = True
        logger.info("Store scanning paused")

    def resume(self):
        """Resume scanning."""
        self._scan_progress["paused"] = False
        logger.info("Store scanning resumed")

    async def delta_sync_packages(self) -> bool:
        """
        Sync package hashes with tracker using delta updates.

        Only sends added/removed hashes since last sync. Falls back to
        batch register if this is the first sync.

        Returns:
            True if successful
        """
        if not self.tracker_url or not self.peer_id:
            return True  # Nothing to sync

        current_hashes = self._available_hashes

        # First sync - send all hashes
        if not self._last_announced_hashes:
            logger.info("First sync, sending all hashes via batch register")
            return await self._batch_register_packages(list(current_hashes))

        # Compute delta
        added = current_hashes - self._last_announced_hashes
        removed = self._last_announced_hashes - current_hashes

        # Nothing changed
        if not added and not removed:
            logger.debug("No package changes, skipping delta sync")
            return True

        client = await self._get_http_client()
        try:
            resp = await client.post(
                f"{self.tracker_url}/packages/delta",
                json={
                    "peer_id": self.peer_id,
                    "added": list(added),
                    "removed": list(removed),
                },
                timeout=60.0,
            )
            if resp.status_code == 200:
                self._last_announced_hashes = current_hashes.copy()
                self._save_announced_state()
                logger.info(f"Delta sync: +{len(added)} -{len(removed)} packages")
                return True
            else:
                logger.warning(f"Delta sync failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Delta sync error: {e}")
            return False

    async def _batch_register_packages(self, hashes: t.List[str]) -> bool:
        """Register many package hashes at once with the tracker."""
        if not self.tracker_url or not self.peer_id:
            return True

        client = await self._get_http_client()
        try:
            resp = await client.post(
                f"{self.tracker_url}/packages/batch",
                json={"peer_id": self.peer_id, "hashes": hashes},
                timeout=60.0,
            )
            if resp.status_code == 200:
                self._last_announced_hashes = set(hashes)
                self._save_announced_state()
                logger.info(f"Batch registered {len(hashes)} packages with tracker")
                return True
            else:
                logger.warning(f"Batch register failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Batch register error: {e}")
            return False

    async def _filter_hashes_batch(self, hashes: t.List[str]) -> t.Set[str]:
        """
        Filter hashes through NixpkgsFilteredStore.

        Only returns hashes that exist in cache.nixos.org.
        Uses semaphore for concurrency control.
        """
        if not self._nixpkgs_filter:
            return set(hashes)

        filtered: t.Set[str] = set()
        semaphore = asyncio.Semaphore(self._filter_concurrency)
        checked = 0

        async def check_one(hsh: str) -> t.Optional[str]:
            nonlocal checked
            async with semaphore:
                try:
                    # Use the filter's _check_nixpkgs method
                    if await self._nixpkgs_filter._check_nixpkgs(hsh):
                        return hsh
                    return None
                finally:
                    checked += 1
                    if checked % 500 == 0:
                        logger.debug(f"Checked {checked}/{len(hashes)} hashes...")

        # Check all hashes concurrently
        results = await asyncio.gather(*[check_one(h) for h in hashes])
        filtered = {r for r in results if r is not None}

        return filtered

    async def scan_once(self) -> int:
        """
        Perform a single store scan.

        Returns:
            Number of hashes found (after filtering)
        """
        import time

        self._scan_progress["active"] = True
        self._scan_progress["scanned"] = 0
        self._scan_progress["filtered"] = 0

        try:
            # scan_store_paths is synchronous but fast (just directory listing)
            all_hashes = scan_store_paths(limit=0)
            self._scan_progress["total"] = len(all_hashes)
            self._scan_progress["scanned"] = len(all_hashes)

            # Filter through NixpkgsFilteredStore if enabled
            if self._nixpkgs_filter:
                logger.info(f"Filtering {len(all_hashes)} hashes through cache.nixos.org...")
                filtered_hashes = await self._filter_hashes_batch(all_hashes)
                self._scan_progress["filtered"] = len(all_hashes) - len(filtered_hashes)
                logger.info(
                    f"Filtered: {len(filtered_hashes)}/{len(all_hashes)} hashes in cache.nixos.org"
                )
                self._available_hashes = filtered_hashes
            else:
                self._available_hashes = set(all_hashes)

            self._scan_progress["last_scan"] = time.time()
            logger.info(f"Store scan complete: {len(self._available_hashes)} paths available")
            return len(self._available_hashes)

        finally:
            self._scan_progress["active"] = False

    async def run_periodic_scan(self):
        """Run periodic store scanning in background."""
        self._running = True
        logger.info(f"Starting periodic store scan (interval={self.scan_interval}s)")

        while self._running:
            # Check if paused
            while self._scan_progress["paused"] and self._running:
                await asyncio.sleep(5)

            if not self._running:
                break

            try:
                await self.scan_once()
            except Exception as e:
                logger.warning(f"Store scan failed: {e}")

            await asyncio.sleep(self.scan_interval)

    async def run_periodic_delta_sync(self, interval: int = 300):
        """
        Run periodic delta sync with tracker.

        Args:
            interval: Seconds between syncs (default: 300 = 5 minutes)
        """
        if not self.tracker_url:
            logger.info("No tracker URL, skipping delta sync")
            return

        logger.info(f"Starting periodic delta sync (interval={interval}s)")

        while self._running:
            try:
                await self.delta_sync_packages()
            except Exception as e:
                logger.warning(f"Delta sync failed: {e}")

            await asyncio.sleep(interval)

    def stop(self):
        """Stop the periodic scanning."""
        self._running = False

    async def close(self):
        """Clean up resources."""
        self.stop()
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()


def get_client_ip(request: Request) -> str:
    """Get client IP, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


def is_localhost(request: Request) -> bool:
    """Check if request is from localhost."""
    client_ip = get_client_ip(request)
    return client_ip in ("127.0.0.1", "::1", "localhost")


# ========== HTTP Endpoints ==========

async def nix_cache_info(request: Request) -> Response:
    """Serve nix-cache-info for the local nix daemon."""
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    cache = await _local_store.cache_info()
    content = f"""StoreDir: {cache.storeDir}
WantMassQuery: {cache.wantMassQuery}
Priority: {_cache_priority}
"""
    return Response(content, media_type="text/plain")


async def narinfo_handler(request: Request) -> Response:
    """
    Handle narinfo requests from local nix daemon.

    First checks local store, then tries Iroh peers.
    """
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    hash_part = request.path_params.get("hash", "")
    if not hash_part:
        return Response("Bad request", status_code=400)

    # Remove .narinfo suffix if present
    if hash_part.endswith(".narinfo"):
        hash_part = hash_part[:-8]

    logger.debug(f"Narinfo request for {hash_part}")

    # Try local store first
    narinfo = await _local_store.narinfo(hash_part)
    if narinfo:
        logger.debug(f"Found locally: {narinfo.storePath}")
        # Sign the narinfo before returning
        signed_narinfo = sign_narinfo(narinfo)
        return Response(signed_narinfo.dump(), media_type="text/x-nix-narinfo")

    # Try Iroh peers
    if _iroh_node and _iroh_node._known_peers:
        result = await _iroh_node.fetch_narinfo_from_peers(hash_part, max_attempts=3)
        if result:
            narinfo_content, peer_id = result
            logger.info(f"Got narinfo from peer {peer_id[:16]}...")
            # Parse the narinfo and rewrite URL to route through our Iroh endpoint
            peer_narinfo = NarInfo.parse(narinfo_content)
            # Rewrite URL: original URL -> /iroh/nar/{peer_id}/{original_url}
            new_url = f"iroh/nar/{peer_id}/{peer_narinfo.url}"
            rewritten_narinfo = peer_narinfo._replace(url=new_url)
            return Response(rewritten_narinfo.dump(), media_type="text/x-nix-narinfo")

    return Response("Not found", status_code=404)


async def local_narinfo_handler(request: Request) -> Response:
    """Handle narinfo requests from other Iroh peers (via HTTP fallback)."""
    hash_part = request.path_params.get("hash", "")
    if hash_part.endswith(".narinfo"):
        hash_part = hash_part[:-8]

    narinfo = await _local_store.narinfo(hash_part)
    if narinfo:
        # Sign the narinfo before returning
        signed_narinfo = sign_narinfo(narinfo)
        return Response(signed_narinfo.dump(), media_type="text/x-nix-narinfo")
    return Response("Not found", status_code=404)


async def nar_handler(request: Request) -> Response:
    """Handle NAR requests - stream from local store."""
    nar_path = request.path_params.get("path", "")

    try:
        async def stream_nar():
            async for chunk in _local_store.nar(nar_path):
                yield chunk

        return StreamingResponse(stream_nar(), media_type="application/x-nix-nar")
    except FileNotFoundError:
        return Response("Not found", status_code=404)
    except Exception as e:
        logger.error(f"NAR error: {e}")
        return Response("Internal error", status_code=500)


async def iroh_nar_handler(request: Request) -> Response:
    """
    Fetch NAR from an Iroh peer.

    URL format: /iroh/nar/{peer_id}/{original_nar_path}
    """
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    peer_id = request.path_params.get("peer_id", "")
    nar_path = request.path_params.get("path", "")

    if not peer_id or not nar_path:
        return Response("Bad request", status_code=400)

    if not _iroh_node:
        return Response("Iroh node not available", status_code=503)

    logger.info(f"Fetching NAR from peer {peer_id[:16]}...: {nar_path}")

    try:
        async def stream_from_peer():
            async for chunk in _iroh_node.fetch_nar(peer_id, nar_path):
                yield chunk

        return StreamingResponse(stream_from_peer(), media_type="application/x-nix-nar")
    except asyncio.TimeoutError:
        logger.warning(f"Timeout fetching NAR from {peer_id[:16]}...")
        return Response("Peer timeout", status_code=504)
    except Exception as e:
        logger.error(f"Error fetching NAR from peer: {e}")
        return Response(f"Error: {e}", status_code=502)


async def status_handler(request: Request) -> Response:
    """Return node status."""
    status = {
        "mode": "iroh",
        "node_id": _iroh_node._node_id if _iroh_node else None,
        "known_peers": len(_iroh_node._known_peers) if _iroh_node else 0,
        "tracker_url": _iroh_node.tracker_url if _iroh_node else None,
    }

    if _iroh_node and _iroh_node.net:
        try:
            addr = await _iroh_node.get_node_addr()
            status["relay_url"] = addr.relay_url() if addr else None
            status["direct_addrs"] = addr.direct_addresses() if addr else []
        except:
            pass

    return JSONResponse(status)


async def peers_handler(request: Request) -> Response:
    """List known Iroh peers."""
    if not _iroh_node:
        return JSONResponse({"peers": []})

    peers = []
    for node_id in _iroh_node._known_peers:
        peers.append({
            "node_id": node_id,
            "node_id_short": node_id[:16] + "...",
        })

    return JSONResponse({"peers": peers, "count": len(peers)})


async def scan_status_handler(request: Request) -> Response:
    """Get current store scan progress."""
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized", "active": False})

    progress = _store_manager.get_scan_progress()
    progress["available_hashes"] = len(_store_manager.available_hashes)
    return JSONResponse(progress)


async def scan_pause_handler(request: Request) -> Response:
    """Pause store scanning. Localhost only."""
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized"}, status_code=404)
    _store_manager.pause()
    return JSONResponse({"status": "paused"})


async def scan_resume_handler(request: Request) -> Response:
    """Resume store scanning. Localhost only."""
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized"}, status_code=404)
    _store_manager.resume()
    return JSONResponse({"status": "resumed"})


async def dashboard_stats_handler(request: Request) -> Response:
    """Get dashboard statistics as JSON."""
    stats = {
        "mode": "iroh",
        "node_id": _iroh_node._node_id if _iroh_node else None,
        "known_peers": len(_iroh_node._known_peers) if _iroh_node else 0,
        "tracker_url": _iroh_node.tracker_url if _iroh_node else None,
        "available_hashes": len(_store_manager.available_hashes) if _store_manager else 0,
        "announced_hashes": len(_store_manager._last_announced_hashes) if _store_manager else 0,
    }

    # Add scan progress
    if _store_manager:
        progress = _store_manager.get_scan_progress()
        stats["scan"] = progress

    # Add Iroh node info
    if _iroh_node and _iroh_node.net:
        try:
            addr = await _iroh_node.get_node_addr()
            if addr:
                stats["relay_url"] = addr.relay_url()
                stats["direct_addrs"] = len(addr.direct_addresses())
        except:
            pass

    return JSONResponse(stats)


DASHBOARD_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Peerix Iroh Dashboard</title>
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
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            max-width: 1200px;
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
            font-size: 32px;
            font-weight: bold;
            color: #00d9ff;
        }
        .value.success { color: #00ff88; }
        .value.warning { color: #ffaa00; }
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
            background: #9b59b6;
            color: white;
        }
        .node-id {
            font-family: monospace;
            font-size: 11px;
            color: #00d9ff;
            word-break: break-all;
        }
        .ctrl-btn {
            background: #1a1a2e;
            border: 1px solid #333;
            color: #fff;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-right: 8px;
        }
        .ctrl-btn:hover { background: #2a2a3e; }
        .ctrl-btn.paused { color: #ff9500; border-color: #ff9500; }
        .ctrl-btn.running { color: #00ff88; border-color: #00ff88; }
        .peers-list {
            max-height: 200px;
            overflow-y: auto;
        }
        .peer-item {
            padding: 6px 0;
            border-bottom: 1px solid #0f3460;
            font-family: monospace;
            font-size: 11px;
            color: #888;
        }
        .peer-item:last-child { border-bottom: none; }
        .progress-bar {
            background: #0f3460;
            border-radius: 8px;
            height: 8px;
            margin-top: 8px;
            overflow: hidden;
        }
        .progress-bar .fill {
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            height: 100%;
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <h1>Peerix Dashboard <span class="mode-badge">Iroh</span></h1>
    <div class="grid">
        <div class="card">
            <h2>Node Status</h2>
            <div class="status-row">
                <span class="status-label">Node ID</span>
                <span class="node-id" id="node-id">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Relay</span>
                <span class="status-value" id="relay-url">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Direct Addrs</span>
                <span class="status-value" id="direct-addrs">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Tracker</span>
                <span class="status-value" id="tracker-url" style="font-size: 0.8em;">--</span>
            </div>
        </div>
        <div class="card">
            <h2>Peers</h2>
            <div class="value" id="peer-count">0</div>
            <div class="peers-list" id="peers-list"></div>
        </div>
        <div class="card">
            <h2>Store</h2>
            <div class="status-row">
                <span class="status-label">Available Paths</span>
                <span class="value" id="available-hashes">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Announced to Tracker</span>
                <span class="status-value" id="announced-hashes">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Last Scan</span>
                <span class="status-value" id="last-scan">--</span>
            </div>
            <div style="margin-top: 12px;">
                <button class="ctrl-btn" id="scan-toggle" onclick="toggleScan()">Pause Scan</button>
            </div>
        </div>
    </div>
    <script>
        let scanPaused = false;

        async function toggleScan() {
            const endpoint = scanPaused ? '/scan/resume' : '/scan/pause';
            await fetch(endpoint, { method: 'POST' });
        }

        function formatTime(ts) {
            if (!ts) return '--';
            const date = new Date(ts * 1000);
            return date.toLocaleTimeString();
        }

        async function update() {
            try {
                const [statsResp, peersResp] = await Promise.all([
                    fetch('/dashboard-stats'),
                    fetch('/peers')
                ]);

                const stats = await statsResp.json();
                const peersData = await peersResp.json();

                // Node info
                const nodeId = stats.node_id || '--';
                document.getElementById('node-id').textContent = nodeId.substring(0, 32) + '...';
                document.getElementById('node-id').title = nodeId;

                if (stats.relay_url) {
                    const relayHost = stats.relay_url.replace(/^https?:\\/\\//, '').split('/')[0];
                    document.getElementById('relay-url').textContent = relayHost;
                } else {
                    document.getElementById('relay-url').textContent = '--';
                }

                document.getElementById('direct-addrs').textContent = stats.direct_addrs || 0;
                document.getElementById('tracker-url').textContent = stats.tracker_url || 'Not configured';

                // Peers
                document.getElementById('peer-count').textContent = peersData.count || 0;
                const peersList = document.getElementById('peers-list');
                peersList.innerHTML = '';
                for (const peer of (peersData.peers || [])) {
                    const div = document.createElement('div');
                    div.className = 'peer-item';
                    div.textContent = peer.node_id_short;
                    div.title = peer.node_id;
                    peersList.appendChild(div);
                }

                // Store stats
                document.getElementById('available-hashes').textContent = stats.available_hashes || 0;
                document.getElementById('announced-hashes').textContent = stats.announced_hashes || 0;

                if (stats.scan) {
                    document.getElementById('last-scan').textContent = formatTime(stats.scan.last_scan);
                    scanPaused = stats.scan.paused;

                    const btn = document.getElementById('scan-toggle');
                    if (scanPaused) {
                        btn.textContent = 'Resume Scan';
                        btn.className = 'ctrl-btn paused';
                    } else {
                        btn.textContent = 'Pause Scan';
                        btn.className = 'ctrl-btn running';
                    }
                }

            } catch (e) {
                console.error('Update failed:', e);
            }
        }

        update();
        setInterval(update, 3000);
    </script>
</body>
</html>'''


async def dashboard_handler(request: Request) -> Response:
    """Serve the peerix dashboard HTML page."""
    return Response(content=DASHBOARD_HTML, media_type="text/html")


# ========== Application Setup ==========

def create_app() -> Starlette:
    """Create the Starlette application."""
    routes = [
        Route("/nix-cache-info", nix_cache_info),
        Route("/{hash}.narinfo", narinfo_handler),
        Route("/local/{hash}.narinfo", local_narinfo_handler),
        Route("/nar/{path:path}", nar_handler),
        Route("/iroh/nar/{peer_id}/{path:path}", iroh_nar_handler),
        Route("/status", status_handler),
        Route("/peers", peers_handler),
        Route("/scan-status", scan_status_handler),
        Route("/scan/pause", scan_pause_handler, methods=["POST"]),
        Route("/scan/resume", scan_resume_handler, methods=["POST"]),
        Route("/dashboard", dashboard_handler),
        Route("/dashboard-stats", dashboard_stats_handler),
    ]

    return Starlette(routes=routes)


async def run_server(
    port: int = 12304,
    tracker_url: str = None,
    peer_id: str = None,
    priority: int = 5,
    connect_timeout: float = 10.0,
    state_dir: t.Optional[Path] = None,
    private_key: t.Optional[str] = None,
    scan_interval: int = 3600,
    no_filter: bool = False,
    filter_mode: str = "nixpkgs",
    filter_patterns: t.Optional[t.List[str]] = None,
    no_verify: bool = False,
    upstream_cache: str = "https://cache.nixos.org",
):
    """
    Run the Iroh-based peerix server.

    Args:
        port: HTTP port to listen on
        tracker_url: Tracker URL for peer discovery
        peer_id: Human-readable peer ID
        priority: Cache priority (lower = higher priority)
        connect_timeout: Timeout for Iroh connections
        state_dir: Directory for persistent state (secret key)
        private_key: Path to nix secret key file for signing narinfo
        scan_interval: Seconds between store scans (0 to disable)
        no_filter: Disable filtering entirely
        filter_mode: Filter mode ("nixpkgs" or "rules")
        filter_patterns: Additional filter patterns for rules mode
        no_verify: Disable hash verification against upstream cache
        upstream_cache: Upstream cache URL for verification
    """
    global _iroh_node, _local_store, _cache_priority, _store_manager
    _cache_priority = priority
    _nixpkgs_filter = None  # Track for cleanup
    _verified_store = None  # Track for cleanup

    # Initialize signing if key provided
    if private_key:
        if init_signer(private_key):
            logger.info(f"Narinfo signing enabled with key: {private_key}")
        else:
            logger.warning(f"Failed to load signing key: {private_key}")
    else:
        # Try environment variable
        init_signer()

    # Use hostname as default peer_id
    if not peer_id:
        peer_id = socket.gethostname()

    logger.info(f"Starting Iroh peerix on port {port}")
    logger.info(f"Peer ID: {peer_id}")
    if tracker_url:
        logger.info(f"Tracker: {tracker_url}")

    # Start local store
    async with local_async() as store:
        # Build the store chain: local → verified → filtered
        serving_store: Store = store
        _nixpkgs_filter = None
        _verified_store = None

        # Apply verification if enabled
        if not no_verify:
            _verified_store = VerifiedStore(serving_store, upstream_cache=upstream_cache)
            serving_store = _verified_store
            logger.info(f"Hash verification enabled (upstream: {upstream_cache})")

        # Apply filtering if enabled
        if not no_filter:
            if filter_mode == "nixpkgs":
                _nixpkgs_filter = NixpkgsFilteredStore(serving_store, cache_url=upstream_cache)
                serving_store = _nixpkgs_filter
                logger.info("Using nixpkgs filter (only serving packages in cache.nixos.org)")
            else:  # "rules"
                serving_store = FilteredStore(
                    serving_store,
                    extra_patterns=filter_patterns or [],
                    use_defaults=True,
                )
                logger.info("Using rules-based filter")

        _local_store = serving_store
        logger.info("LocalStore ready")

        # Start Iroh node (use serving_store which has filtering/verification applied)
        _iroh_node = IrohNode(
            serving_store,
            tracker_url=tracker_url,
            peer_id=peer_id,
            connect_timeout=connect_timeout,
            state_dir=state_dir,
        )

        try:
            node_id = await _iroh_node.start()
            logger.info(f"Iroh node ID: {node_id}")

            # Get our address info
            addr = await _iroh_node.get_node_addr()
            logger.info(f"Relay: {addr.relay_url()}")
            logger.info(f"Direct addrs: {len(addr.direct_addresses())}")

            # Initialize store manager for tracking available packages
            if scan_interval > 0:
                _store_manager = StoreManager(
                    scan_interval=scan_interval,
                    tracker_url=tracker_url,
                    peer_id=peer_id,
                    nixpkgs_filter=_nixpkgs_filter,
                )
                # Do initial scan
                await _store_manager.scan_once()
                # Do initial delta sync
                if tracker_url:
                    await _store_manager.delta_sync_packages()
                logger.info(f"Store manager initialized (scan_interval={scan_interval}s)")

            # Create and run HTTP server
            app = create_app()

            # Import uvicorn for serving
            import uvicorn

            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)

            # Run server, tracker sync, store scanning, and delta sync concurrently
            async with asyncio.TaskGroup() as tg:
                tg.create_task(server.serve())
                if tracker_url:
                    tg.create_task(_iroh_node.run_tracker_sync())
                if _store_manager and scan_interval > 0:
                    tg.create_task(_store_manager.run_periodic_scan())
                    if tracker_url:
                        tg.create_task(_store_manager.run_periodic_delta_sync())

        except asyncio.CancelledError:
            logger.info("Shutting down...")
        finally:
            if _store_manager:
                await _store_manager.close()
                _store_manager = None
            if _nixpkgs_filter:
                await _nixpkgs_filter.close()
            if _verified_store:
                await _verified_store.close()
            await _iroh_node.stop()
            _iroh_node = None
            _local_store = None


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Iroh-based Peerix server")
    parser.add_argument("--port", "-p", type=int, default=12304,
                        help="HTTP port (default: 12304)")
    parser.add_argument("--tracker", "-t", type=str,
                        help="Tracker URL for peer discovery")
    parser.add_argument("--peer-id", type=str,
                        help="Human-readable peer ID (default: hostname)")
    parser.add_argument("--priority", type=int, default=5,
                        help="Cache priority (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--state-dir", type=str,
                        help="Directory for persistent state (default: /var/lib/peerix)")
    parser.add_argument("--private-key", type=str,
                        help="Path to nix secret key file for signing narinfo")
    parser.add_argument("--scan-interval", type=int, default=3600,
                        help="Seconds between store scans (0 to disable, default: 3600)")
    parser.add_argument("--no-filter", action="store_true",
                        help="Disable package filtering")
    parser.add_argument("--filter-mode", type=str, default="nixpkgs",
                        choices=["nixpkgs", "rules"],
                        help="Filter mode: nixpkgs (only cache.nixos.org packages) or rules (pattern-based)")
    parser.add_argument("--filter-pattern", type=str, action="append", dest="filter_patterns",
                        help="Additional filter pattern (can be specified multiple times)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable hash verification against upstream cache")
    parser.add_argument("--upstream-cache", type=str, default="https://cache.nixos.org",
                        help="Upstream cache URL for verification (default: https://cache.nixos.org)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    try:
        asyncio.run(run_server(
            port=args.port,
            tracker_url=args.tracker,
            peer_id=args.peer_id,
            priority=args.priority,
            connect_timeout=args.timeout,
            state_dir=Path(args.state_dir) if args.state_dir else None,
            private_key=args.private_key,
            scan_interval=args.scan_interval,
            no_filter=args.no_filter,
            filter_mode=args.filter_mode,
            filter_patterns=args.filter_patterns,
            no_verify=args.no_verify,
            upstream_cache=args.upstream_cache,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    main()
