"""
Asyncio-based Peerix application using Iroh P2P.

This is a cleaner implementation that replaces trio with asyncio
and uses Iroh for NAT-traversing P2P connectivity.
"""

import asyncio
import logging
import socket
import signal
import time
import typing as t
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse, JSONResponse
from starlette.routing import Route

import base64
import hashlib
import json
import os
import urllib.parse

import httpx


def compute_nar_hash(data: bytes) -> str:
    """
    Compute NarHash in Nix format: sha256:base32_encoded_hash

    Nix uses a custom base32 alphabet (excludes E, O, U, T).
    The encoding iterates from highest to lowest position, outputting forwards.
    """
    sha256_digest = hashlib.sha256(data).digest()
    # Nix base32 alphabet: excludes e, o, u, t (has i instead)
    NIX_BASE32_CHARS = "0123456789abcdfghijklmnpqrsvwxyz"

    n_bytes = len(sha256_digest)
    n_chars = (n_bytes * 8 - 1) // 5 + 1 if n_bytes > 0 else 0

    result = []
    # Iterate backwards from highest index, building string forwards
    for n in range(n_chars - 1, -1, -1):
        b = n * 5
        i = b // 8
        j = b % 8

        c = 0
        if i < n_bytes:
            c = sha256_digest[i] >> j
        if i + 1 < n_bytes:
            c |= sha256_digest[i + 1] << (8 - j)

        result.append(NIX_BASE32_CHARS[c & 0x1f])

    return f"sha256:{''.join(result)}"


def verify_nar_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify NAR data matches expected hash.

    Args:
        data: The NAR content bytes
        expected_hash: Expected hash in format "sha256:base32hash"

    Returns:
        True if hash matches, False otherwise
    """
    if not expected_hash.startswith("sha256:"):
        logger.warning(f"Unsupported hash format: {expected_hash}")
        return False

    computed = compute_nar_hash(data)
    return computed == expected_hash


class KalmanETA:
    """
    Kalman filter for ETA estimation based on processing rate.

    Tracks the rate of items processed per second and provides
    smoothed ETA estimates that adapt to changing conditions.
    """

    def __init__(self, process_noise: float = 0.1, measurement_noise: float = 0.5):
        self._rate = 0.0  # items per second
        self._variance = 1.0  # uncertainty
        self._process_noise = process_noise
        self._measurement_noise = measurement_noise
        self._last_update = None
        self._last_count = 0

    def update(self, processed: int, total: int) -> t.Optional[float]:
        """
        Update filter with new measurement and return ETA in seconds.

        Args:
            processed: Number of items processed so far
            total: Total number of items

        Returns:
            Estimated seconds remaining, or None if not enough data
        """
        now = time.time()

        if self._last_update is None:
            self._last_update = now
            self._last_count = processed
            return None

        dt = now - self._last_update
        if dt < 0.1:  # Too soon for meaningful update
            if self._rate > 0:
                remaining = total - processed
                return remaining / self._rate
            return None

        # Measure current rate
        items_done = processed - self._last_count
        measured_rate = items_done / dt if dt > 0 else 0

        # Kalman predict step
        self._variance += self._process_noise

        # Kalman update step
        if measured_rate > 0 or self._rate > 0:
            kalman_gain = self._variance / (self._variance + self._measurement_noise)
            self._rate = self._rate + kalman_gain * (measured_rate - self._rate)
            self._variance = (1 - kalman_gain) * self._variance

        self._last_update = now
        self._last_count = processed

        # Calculate ETA
        if self._rate > 0:
            remaining = total - processed
            return remaining / self._rate
        return None

    def format_eta(self, seconds: t.Optional[float]) -> str:
        """Format ETA as human-readable string."""
        if seconds is None:
            return "calculating..."
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"

from .local_asyncio import local_async, LocalStoreAsync
from .iroh_proto import IrohNode, NARINFO_PROTOCOL
from .store import NarInfo, Store
from .signing import init_signer, sign_narinfo
from .store_scanner import scan_store_paths
from .filtered import FilteredStore, NixpkgsFilteredStore
from .verified import VerifiedStore
from .lan_discovery import LANDiscovery

# Default path for persisting announced state
DEFAULT_STATE_FILE = "/var/lib/peerix/announced_state.json"
# Default path for caching filtered/skipped hashes
FILTER_CACHE_FILE = "/var/lib/peerix/filter_cache.json"
# Default path for dashboard stats persistence
DEFAULT_STATS_FILE = "/var/lib/peerix/stats.json"

# Version info - read from VERSION file
def _read_version() -> str:
    """Read version from VERSION file."""
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "0.0.4"  # Fallback

PEERIX_VERSION = _read_version()
# Git commit is passed via PEERIX_COMMIT env var at build time (from flake.nix)
PEERIX_COMMIT = os.environ.get("PEERIX_COMMIT", "dev")

logger = logging.getLogger("peerix.iroh_app")

# Global state
_iroh_node: t.Optional[IrohNode] = None
_lan_discovery: t.Optional[LANDiscovery] = None
_local_store: t.Optional[LocalStoreAsync] = None
_cache_priority: int = 5
_store_manager: t.Optional["StoreManager"] = None

# Cache for IP -> country code lookups
_ip_country_cache: t.Dict[str, str] = {}

# Track most requested derivations (hash -> {count, name})
_request_counts: t.Dict[str, t.Dict[str, t.Any]] = {}

# Track most served derivations to peers (hash -> {count, name})
_served_counts: t.Dict[str, t.Dict[str, t.Any]] = {}

# Activity log (recent checks and downloads)
_activity_log: t.List[t.Dict[str, t.Any]] = []
_activity_log_max = 50  # Keep last 50 entries

# Health tracking
_health_state: t.Dict[str, t.Any] = {
    "start_time": time.time(),
    "last_successful_operation": None,
    "last_store_scan": None,
    "last_tracker_sync": None,
    "errors_count": 0,
}

# Prometheus metrics tracking
_metrics: t.Dict[str, t.Any] = {
    "nars_served_total": 0,
    "narinfos_served_total": 0,
    "bytes_sent_total": 0,
    "bytes_received_total": 0,
    "cache_hits_total": 0,
    "cache_misses_total": 0,
    "peer_requests_total": 0,
    "request_duration_seconds": [],  # List of (duration, labels) for histogram
}
_metrics_lock = asyncio.Lock() if asyncio else None  # Will be set on first use

# Per-peer bandwidth tracking: peer_id -> {bytes_sent, bytes_received, last_seen, requests}
_peer_bandwidth: t.Dict[str, t.Dict[str, t.Any]] = {}


def _record_metric(name: str, value: float = 1, labels: t.Dict[str, str] = None):
    """Record a metric value."""
    global _metrics
    if name in _metrics:
        if isinstance(_metrics[name], (int, float)):
            _metrics[name] += value
        elif isinstance(_metrics[name], list):
            _metrics[name].append((value, labels or {}))
            # Keep only last 1000 for histogram
            if len(_metrics[name]) > 1000:
                _metrics[name] = _metrics[name][-1000:]


def _record_peer_bandwidth(peer_id: str, bytes_sent: int = 0, bytes_received: int = 0):
    """Record bandwidth for a specific peer."""
    global _peer_bandwidth
    short_id = peer_id[:16] if len(peer_id) > 16 else peer_id
    if short_id not in _peer_bandwidth:
        _peer_bandwidth[short_id] = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "requests": 0,
            "last_seen": time.time(),
            "full_id": peer_id,
        }
    _peer_bandwidth[short_id]["bytes_sent"] += bytes_sent
    _peer_bandwidth[short_id]["bytes_received"] += bytes_received
    _peer_bandwidth[short_id]["requests"] += 1
    _peer_bandwidth[short_id]["last_seen"] = time.time()


def _extract_drv_name(store_path: str) -> str:
    """Extract derivation name from store path like /nix/store/xxxxx-name."""
    if not store_path:
        return ""
    # Extract the part after hash: /nix/store/xxxxx-name -> name
    basename = store_path.split("/")[-1]
    # Remove hash prefix (32 chars + dash)
    if len(basename) > 33 and basename[32] == "-":
        return basename[33:]
    return basename


def _track_request(hash_part: str, name: str = ""):
    """Track a request for a derivation."""
    if hash_part not in _request_counts:
        _request_counts[hash_part] = {"count": 0, "name": name}
    _request_counts[hash_part]["count"] += 1
    # Update name if we have a better one
    if name and not _request_counts[hash_part]["name"]:
        _request_counts[hash_part]["name"] = name


def _track_served(hash_part: str, name: str = "", peer_id: str = ""):
    """Track a package served to a peer."""
    if hash_part not in _served_counts:
        _served_counts[hash_part] = {"count": 0, "name": name, "peers": {}}
    _served_counts[hash_part]["count"] += 1
    # Update name if we have a better one
    if name and not _served_counts[hash_part].get("name"):
        _served_counts[hash_part]["name"] = name
    # Track per-peer counts
    if peer_id:
        short_peer = peer_id[:16] if len(peer_id) > 16 else peer_id
        if "peers" not in _served_counts[hash_part]:
            _served_counts[hash_part]["peers"] = {}
        if short_peer not in _served_counts[hash_part]["peers"]:
            _served_counts[hash_part]["peers"][short_peer] = 0
        _served_counts[hash_part]["peers"][short_peer] += 1


def _log_activity(action: str, hash_part: str, source: str, success: bool, size: int = 0, name: str = "", peer_id: str = ""):
    """Log an activity (check or download)."""
    now = time.time()
    entry = {
        "time": now,
        "action": action,  # "check" or "download" or "served"
        "hash": hash_part,
        "name": name,  # Derivation name (e.g., "python-3.12")
        "source": source,  # "local", "peer:xxxx", "miss"
        "success": success,
        "size": size,
    }
    if peer_id:
        entry["peer_id"] = peer_id[:16] if len(peer_id) > 16 else peer_id
    _activity_log.append(entry)
    # Trim to max size
    while len(_activity_log) > _activity_log_max:
        _activity_log.pop(0)

    # Update health state
    if success:
        _health_state["last_successful_operation"] = now
    else:
        _health_state["errors_count"] = _health_state.get("errors_count", 0) + 1


def _load_stats(stats_file: str = DEFAULT_STATS_FILE) -> None:
    """Load persisted dashboard stats from disk."""
    global _request_counts, _served_counts, _activity_log, _peer_bandwidth, _metrics
    try:
        if os.path.exists(stats_file):
            with open(stats_file, "r") as f:
                data = json.load(f)
                _request_counts = data.get("request_counts", {})
                _served_counts = data.get("served_counts", {})
                _activity_log = data.get("activity_log", [])
                _peer_bandwidth = data.get("peer_bandwidth", {})
                # Load metrics counters (but not histograms)
                saved_metrics = data.get("metrics", {})
                for key in ["nars_served_total", "narinfos_served_total", "bytes_sent_total",
                            "bytes_received_total", "cache_hits_total", "cache_misses_total",
                            "peer_requests_total"]:
                    if key in saved_metrics:
                        _metrics[key] = saved_metrics[key]
                # Trim activity log to max size
                while len(_activity_log) > _activity_log_max:
                    _activity_log.pop(0)
                total_requests = sum(info["count"] for info in _request_counts.values())
                total_served = sum(info["count"] for info in _served_counts.values())
                logger.info(
                    f"Loaded stats: {total_requests} requests, {total_served} served, "
                    f"{len(_activity_log)} activity entries, {len(_peer_bandwidth)} peers tracked"
                )
    except Exception as e:
        logger.warning(f"Failed to load stats: {e}")


def _save_stats(stats_file: str = DEFAULT_STATS_FILE) -> None:
    """Save dashboard stats to disk."""
    try:
        os.makedirs(os.path.dirname(stats_file), exist_ok=True)
        # Save counters from metrics (not histograms)
        metrics_to_save = {
            key: _metrics[key] for key in [
                "nars_served_total", "narinfos_served_total", "bytes_sent_total",
                "bytes_received_total", "cache_hits_total", "cache_misses_total",
                "peer_requests_total"
            ]
        }
        with open(stats_file, "w") as f:
            json.dump({
                "request_counts": _request_counts,
                "served_counts": _served_counts,
                "activity_log": _activity_log,
                "peer_bandwidth": _peer_bandwidth,
                "metrics": metrics_to_save,
            }, f)
        logger.debug("Saved dashboard stats")
    except Exception as e:
        logger.warning(f"Failed to save stats: {e}")


async def _run_periodic_stats_save(interval: int = 60, stats_file: str = DEFAULT_STATS_FILE):
    """Periodically save dashboard stats to disk."""
    logger.info(f"Starting periodic stats save (interval={interval}s)")
    while True:
        await asyncio.sleep(interval)
        _save_stats(stats_file)


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
        filter_cache_file: str = FILTER_CACHE_FILE,
        nixpkgs_filter: t.Optional["NixpkgsFilteredStore"] = None,
        filter_concurrency: int = 10,
    ):
        self.scan_interval = scan_interval
        self.tracker_url = tracker_url.rstrip("/") if tracker_url else None
        self.peer_id = peer_id
        self._state_file = state_file
        self._filter_cache_file = filter_cache_file
        self._nixpkgs_filter = nixpkgs_filter
        self._filter_concurrency = filter_concurrency
        self._available_hashes: t.Set[str] = set()
        self._last_announced_hashes: t.Set[str] = set()
        self._cached_filtered_hashes: t.Set[str] = set()  # Hashes known to pass filter
        self._cached_skipped_hashes: t.Set[str] = set()   # Hashes known to fail filter
        self._total_store_paths: int = 0  # Total paths in /nix/store
        self._scan_progress: t.Dict[str, t.Any] = {
            "active": False,
            "total": 0,
            "scanned": 0,
            "filtered": 0,
            "filter_checked": 0,
            "filter_to_check": 0,
            "filter_found": 0,
            "filter_skipped": 0,
            "filter_eta": None,
            "last_scan": None,
            "paused": False,
        }
        self._running = False
        self._http_client: t.Optional[httpx.AsyncClient] = None

        # Load previously announced state and filter cache
        self._load_announced_state()
        self._load_filter_cache()

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

    def _load_filter_cache(self) -> None:
        """Load cached filtered and skipped hashes from disk."""
        try:
            if os.path.exists(self._filter_cache_file):
                with open(self._filter_cache_file, "r") as f:
                    data = json.load(f)
                    self._cached_filtered_hashes = set(data.get("filtered", []))
                    self._cached_skipped_hashes = set(data.get("skipped", []))
                    logger.info(
                        f"Loaded filter cache: {len(self._cached_filtered_hashes)} filtered, "
                        f"{len(self._cached_skipped_hashes)} skipped"
                    )
        except Exception as e:
            logger.warning(f"Failed to load filter cache: {e}")
            self._cached_filtered_hashes = set()
            self._cached_skipped_hashes = set()

    def _save_filter_cache(self) -> None:
        """Save filtered and skipped hashes cache to disk."""
        try:
            os.makedirs(os.path.dirname(self._filter_cache_file), exist_ok=True)
            with open(self._filter_cache_file, "w") as f:
                json.dump({
                    "filtered": list(self._cached_filtered_hashes),
                    "skipped": list(self._cached_skipped_hashes)
                }, f)
            logger.debug(
                f"Saved filter cache: {len(self._cached_filtered_hashes)} filtered, "
                f"{len(self._cached_skipped_hashes)} skipped"
            )
        except Exception as e:
            logger.warning(f"Failed to save filter cache: {e}")

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
        progress["total_store_paths"] = self._total_store_paths
        progress["cached_filtered"] = len(self._cached_filtered_hashes)
        progress["cached_skipped"] = len(self._cached_skipped_hashes)
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
        Uses semaphore for concurrency control with Kalman ETA.
        Adds hashes to _available_hashes incrementally as they pass.
        Uses cached filtered/skipped hashes to skip HTTP checks.
        """
        if not self._nixpkgs_filter:
            return set(hashes)

        filtered: t.Set[str] = set()
        semaphore = asyncio.Semaphore(self._filter_concurrency)
        checked = 0
        found = 0
        skipped = 0
        cache_hits_filtered = 0
        cache_hits_skipped = 0
        lock = asyncio.Lock()
        last_sync_count = 0
        last_cache_save = 0

        # Separate cached vs uncached hashes
        hashes_to_check: t.List[str] = []
        for hsh in hashes:
            if hsh in self._cached_filtered_hashes:
                # Already known to pass filter
                filtered.add(hsh)
                self._available_hashes.add(hsh)
                cache_hits_filtered += 1
            elif hsh in self._cached_skipped_hashes:
                # Already known to fail filter - skip
                cache_hits_skipped += 1
            else:
                hashes_to_check.append(hsh)

        total = len(hashes_to_check)
        eta = KalmanETA()

        # Store the number of hashes that need actual HTTP checking
        self._scan_progress["filter_to_check"] = total

        total_cache_hits = cache_hits_filtered + cache_hits_skipped
        if total_cache_hits > 0:
            logger.info(
                f"Filter cache: {cache_hits_filtered} filtered, "
                f"{cache_hits_skipped} skipped, {total} need checking"
            )
            self._scan_progress["filter_found"] = cache_hits_filtered
            self._scan_progress["filter_skipped"] = cache_hits_skipped

        if total == 0:
            # All from cache
            self._scan_progress["filter_checked"] = 0
            return filtered

        async def check_one(hsh: str) -> t.Optional[str]:
            nonlocal checked, found, skipped, last_sync_count, last_cache_save
            async with semaphore:
                exists = False
                try:
                    exists = await self._nixpkgs_filter._check_nixpkgs(hsh)
                    if exists:
                        return hsh
                    return None
                finally:
                    async with lock:
                        checked += 1
                        if exists:
                            found += 1
                            # Add to available hashes immediately
                            self._available_hashes.add(hsh)
                            # Add to filtered cache
                            self._cached_filtered_hashes.add(hsh)
                        else:
                            skipped += 1
                            # Add to skipped cache
                            self._cached_skipped_hashes.add(hsh)

                        # Update progress
                        self._scan_progress["filter_checked"] = checked
                        self._scan_progress["filter_found"] = cache_hits_filtered + found
                        self._scan_progress["filter_skipped"] = cache_hits_skipped + skipped

                        # Log with ETA every 1000 items
                        if checked % 1000 == 0:
                            eta_secs = eta.update(checked, total)
                            eta_str = eta.format_eta(eta_secs)
                            pct = (checked / total) * 100
                            logger.info(
                                f"Filtering: {checked}/{total} ({pct:.1f}%) "
                                f"found={found} skipped={skipped} ETA={eta_str}"
                            )
                            self._scan_progress["filter_eta"] = eta_str

                        # Incremental delta sync every 5000 new hashes found
                        if self.tracker_url and (found - last_sync_count) >= 5000:
                            last_sync_count = found
                            # Schedule sync without blocking
                            asyncio.create_task(self._incremental_sync())

                        # Save cache every 10000 newly checked hashes
                        if checked - last_cache_save >= 10000:
                            last_cache_save = checked
                            self._save_filter_cache()

        # Check uncached hashes concurrently
        results = await asyncio.gather(*[check_one(h) for h in hashes_to_check])
        newly_filtered = {r for r in results if r is not None}
        filtered.update(newly_filtered)

        # Save cache at the end
        self._save_filter_cache()

        return filtered

    async def _incremental_sync(self):
        """Do an incremental delta sync during filtering."""
        try:
            await self.delta_sync_packages()
            logger.info(f"Incremental sync: {len(self._available_hashes)} hashes available")
        except Exception as e:
            logger.warning(f"Incremental sync failed: {e}")

    async def scan_once(self) -> int:
        """
        Perform a single store scan.

        Returns:
            Number of hashes found (after filtering)
        """
        self._scan_progress["active"] = True
        self._scan_progress["scanned"] = 0
        self._scan_progress["filtered"] = 0
        self._scan_progress["filter_checked"] = 0
        self._scan_progress["filter_to_check"] = 0
        self._scan_progress["filter_found"] = 0
        self._scan_progress["filter_skipped"] = 0
        self._scan_progress["filter_eta"] = None

        # Clear available hashes for fresh scan (they get added incrementally during filtering)
        self._available_hashes.clear()

        try:
            # scan_store_paths is synchronous but fast (just directory listing)
            all_hashes = scan_store_paths(limit=0)
            self._total_store_paths = len(all_hashes)
            self._scan_progress["total"] = len(all_hashes)
            self._scan_progress["scanned"] = len(all_hashes)

            # Filter through NixpkgsFilteredStore if enabled
            if self._nixpkgs_filter:
                logger.info(f"Filtering {len(all_hashes)} hashes through cache.nixos.org...")
                # Hashes are added to _available_hashes incrementally during filtering
                filtered_hashes = await self._filter_hashes_batch(all_hashes)
                self._scan_progress["filtered"] = len(all_hashes) - len(filtered_hashes)
                logger.info(
                    f"Filtered: {len(filtered_hashes)}/{len(all_hashes)} hashes in cache.nixos.org"
                )
                # _available_hashes already populated incrementally
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
        first_run = True

        while self._running:
            # Check if paused
            while self._scan_progress["paused"] and self._running:
                await asyncio.sleep(5)

            if not self._running:
                break

            try:
                await self.scan_once()
                # Delta sync after each scan
                if self.tracker_url:
                    await self.delta_sync_packages()
            except Exception as e:
                logger.warning(f"Store scan failed: {e}")

            # First scan runs immediately, then wait for interval
            if first_run:
                first_run = False
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

    start_time = time.time()
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
        drv_name = _extract_drv_name(narinfo.storePath)
        _track_request(hash_part, drv_name)
        _log_activity("check", hash_part, "local", True, name=drv_name)
        _record_metric("cache_hits_total")
        _record_metric("request_duration_seconds", time.time() - start_time, {"type": "local"})
        # Sign the narinfo before returning
        signed_narinfo = sign_narinfo(narinfo)
        return Response(signed_narinfo.dump(), media_type="text/x-nix-narinfo")

    # Try Iroh peers
    if _iroh_node and _iroh_node._known_peers:
        _record_metric("peer_requests_total")
        result = await _iroh_node.fetch_narinfo_from_peers(hash_part, max_attempts=3)
        if result:
            narinfo_content, peer_id = result
            logger.info(f"Got narinfo from peer {peer_id[:16]}...")
            # Parse the narinfo and rewrite URL to route through our Iroh endpoint
            peer_narinfo = NarInfo.parse(narinfo_content)
            drv_name = _extract_drv_name(peer_narinfo.storePath)
            _track_request(hash_part, drv_name)
            _log_activity("check", hash_part, f"peer:{peer_id[:8]}", True, name=drv_name)
            _record_metric("request_duration_seconds", time.time() - start_time, {"type": "peer"})
            # Rewrite URL: original URL -> /iroh/nar/{peer_id}/{nar_hash_urlsafe}/{original_url}
            # Include NarHash in URL for verification after download (security)
            nar_hash_urlsafe = urllib.parse.quote(peer_narinfo.narHash, safe='')
            new_url = f"iroh/nar/{peer_id}/{nar_hash_urlsafe}/{peer_narinfo.url}"
            rewritten_narinfo = peer_narinfo._replace(url=new_url)
            return Response(rewritten_narinfo.dump(), media_type="text/x-nix-narinfo")

    # Try LAN discovery (UDP broadcast)
    if _lan_discovery:
        result = await _lan_discovery.discover_narinfo(hash_part)
        if result:
            narinfo_content, peer_addr, peer_port = result
            logger.info(f"Got narinfo from LAN peer {peer_addr}:{peer_port}")
            peer_narinfo = NarInfo.parse(narinfo_content)
            drv_name = _extract_drv_name(peer_narinfo.storePath)
            _track_request(hash_part, drv_name)
            _log_activity("check", hash_part, f"lan:{peer_addr}", True, name=drv_name)
            _record_metric("request_duration_seconds", time.time() - start_time, {"type": "lan"})
            # Rewrite URL to proxy through LAN peer
            new_url = f"lan/nar/{peer_addr}/{peer_port}/{peer_narinfo.url}"
            rewritten_narinfo = peer_narinfo._replace(url=new_url)
            return Response(rewritten_narinfo.dump(), media_type="text/x-nix-narinfo")

    _track_request(hash_part)
    _log_activity("check", hash_part, "miss", False)
    _record_metric("cache_misses_total")
    _record_metric("request_duration_seconds", time.time() - start_time, {"type": "miss"})
    return Response("Not found", status_code=404)


async def local_narinfo_handler(request: Request) -> Response:
    """Handle narinfo requests from other Iroh peers (via HTTP fallback)."""
    hash_part = request.path_params.get("hash", "")
    if hash_part.endswith(".narinfo"):
        hash_part = hash_part[:-8]

    narinfo = await _local_store.narinfo(hash_part)
    if narinfo:
        # Track as served to peer
        drv_name = _extract_drv_name(narinfo.storePath)
        _track_served(hash_part, drv_name)
        _record_metric("narinfos_served_total")
        # Sign the narinfo before returning
        signed_narinfo = sign_narinfo(narinfo)
        return Response(signed_narinfo.dump(), media_type="text/x-nix-narinfo")
    return Response("Not found", status_code=404)


async def nar_handler(request: Request) -> Response:
    """Handle NAR requests - stream from local store."""
    nar_path = request.path_params.get("path", "")
    # Extract hash and name from path (format: nar/xxxxx-name.nar or similar)
    filename = nar_path.split("/")[-1] if nar_path else ""
    hash_part = filename.split("-")[0] if filename else "?"
    # Extract name: xxxxx-foo-bar.nar -> foo-bar
    drv_name = ""
    if "-" in filename:
        name_part = filename.split("-", 1)[1]  # Everything after first dash
        drv_name = name_part.rsplit(".", 1)[0] if "." in name_part else name_part

    try:
        async def stream_nar():
            total_bytes = 0
            async for chunk in _local_store.nar(nar_path):
                total_bytes += len(chunk)
                yield chunk
            _log_activity("download", hash_part, "local", True, total_bytes, name=drv_name)
            _record_metric("nars_served_total")
            _record_metric("bytes_sent_total", total_bytes)

        return StreamingResponse(stream_nar(), media_type="application/x-nix-nar")
    except FileNotFoundError:
        _log_activity("download", hash_part, "local", False, name=drv_name)
        return Response("Not found", status_code=404)
    except Exception as e:
        logger.error(f"NAR error: {e}")
        _log_activity("download", hash_part, "local", False, name=drv_name)
        return Response("Internal error", status_code=500)


async def iroh_nar_handler(request: Request) -> Response:
    """
    Fetch NAR from an Iroh peer with hash verification.

    URL format: /iroh/nar/{peer_id}/{expected_nar_hash}/{original_nar_path}

    Uses pre-buffering with retry to ensure reliable transfers.
    The entire NAR is fetched before starting the HTTP response,
    allowing retries on transient iroh errors.

    Security: After download, verifies the NAR content matches the expected
    NarHash from the narinfo. This prevents malicious peers from serving
    arbitrary content with valid-looking narinfo.
    """
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    peer_id = request.path_params.get("peer_id", "")
    expected_nar_hash = request.path_params.get("nar_hash", "")
    nar_path = request.path_params.get("path", "")

    if not peer_id or not nar_path:
        return Response("Bad request", status_code=400)

    # Decode URL-encoded NarHash (e.g., sha256%3Axxxxx -> sha256:xxxxx)
    expected_nar_hash = urllib.parse.unquote(expected_nar_hash)

    if not _iroh_node:
        return Response("Iroh node not available", status_code=503)

    logger.info(f"Fetching NAR from peer {peer_id[:16]}...: {nar_path}")
    # Extract hash and name from path (base64-encoded store path)
    hash_part = "?"
    drv_name = ""
    try:
        # Remove .nar suffix if present
        path_to_decode = nar_path
        if path_to_decode.endswith(".nar"):
            path_to_decode = path_to_decode[:-4]
        # Decode base64 (handle URL-safe encoding)
        decoded = base64.b64decode(path_to_decode.replace("_", "/")).decode("utf-8")
        # Extract from /nix/store/xxxxx-name
        basename = decoded.split("/")[-1]
        hash_part = basename[:32] if len(basename) > 32 else basename
        if len(basename) > 33 and basename[32] == "-":
            drv_name = basename[33:]
    except Exception as e:
        logger.debug(f"Failed to decode nar_path: {e}")

    try:
        # Pre-buffer the entire NAR with retry support
        nar_data = await _iroh_node.fetch_nar_buffered(peer_id, nar_path, max_retries=3)
        logger.info(f"NAR buffered: {len(nar_data)} bytes for {nar_path}")

        # Security: Verify NAR content matches expected hash from narinfo
        # This prevents malicious peers from serving arbitrary content
        if expected_nar_hash:
            if not verify_nar_hash(nar_data, expected_nar_hash):
                computed_hash = compute_nar_hash(nar_data)
                # Enhanced diagnostic logging for hash mismatches
                logger.error(
                    f"NAR hash mismatch from peer {peer_id[:16]}! "
                    f"Expected: {expected_nar_hash}, Got: {computed_hash}, "
                    f"Size: {len(nar_data)} bytes, "
                    f"First16: {nar_data[:16].hex() if len(nar_data) >= 16 else nar_data.hex()}, "
                    f"Last16: {nar_data[-16:].hex() if len(nar_data) >= 16 else 'N/A'}"
                )
                _log_activity("download", hash_part, f"peer:{peer_id[:8]}", False, len(nar_data), name=drv_name)
                return Response(
                    f"NAR hash verification failed: content from peer does not match expected hash",
                    status_code=502
                )
            logger.debug(f"NAR hash verified: {expected_nar_hash}")
        else:
            # No hash provided - legacy URL format, log warning
            logger.warning(f"No expected hash for NAR verification (legacy URL format)")

        _log_activity("download", hash_part, f"peer:{peer_id[:8]}", True, len(nar_data), name=drv_name)
        _record_metric("bytes_received_total", len(nar_data))
        _record_peer_bandwidth(peer_id, bytes_received=len(nar_data))

        # Stream the buffered data to the HTTP response
        async def stream_buffered():
            chunk_size = 65536
            for i in range(0, len(nar_data), chunk_size):
                yield nar_data[i:i + chunk_size]

        return StreamingResponse(
            stream_buffered(),
            media_type="application/x-nix-nar",
            headers={"Content-Length": str(len(nar_data))}
        )

    except Exception as e:
        logger.error(f"Failed to fetch NAR from peer {peer_id[:16]}: {e}")
        _log_activity("download", hash_part, f"peer:{peer_id[:8]}", False, 0, name=drv_name)
        return Response(f"Failed to fetch NAR: {e}", status_code=502)


async def metrics_handler(request: Request) -> Response:
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus text format.
    """
    lines = []
    uptime = time.time() - _health_state["start_time"]

    # Basic info
    lines.append(f"# HELP peerix_up Peerix is running")
    lines.append(f"# TYPE peerix_up gauge")
    lines.append(f"peerix_up 1")

    lines.append(f"# HELP peerix_uptime_seconds Uptime in seconds")
    lines.append(f"# TYPE peerix_uptime_seconds gauge")
    lines.append(f"peerix_uptime_seconds {uptime:.0f}")

    # Peers
    peer_count = len(_iroh_node._known_peers) if _iroh_node else 0
    lines.append(f"# HELP peerix_peers_connected Number of connected peers")
    lines.append(f"# TYPE peerix_peers_connected gauge")
    lines.append(f"peerix_peers_connected {peer_count}")

    # Store
    available = len(_store_manager.available_hashes) if _store_manager else 0
    lines.append(f"# HELP peerix_available_hashes Number of available store path hashes")
    lines.append(f"# TYPE peerix_available_hashes gauge")
    lines.append(f"peerix_available_hashes {available}")

    # Counters
    lines.append(f"# HELP peerix_nars_served_total Total NARs served to peers")
    lines.append(f"# TYPE peerix_nars_served_total counter")
    lines.append(f"peerix_nars_served_total {_metrics['nars_served_total']}")

    lines.append(f"# HELP peerix_narinfos_served_total Total narinfos served")
    lines.append(f"# TYPE peerix_narinfos_served_total counter")
    lines.append(f"peerix_narinfos_served_total {_metrics['narinfos_served_total']}")

    lines.append(f"# HELP peerix_bytes_sent_total Total bytes sent to peers")
    lines.append(f"# TYPE peerix_bytes_sent_total counter")
    lines.append(f"peerix_bytes_sent_total {_metrics['bytes_sent_total']}")

    lines.append(f"# HELP peerix_bytes_received_total Total bytes received from peers")
    lines.append(f"# TYPE peerix_bytes_received_total counter")
    lines.append(f"peerix_bytes_received_total {_metrics['bytes_received_total']}")

    lines.append(f"# HELP peerix_cache_hits_total Cache hits (found locally)")
    lines.append(f"# TYPE peerix_cache_hits_total counter")
    lines.append(f"peerix_cache_hits_total {_metrics['cache_hits_total']}")

    lines.append(f"# HELP peerix_cache_misses_total Cache misses (not found)")
    lines.append(f"# TYPE peerix_cache_misses_total counter")
    lines.append(f"peerix_cache_misses_total {_metrics['cache_misses_total']}")

    lines.append(f"# HELP peerix_peer_requests_total Requests forwarded to peers")
    lines.append(f"# TYPE peerix_peer_requests_total counter")
    lines.append(f"peerix_peer_requests_total {_metrics['peer_requests_total']}")

    lines.append(f"# HELP peerix_errors_total Total errors")
    lines.append(f"# TYPE peerix_errors_total counter")
    lines.append(f"peerix_errors_total {_health_state.get('errors_count', 0)}")

    # Request counts from tracking
    total_requests = sum(info["count"] for info in _request_counts.values())
    total_served = sum(info["count"] for info in _served_counts.values())
    lines.append(f"# HELP peerix_requests_total Total narinfo requests received")
    lines.append(f"# TYPE peerix_requests_total counter")
    lines.append(f"peerix_requests_total {total_requests}")

    lines.append(f"# HELP peerix_served_total Total packages served to peers")
    lines.append(f"# TYPE peerix_served_total counter")
    lines.append(f"peerix_served_total {total_served}")

    # Request duration histogram (simplified - just percentiles)
    durations = _metrics.get("request_duration_seconds", [])
    if durations:
        sorted_d = sorted(d[0] for d in durations)
        p50 = sorted_d[len(sorted_d) // 2] if sorted_d else 0
        p90 = sorted_d[int(len(sorted_d) * 0.9)] if len(sorted_d) > 1 else p50
        p99 = sorted_d[int(len(sorted_d) * 0.99)] if len(sorted_d) > 10 else p90
        lines.append(f"# HELP peerix_request_duration_seconds Request duration")
        lines.append(f"# TYPE peerix_request_duration_seconds summary")
        lines.append(f'peerix_request_duration_seconds{{quantile="0.5"}} {p50:.4f}')
        lines.append(f'peerix_request_duration_seconds{{quantile="0.9"}} {p90:.4f}')
        lines.append(f'peerix_request_duration_seconds{{quantile="0.99"}} {p99:.4f}')
        lines.append(f"peerix_request_duration_seconds_count {len(durations)}")
        lines.append(f"peerix_request_duration_seconds_sum {sum(d[0] for d in durations):.4f}")

    content = "\n".join(lines) + "\n"
    return Response(content, media_type="text/plain; version=0.0.4; charset=utf-8")


async def health_handler(request: Request) -> Response:
    """
    Health check endpoint for systemd watchdog and load balancers.

    Returns 200 if healthy, 503 if degraded.
    Checks: local store, iroh node, recent activity.
    """
    checks = {
        "local_store": False,
        "iroh_node": False,
        "store_manager": False,
    }
    healthy = True
    details = []

    # Check local store
    if _local_store:
        try:
            cache = await _local_store.cache_info()
            checks["local_store"] = bool(cache and cache.storeDir)
        except Exception as e:
            details.append(f"local_store error: {e}")
            healthy = False
    else:
        details.append("local_store not initialized")
        healthy = False

    # Check Iroh node
    if _iroh_node and _iroh_node._node_id:
        checks["iroh_node"] = True
    else:
        details.append("iroh_node not ready")
        # Not critical if running in LAN mode
        if _iroh_node is not None:
            healthy = False

    # Check store manager
    if _store_manager:
        checks["store_manager"] = True
        progress = _store_manager.get_scan_progress()
        if progress.get("last_scan"):
            _health_state["last_store_scan"] = progress["last_scan"]

    # Build response
    uptime = time.time() - _health_state["start_time"]
    response = {
        "status": "healthy" if healthy else "degraded",
        "uptime_seconds": int(uptime),
        "checks": checks,
        "peers": len(_iroh_node._known_peers) if _iroh_node else 0,
        "available_hashes": len(_store_manager.available_hashes) if _store_manager else 0,
        "last_successful_operation": _health_state.get("last_successful_operation"),
        "errors_count": _health_state.get("errors_count", 0),
    }

    if details:
        response["details"] = details

    status_code = 200 if healthy else 503
    return JSONResponse(response, status_code=status_code)


async def lan_nar_handler(request: Request) -> Response:
    """
    Proxy NAR from a LAN peer.

    URL format: /lan/nar/{peer_addr}/{peer_port}/{original_nar_path}
    """
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    peer_addr = request.path_params.get("peer_addr", "")
    peer_port = request.path_params.get("peer_port", "")
    nar_path = request.path_params.get("path", "")

    if not peer_addr or not peer_port or not nar_path:
        return Response("Bad request", status_code=400)

    # Construct URL to LAN peer
    nar_url = f"http://{peer_addr}:{peer_port}/{nar_path}"
    logger.info(f"Fetching NAR from LAN peer: {nar_url}")

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("GET", nar_url) as resp:
                if resp.status_code != 200:
                    return Response(f"LAN peer returned {resp.status_code}", status_code=502)

                async def stream_response():
                    total = 0
                    async for chunk in resp.aiter_bytes(65536):
                        total += len(chunk)
                        yield chunk
                    _record_metric("bytes_received_total", total)
                    _log_activity("download", "?", f"lan:{peer_addr}", True, total)

                return StreamingResponse(
                    stream_response(),
                    media_type="application/x-nix-nar"
                )

    except Exception as e:
        logger.error(f"Failed to fetch from LAN peer {peer_addr}: {e}")
        return Response(f"LAN fetch failed: {e}", status_code=502)


async def status_handler(request: Request) -> Response:
    """Return node status."""
    mode = "iroh" if _iroh_node else ("lan" if _lan_discovery else "unknown")
    status = {
        "mode": mode,
        "node_id": _iroh_node._node_id if _iroh_node else None,
        "known_peers": len(_iroh_node._known_peers) if _iroh_node else 0,
        "tracker_url": _iroh_node.tracker_url if _iroh_node else None,
        "lan_discovery": _lan_discovery is not None,
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
    """List known Iroh peers with IP addresses and country flags."""
    global _ip_country_cache

    if not _iroh_node:
        return JSONResponse({"peers": [], "count": 0})

    peers = []
    ips_to_lookup = []
    tracker_peers = {}

    # Fetch peer data from tracker (has real public IPs)
    if _iroh_node.tracker_url:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{_iroh_node.tracker_url}/iroh/peers")
                if resp.status_code == 200:
                    for p in resp.json().get("peers", []):
                        tracker_peers[p["node_id"]] = p.get("addr")  # Real public IP
        except Exception as e:
            logger.debug(f"Failed to fetch tracker peers: {e}")

    for node_id, node_addr in _iroh_node._known_peers.items():
        # Get real public IP from tracker
        public_ip = tracker_peers.get(node_id)

        # Extract direct address from Iroh (might be Tailscale, local, etc.)
        direct_ip = None
        try:
            direct_addrs = node_addr.direct_addresses()
            if direct_addrs:
                addr_str = str(direct_addrs[0])
                if addr_str.startswith("["):
                    direct_ip = addr_str.split("]:")[0][1:]
                else:
                    direct_ip = addr_str.rsplit(":", 1)[0]
        except Exception:
            pass

        # Use public IP for geo lookup (more accurate)
        geo_ip = public_ip or direct_ip

        # Get reputation data for this peer
        rep = _iroh_node._get_peer_reputation(node_id)
        peer_info = {
            "node_id": node_id,
            "node_id_short": node_id[:16] + "...",
            "public_ip": public_ip,      # Real IP from tracker
            "direct_ip": direct_ip,       # Direct connection IP (may be VPN/Tailscale)
            "country": _ip_country_cache.get(geo_ip, "") if geo_ip else "",
            "reputation": {
                "score": round(rep.score(), 2),
                "success_rate": round(rep.success_rate * 100, 1),
                "total_requests": rep.total_requests,
                "successful": rep.successful_requests,
                "failed": rep.failed_requests,
                "avg_latency_ms": round(rep.avg_latency_ms, 1),
                "bytes_transferred": rep.total_bytes_transferred,
                "backed_off": rep.is_backed_off(),
            },
        }
        peers.append(peer_info)

        # Collect IPs for geo lookup (prefer public IP)
        if geo_ip and geo_ip not in _ip_country_cache:
            ips_to_lookup.append(geo_ip)

    # Batch lookup country codes using ip-api.com
    if ips_to_lookup:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    "http://ip-api.com/batch?fields=query,countryCode",
                    json=ips_to_lookup,
                )
                if resp.status_code == 200:
                    for item in resp.json():
                        _ip_country_cache[item.get("query", "")] = item.get("countryCode", "")
                    # Update peer countries after lookup
                    for peer in peers:
                        geo_ip = peer["public_ip"] or peer["direct_ip"]
                        if geo_ip and not peer["country"]:
                            peer["country"] = _ip_country_cache.get(geo_ip, "")
        except Exception as e:
            logger.debug(f"Geo lookup failed: {e}")

    return JSONResponse({"peers": peers, "count": len(peers)})


async def scan_status_handler(request: Request) -> Response:
    """Get current store scan progress."""
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized", "active": False})

    progress = _store_manager.get_scan_progress()
    progress["available_hashes"] = len(_store_manager.available_hashes)
    return JSONResponse(progress)


async def scan_pause_handler(request: Request) -> Response:
    """Pause store scanning."""
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized"}, status_code=404)
    _store_manager.pause()
    return JSONResponse({"status": "paused"})


async def scan_resume_handler(request: Request) -> Response:
    """Resume store scanning."""
    if not _store_manager:
        return JSONResponse({"error": "Store manager not initialized"}, status_code=404)
    _store_manager.resume()
    return JSONResponse({"status": "resumed"})


async def dashboard_stats_handler(request: Request) -> Response:
    """Get dashboard statistics as JSON."""
    stats = {
        "mode": "iroh",
        "version": f"{PEERIX_VERSION}+{PEERIX_COMMIT}",
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

    # Add most requested derivations (top 10)
    sorted_requests = sorted(
        _request_counts.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )[:10]
    stats["most_requested"] = [
        {"hash": h, "count": info["count"], "name": info.get("name", "")}
        for h, info in sorted_requests
    ]
    stats["total_requests"] = sum(info["count"] for info in _request_counts.values())

    # Add most served derivations to peers (top 10)
    sorted_served = sorted(
        _served_counts.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )[:10]
    stats["most_served"] = [
        {"hash": h, "count": info["count"], "name": info.get("name", ""), "peers": info.get("peers", {})}
        for h, info in sorted_served
    ]
    stats["total_served"] = sum(info["count"] for info in _served_counts.values())

    # Add activity log (most recent first)
    stats["activity"] = list(reversed(_activity_log[-20:]))

    # Add per-peer bandwidth stats (top 10 by total bytes)
    sorted_peers = sorted(
        _peer_bandwidth.items(),
        key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"],
        reverse=True
    )[:10]
    stats["peer_bandwidth"] = [
        {
            "peer_id": pid,
            "bytes_sent": info["bytes_sent"],
            "bytes_received": info["bytes_received"],
            "requests": info["requests"],
            "last_seen": info["last_seen"],
        }
        for pid, info in sorted_peers
    ]

    # Add peer reputation stats from Iroh node
    if _iroh_node:
        stats["peer_reputation"] = _iroh_node.get_peer_stats()

    # Add total bandwidth
    stats["total_bytes_sent"] = _metrics["bytes_sent_total"]
    stats["total_bytes_received"] = _metrics["bytes_received_total"]

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
    <h1>Peerix Dashboard <span class="mode-badge">Iroh</span> <span id="version" style="font-size: 12px; color: #666; font-weight: normal;"></span></h1>
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
                <span class="status-label">Available (in cache.nixos.org)</span>
                <span class="value" id="available-hashes">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Total Store Paths</span>
                <span class="status-value" id="total-store-paths">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Skipped (not in cache)</span>
                <span class="status-value warning" id="skipped-hashes">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Announced to Tracker</span>
                <span class="status-value" id="announced-hashes">--</span>
            </div>
            <div class="status-row">
                <span class="status-label">Last Scan</span>
                <span class="status-value" id="last-scan">--</span>
            </div>
            <div id="filter-progress" style="display: none; margin-top: 12px; padding-top: 12px; border-top: 1px solid #0f3460;">
                <div class="status-row">
                    <span class="status-label">Filtering</span>
                    <span class="status-value"><span id="filter-checked">0</span> / <span id="filter-total">0</span></span>
                </div>
                <div class="progress-bar">
                    <div class="fill" id="filter-bar" style="width: 0%"></div>
                </div>
                <div class="status-row" style="margin-top: 8px;">
                    <span class="status-label">Found</span>
                    <span class="status-value success" id="filter-found">0</span>
                </div>
                <div class="status-row">
                    <span class="status-label">ETA</span>
                    <span class="status-value" id="filter-eta">--</span>
                </div>
            </div>
            <div style="margin-top: 12px;">
                <button class="ctrl-btn" id="scan-toggle" onclick="toggleScan()">Pause Scan</button>
            </div>
        </div>
        <div class="card">
            <h2>Most Requested</h2>
            <div class="status-row">
                <span class="status-label">Total Requests</span>
                <span class="value" id="total-requests">0</span>
            </div>
            <div class="peers-list" id="most-requested" style="margin-top: 12px;"></div>
        </div>
        <div class="card">
            <h2>Most Served</h2>
            <div class="status-row">
                <span class="status-label">Total Served</span>
                <span class="value" id="total-served">0</span>
            </div>
            <div class="peers-list" id="most-served" style="margin-top: 12px;"></div>
        </div>
        <div class="card">
            <h2>Activity Log</h2>
            <div class="peers-list" id="activity-log" style="max-height: 300px;"></div>
        </div>
    </div>
    <script>
        let scanPaused = false;
        let lastDataHash = '';

        async function toggleScan() {
            const endpoint = scanPaused ? '/scan/resume' : '/scan/pause';
            await fetch(endpoint, { method: 'POST' });
            // Force refresh to show new state
            lastDataHash = '';
            await update();
        }

        function formatTime(ts) {
            if (!ts) return '--';
            const date = new Date(ts * 1000);
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            const hours = String(date.getHours()).padStart(2, '0');
            const mins = String(date.getMinutes()).padStart(2, '0');
            const secs = String(date.getSeconds()).padStart(2, '0');
            return `${month}/${day} ${hours}:${mins}:${secs}`;
        }

        // Country code to flag emoji
        function countryToFlag(code) {
            if (!code || code.length !== 2) return '';
            const offset = 127397;
            return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
        }

        // Simple hash function for change detection
        function hashData(obj) {
            return JSON.stringify(obj);
        }

        async function update() {
            try {
                const [statsResp, peersResp] = await Promise.all([
                    fetch('/dashboard-stats'),
                    fetch('/peers')
                ]);

                const stats = await statsResp.json();
                const peersData = await peersResp.json();

                // Check if data changed
                const currentHash = hashData({stats, peersData});
                if (currentHash === lastDataHash) {
                    return; // No changes, skip DOM update
                }
                lastDataHash = currentHash;

                // Version
                if (stats.version) {
                    document.getElementById('version').textContent = 'v' + stats.version;
                }

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
                    const flag = countryToFlag(peer.country);
                    // Show public IP (from tracker) and direct IP (connection path) if different
                    let ipInfo = '';
                    if (peer.public_ip && peer.direct_ip && peer.public_ip !== peer.direct_ip) {
                        ipInfo = `<span style="color:#00ff88">${peer.public_ip}</span> <span style="color:#666">via</span> <span style="color:#888">${peer.direct_ip}</span>`;
                    } else if (peer.public_ip) {
                        ipInfo = `<span style="color:#00ff88">${peer.public_ip}</span>`;
                    } else if (peer.direct_ip) {
                        ipInfo = `<span style="color:#888">${peer.direct_ip}</span>`;
                    }
                    // Reputation display
                    let repInfo = '';
                    if (peer.reputation) {
                        const rep = peer.reputation;
                        const scoreColor = rep.score >= 0.7 ? '#00ff88' : (rep.score >= 0.4 ? '#ffaa00' : '#ff4444');
                        const backedOff = rep.backed_off ? ' <span style="color:#ff4444">⏸</span>' : '';
                        repInfo = ` <span style="color:${scoreColor}" title="Score: ${rep.score}, Success: ${rep.success_rate}%, Reqs: ${rep.total_requests}, Latency: ${rep.avg_latency_ms}ms">★${rep.score}</span>${backedOff}`;
                    }
                    div.innerHTML = `<span style="margin-right: 6px;">${flag}</span>${peer.node_id_short} ${ipInfo}${repInfo}`;
                    div.title = peer.node_id;
                    peersList.appendChild(div);
                }

                // Store stats
                if (stats.scan && stats.scan.total_store_paths) {
                    document.getElementById('total-store-paths').textContent = stats.scan.total_store_paths.toLocaleString();
                }
                document.getElementById('available-hashes').textContent = (stats.available_hashes || 0).toLocaleString();
                if (stats.scan && stats.scan.cached_skipped !== undefined) {
                    document.getElementById('skipped-hashes').textContent = stats.scan.cached_skipped.toLocaleString();
                }
                document.getElementById('announced-hashes').textContent = (stats.announced_hashes || 0).toLocaleString();

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

                    // Filter progress (only show paths that need HTTP checking, not cached ones)
                    const filterProgress = document.getElementById('filter-progress');
                    const toCheck = stats.scan.filter_to_check || 0;
                    if (stats.scan.active && stats.scan.filtering_enabled && toCheck > 0) {
                        filterProgress.style.display = 'block';
                        const checked = stats.scan.filter_checked || 0;
                        const pct = (checked / toCheck) * 100;
                        document.getElementById('filter-checked').textContent = checked.toLocaleString();
                        document.getElementById('filter-total').textContent = toCheck.toLocaleString();
                        document.getElementById('filter-bar').style.width = pct + '%';
                        document.getElementById('filter-found').textContent = (stats.scan.filter_found || 0).toLocaleString();
                        document.getElementById('filter-eta').textContent = stats.scan.filter_eta || 'calculating...';
                    } else {
                        filterProgress.style.display = 'none';
                    }
                }

                // Most requested derivations
                document.getElementById('total-requests').textContent = (stats.total_requests || 0).toLocaleString();
                const mostRequested = document.getElementById('most-requested');
                mostRequested.innerHTML = '';
                for (const item of (stats.most_requested || [])) {
                    const div = document.createElement('div');
                    div.className = 'peer-item';
                    const nameStr = item.name ? `<span style="color:#00ff88">${item.name}</span>` : '';
                    div.innerHTML = `<span style="color:#00d9ff">${item.count}</span> <span style="color:#888">${item.hash}</span> ${nameStr}`;
                    mostRequested.appendChild(div);
                }

                // Most served derivations
                document.getElementById('total-served').textContent = (stats.total_served || 0).toLocaleString();
                const mostServed = document.getElementById('most-served');
                mostServed.innerHTML = '';
                for (const item of (stats.most_served || [])) {
                    const div = document.createElement('div');
                    div.className = 'peer-item';
                    const nameStr = item.name ? `<span style="color:#00ff88">${item.name}</span>` : '';
                    // Show peers who received this package
                    let peersStr = '';
                    if (item.peers && Object.keys(item.peers).length > 0) {
                        const peerList = Object.entries(item.peers).map(([p, c]) => `${p}:${c}`).join(', ');
                        peersStr = ` <span style="color:#9b59b6;font-size:10px">→ ${peerList}</span>`;
                    }
                    div.innerHTML = `<span style="color:#9b59b6">${item.count}</span> <span style="color:#888">${item.hash}</span> ${nameStr}${peersStr}`;
                    mostServed.appendChild(div);
                }

                // Activity log
                const activityLog = document.getElementById('activity-log');
                activityLog.innerHTML = '';
                for (const item of (stats.activity || [])) {
                    const div = document.createElement('div');
                    div.className = 'peer-item';
                    const timeStr = formatTime(item.time);
                    const icon = item.action === 'check' ? '🔍' : (item.action === 'served' ? '📤' : '📦');
                    const color = item.success ? '#00ff88' : '#ff4444';
                    const sizeStr = item.size > 0 ? ` (${(item.size/1024).toFixed(1)}KB)` : '';
                    const nameStr = item.name ? `<span style="color:#00ff88">${item.name}</span> ` : '';
                    const peerStr = item.peer_id ? `<span style="color:#9b59b6">→${item.peer_id}</span> ` : '';
                    div.innerHTML = `<span style="color:#666">${timeStr}</span> ${icon} <span style="color:${color}">${item.source}</span> ${peerStr}${nameStr}<span style="color:#888">${item.hash}</span>${sizeStr}`;
                    activityLog.appendChild(div);
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
        Route("/health", health_handler),
        Route("/metrics", metrics_handler),
        Route("/nix-cache-info", nix_cache_info),
        Route("/{hash}.narinfo", narinfo_handler),
        Route("/local/{hash}.narinfo", local_narinfo_handler),
        Route("/nar/{path:path}", nar_handler),
        Route("/iroh/nar/{peer_id}/{nar_hash}/{path:path}", iroh_nar_handler),
        Route("/lan/nar/{peer_addr}/{peer_port:int}/{path:path}", lan_nar_handler),
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
    filter_concurrency: int = 10,
    lan_discovery: bool = False,
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
        filter_concurrency: Max concurrent requests when filtering (default: 10)
        lan_discovery: Enable LAN peer discovery via UDP broadcast
    """
    global _iroh_node, _local_store, _cache_priority, _store_manager, _lan_discovery
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

    # Load persisted dashboard stats
    _load_stats()

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

        # Tracking callbacks for iroh protocol handlers
        def on_iroh_served(hash_part: str, name: str, peer_id: str):
            """Track narinfo served via iroh protocol."""
            _track_served(hash_part, name, peer_id)

        def on_iroh_nar_served(hash_part: str, name: str, size: int, peer_id: str):
            """Track NAR served via iroh protocol."""
            _track_served(hash_part, name, peer_id)
            _log_activity("served", hash_part, "to-peer", True, size, name=name, peer_id=peer_id)
            _record_metric("nars_served_total")
            _record_metric("bytes_sent_total", size)
            _record_peer_bandwidth(peer_id, bytes_sent=size)

        # Start Iroh node (use serving_store which has filtering/verification applied)
        _iroh_node = IrohNode(
            serving_store,
            tracker_url=tracker_url,
            peer_id=peer_id,
            connect_timeout=connect_timeout,
            state_dir=state_dir,
            on_served=on_iroh_served,
            on_nar_served=on_iroh_nar_served,
        )

        try:
            node_id = await _iroh_node.start()
            logger.info(f"Iroh node ID: {node_id}")

            # Get our address info
            addr = await _iroh_node.get_node_addr()
            logger.info(f"Relay: {addr.relay_url()}")
            logger.info(f"Direct addrs: {len(addr.direct_addresses())}")

            # Initialize store manager for tracking available packages (non-blocking)
            if scan_interval > 0:
                _store_manager = StoreManager(
                    scan_interval=scan_interval,
                    tracker_url=tracker_url,
                    peer_id=peer_id,
                    nixpkgs_filter=_nixpkgs_filter,
                    filter_concurrency=filter_concurrency,
                )
                logger.info(f"Store manager initialized (scan runs in background, concurrency={filter_concurrency})")

            # Initialize LAN discovery if enabled
            if lan_discovery:
                from .lan_discovery import LANDiscovery
                _lan_discovery = LANDiscovery(serving_store, port=port)
                await _lan_discovery.start()
                logger.info("LAN discovery enabled (UDP broadcast)")

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

            # SIGHUP watcher - triggers store rescan on systemd reload
            sighup_event = asyncio.Event()

            def sighup_callback():
                logger.info("SIGHUP received, triggering store rescan...")
                sighup_event.set()

            # Register async-safe SIGHUP handler
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGHUP, sighup_callback)

            async def sighup_watcher():
                """Watch for SIGHUP and trigger store rescan."""
                while True:
                    await sighup_event.wait()
                    sighup_event.clear()
                    if _store_manager:
                        logger.info("Triggering store rescan due to SIGHUP...")
                        try:
                            await _store_manager.scan_once()
                            if _store_manager.tracker_url:
                                await _store_manager.delta_sync_packages()
                            logger.info("SIGHUP rescan complete")
                        except Exception as e:
                            logger.error(f"SIGHUP rescan failed: {e}")
                    else:
                        logger.warning("No store manager, ignoring SIGHUP")

            # Run server, tracker sync, store scanning, and stats persistence concurrently
            # (delta sync is now integrated into periodic scan)
            async with asyncio.TaskGroup() as tg:
                tg.create_task(server.serve())
                if tracker_url:
                    tg.create_task(_iroh_node.run_tracker_sync())
                if _store_manager and scan_interval > 0:
                    tg.create_task(_store_manager.run_periodic_scan())
                # Save dashboard stats every 60 seconds
                tg.create_task(_run_periodic_stats_save(interval=60))
                # SIGHUP watcher for systemd reload
                tg.create_task(sighup_watcher())

        except asyncio.CancelledError:
            logger.info("Shutting down...")
        finally:
            # Save stats before shutdown
            _save_stats()
            logger.info("Dashboard stats saved")
            if _store_manager:
                await _store_manager.close()
                _store_manager = None
            if _nixpkgs_filter:
                await _nixpkgs_filter.close()
            if _verified_store:
                await _verified_store.close()
            if _lan_discovery:
                await _lan_discovery.stop()
                _lan_discovery = None
            await _iroh_node.stop()
            _iroh_node = None
            _local_store = None


def main():
    """CLI entry point."""
    import argparse
    from .config import load_config, apply_config_to_args

    parser = argparse.ArgumentParser(description="Iroh-based Peerix server")
    parser.add_argument("--config", "-c", type=str,
                        help="Path to config file (default: ~/.config/peerix/config.toml)")
    parser.add_argument("--port", "-p", type=int,
                        help="HTTP port (default: 12304)")
    parser.add_argument("--tracker", "-t", type=str,
                        help="Tracker URL for peer discovery (default: https://sophronesis.dev/peerix)")
    parser.add_argument("--peer-id", type=str,
                        help="Human-readable peer ID (default: hostname)")
    parser.add_argument("--priority", type=int,
                        help="Cache priority (default: 5)")
    parser.add_argument("--timeout", type=float,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--state-dir", type=str,
                        help="Directory for persistent state (default: /var/lib/peerix)")
    parser.add_argument("--private-key", type=str,
                        help="Path to nix secret key file for signing narinfo")
    parser.add_argument("--scan-interval", type=int,
                        help="Seconds between store scans (0 to disable, default: 3600)")
    parser.add_argument("--no-filter", action="store_true",
                        help="Disable package filtering")
    parser.add_argument("--filter-mode", type=str, choices=["nixpkgs", "rules"],
                        help="Filter mode: nixpkgs (only cache.nixos.org packages) or rules (pattern-based)")
    parser.add_argument("--filter-pattern", type=str, action="append", dest="filter_patterns",
                        help="Additional filter pattern (can be specified multiple times)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable hash verification against upstream cache")
    parser.add_argument("--upstream-cache", type=str,
                        help="Upstream cache URL for verification (default: https://cache.nixos.org)")
    parser.add_argument("--filter-concurrency", type=int,
                        help="Max concurrent requests when filtering hashes (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--lan-discovery", action="store_true",
                        help="Enable LAN peer discovery via UDP broadcast (supplements Iroh)")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="Allow HTTP (non-TLS) connections to tracker/upstream (INSECURE, for testing only)")
    args = parser.parse_args()

    # Mark which args were explicitly set via CLI
    # (used by apply_config_to_args to know what to override)
    for arg in ['port', 'tracker', 'peer_id', 'priority', 'timeout', 'private_key',
                'scan_interval', 'filter_mode', 'filter_concurrency', 'upstream_cache',
                'no_filter', 'no_verify', 'verbose', 'allow_insecure_http']:
        if getattr(args, arg, None) is not None:
            setattr(args, f'_cli_{arg}', True)

    # Load config file and apply defaults where CLI didn't override
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)
    apply_config_to_args(args, config)

    # Apply final defaults for any still-None values
    if args.port is None:
        args.port = 12304
    if args.priority is None:
        args.priority = 5
    if args.timeout is None:
        args.timeout = 10.0
    if args.scan_interval is None:
        args.scan_interval = 3600
    if args.filter_mode is None:
        args.filter_mode = "nixpkgs"
    if args.filter_concurrency is None:
        args.filter_concurrency = 10
    if args.upstream_cache is None:
        args.upstream_cache = "https://cache.nixos.org"
    if args.tracker is None:
        args.tracker = "https://sophronesis.dev/peerix"

    # Security: Enforce TLS for tracker and upstream cache URLs
    # Unless explicitly disabled with --allow-insecure-http
    if not args.allow_insecure_http:
        if args.tracker and not args.tracker.startswith("https://"):
            print(f"ERROR: Tracker URL must use HTTPS: {args.tracker}")
            print("Use --allow-insecure-http to disable TLS enforcement (INSECURE)")
            raise SystemExit(1)
        if args.upstream_cache and not args.upstream_cache.startswith("https://"):
            print(f"ERROR: Upstream cache URL must use HTTPS: {args.upstream_cache}")
            print("Use --allow-insecure-http to disable TLS enforcement (INSECURE)")
            raise SystemExit(1)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    # Register signal handler to save stats on shutdown
    def handle_shutdown(signum, frame):
        logger.info(f"Received signal {signum}, saving stats...")
        _save_stats()
        logger.info("Stats saved, exiting")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    # Note: SIGHUP is handled asynchronously in run_server() via loop.add_signal_handler()

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
            filter_concurrency=args.filter_concurrency,
            lan_discovery=args.lan_discovery,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    main()
