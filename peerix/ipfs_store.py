"""
IPFS-based Store implementation for peerix.

Uses the local IPFS daemon to store and retrieve NARs.
Content is addressed by CID, with a mapping from NarHash to CID.
"""
import typing as t
import logging
import hashlib
import json
import gzip
import os
import fnmatch
import uuid

import httpx
import trio

from peerix.store import NarInfo, CacheInfo, Store
from peerix.store_scanner import scan_store_paths, get_store_path_hash
from peerix.filtered import DEFAULT_EXCLUDE_PATTERNS


logger = logging.getLogger("peerix.ipfs")

# Default IPFS API endpoint
IPFS_API_URL = "http://127.0.0.1:5001/api/v0"

# Path to store NarHash → CID mappings
# Uses gzip compression for ~73% space savings
CID_CACHE_PATH = "/var/lib/peerix/cid_cache.json.gz"

# Legacy uncompressed path (for migration)
CID_CACHE_PATH_LEGACY = "/var/lib/peerix/cid_cache.json"

# Default scan interval (1 hour)
DEFAULT_SCAN_INTERVAL = 3600


class IPFSStore(Store):
    """
    Store implementation that uses IPFS for NAR distribution.

    NARs are added to IPFS and their CIDs are cached locally.
    When fetching, we look up the CID and retrieve from IPFS.
    """

    def __init__(
        self,
        local_store: Store,
        api_url: str = IPFS_API_URL,
        cache_path: str = CID_CACHE_PATH,
        publish_local: bool = True,
        fetch_timeout: float = 60.0,
        tracker_client: t.Any = None,
        upstream_cache: str = "https://cache.nixos.org",
    ):
        """
        Initialize the IPFS store.

        Args:
            local_store: The underlying local store
            api_url: IPFS HTTP API URL
            cache_path: Path to gzip-compressed CID cache file
            publish_local: Whether to publish local NARs to IPFS
            fetch_timeout: Timeout for IPFS fetches
            tracker_client: Optional tracker client for CID registry
            upstream_cache: Upstream cache URL for narinfo fallback
        """
        # Scan progress tracking
        self._scan_progress: t.Dict[str, t.Any] = {
            "active": False,
            "total": 0,
            "total_work": 0,
            "processed": 0,
            "published": 0,
            "from_tracker": 0,
            "skipped": 0,
            "already_cached": 0,
            "dht_announced": 0,
            "current_hash": None,
            "current_path": None,
            "started_at": None,
        }
        # Total DHT announcements (persists across scans)
        self._total_dht_announced: int = 0
        # Kalman filter state for rate smoothing
        self._kalman_rate: float = 0.0  # Estimated rate
        self._kalman_p: float = 1000.0  # Estimate uncertainty
        self._kalman_q: float = 10.0  # Process noise (rate can change)
        self._kalman_r: float = 2000.0  # Measurement noise (higher = smoother)
        self._kalman_last_time: float = 0.0
        self._kalman_last_processed: int = 0
        self._rate_history: t.List[float] = []  # Recent rate measurements for STD
        self._rate_history_max: int = 30  # Keep last N measurements

        self.local_store = local_store
        self.api_url = api_url.rstrip("/")
        self.cache_path = cache_path  # Gzip-compressed JSON
        self.skipped_cache_path = cache_path.replace("cid_cache", "skipped_cache")
        self.publish_local = publish_local
        self.fetch_timeout = fetch_timeout
        self.tracker_client = tracker_client
        self.upstream_cache = upstream_cache.rstrip("/")

        self._client: t.Optional[httpx.AsyncClient] = None
        self._cid_cache: t.Dict[str, str] = {}  # NarHash -> CID (in-memory)
        self._skipped_cache: t.Set[str] = set()  # Hashes that were skipped
        self._cache_dirty: bool = False  # Track if cache needs saving
        self._skipped_dirty: bool = False
        self._load_cache()
        self._load_skipped_cache()

    def set_tracker_client(self, tracker_client: t.Any) -> None:
        """Set the tracker client for CID registry."""
        self.tracker_client = tracker_client
        logger.info("IPFSStore: tracker client configured for CID lookups")

    def get_scan_progress(self) -> t.Dict[str, t.Any]:
        """
        Get current scan progress.

        Returns dict with:
            active: bool - whether a scan is running
            total: int - total paths to process
            processed: int - paths processed so far
            published: int - new NARs published to IPFS
            from_tracker: int - CIDs reused from tracker
            skipped: int - paths skipped (filtered/failed)
            already_cached: int - already in local cache
            current_hash: str - hash currently being processed
            current_path: str - store path currently being processed
            started_at: float - scan start timestamp
            percent: float - completion percentage
            eta_seconds: float - estimated seconds remaining (null if not calculable)
            rate: float - processing rate (items/sec)
        """
        import time
        progress = self._scan_progress.copy()

        # Calculate percent based on work items (excludes instant cache hits)
        work_items = progress["published"] + progress["from_tracker"] + progress["skipped"]
        total_work = progress.get("total_work", progress["total"])
        if total_work > 0:
            progress["percent"] = round(100 * work_items / total_work, 1)
        else:
            progress["percent"] = 0.0

        progress["eta_seconds"] = None
        progress["rate"] = 0.0

        if progress["active"] and progress["started_at"] and progress["processed"] > 0:
            now = time.time()
            elapsed = now - progress["started_at"]
            remaining = progress["total"] - progress["processed"]

            # Work items = items that required actual work (not instant cache hits)
            work_items = progress["published"] + progress["from_tracker"] + progress["skipped"]

            # Wait for enough work items before initializing Kalman
            min_items = 50
            min_seconds = 5.0
            if self._kalman_rate <= 0:
                if elapsed >= min_seconds and work_items >= min_items:
                    self._kalman_rate = work_items / elapsed
                    self._kalman_last_time = now
                    self._kalman_last_processed = work_items
                else:
                    # Not enough data yet, don't show ETA
                    return progress

            # Kalman filter update based on work items only
            dt = now - self._kalman_last_time if self._kalman_last_time > 0 else 0
            if dt > 0.1:
                items_delta = work_items - self._kalman_last_processed
                measured_rate = items_delta / dt if dt > 0 else self._kalman_rate

                # Track rate history for STD calculation
                self._rate_history.append(measured_rate)
                if len(self._rate_history) > self._rate_history_max:
                    self._rate_history.pop(0)

                # Predict step
                self._kalman_p += self._kalman_q

                # Update step
                k = self._kalman_p / (self._kalman_p + self._kalman_r)  # Kalman gain
                self._kalman_rate += k * (measured_rate - self._kalman_rate)
                self._kalman_p *= (1 - k)
                self._kalman_rate = max(1.0, self._kalman_rate)

                self._kalman_last_time = now
                self._kalman_last_processed = work_items

                # Store calculation details for transparency
                progress["rate_calc"] = f"{items_delta}/{round(dt, 1)}s"

            if self._kalman_rate > 0:
                # ETA based on remaining work items (exclude already_cached from remaining)
                remaining_work = remaining  # All remaining need processing
                eta = remaining_work / self._kalman_rate
                progress["eta_seconds"] = round(eta, 1)
                progress["rate"] = round(self._kalman_rate, 1)
                progress["work_items"] = work_items

                # Calculate ETA error from rate STD (need at least 5 samples)
                if len(self._rate_history) >= 5:
                    import statistics
                    rate_std = statistics.stdev(self._rate_history)
                    # Error propagation: if rate has STD, ETA error ~ remaining * (rate_std / rate^2)
                    if self._kalman_rate > 0:
                        eta_error = remaining_work * rate_std / (self._kalman_rate ** 2)
                        progress["eta_error_seconds"] = round(eta_error, 1)

        return progress

    def _reset_kalman(self) -> None:
        """Reset Kalman filter for new scan."""
        self._kalman_rate = 0.0
        self._kalman_p = 1000.0
        self._kalman_last_time = 0.0
        self._kalman_last_processed = 0
        self._rate_history = []

    async def sync_cid_mappings_to_tracker(self) -> int:
        """
        Register all local CID mappings with the tracker.

        Called on startup to ensure tracker has our complete CID registry.
        This enables other peers to discover content we have in IPFS.

        Returns:
            Number of CID mappings successfully registered
        """
        if self.tracker_client is None:
            logger.debug("No tracker client, skipping CID sync")
            return 0

        if not self._cid_cache:
            logger.debug("No local CID mappings to sync")
            return 0

        # Take snapshot to avoid "dictionary changed size during iteration"
        cid_items = list(self._cid_cache.items())
        logger.info(f"Syncing {len(cid_items)} CID mappings to tracker...")
        registered = 0
        failed = 0

        for nar_hash, cid in cid_items:
            try:
                success = await self.tracker_client.register_cid(nar_hash, cid)
                if success:
                    registered += 1
                else:
                    failed += 1
            except Exception as e:
                logger.debug(f"Failed to register CID {nar_hash}: {e}")
                failed += 1

        if failed > 0:
            logger.warning(f"CID sync: {registered} registered, {failed} failed")
        else:
            logger.info(f"CID sync complete: {registered} mappings registered")

        return registered

    def _migrate_legacy_cache(self) -> None:
        """Migrate uncompressed JSON cache to gzip-compressed format."""
        legacy_path = CID_CACHE_PATH_LEGACY
        if not os.path.exists(legacy_path):
            return

        try:
            with open(legacy_path, "r") as f:
                legacy_cache = json.load(f)

            if not legacy_cache:
                return

            logger.info(f"Migrating {len(legacy_cache)} CID mappings to compressed format...")

            # Merge with any existing cache
            self._cid_cache.update(legacy_cache)
            self._save_cache()

            # Rename old file as backup
            backup_path = legacy_path + ".migrated"
            os.rename(legacy_path, backup_path)
            logger.info(f"Migrated cache, backed up to {backup_path}")
        except Exception as e:
            logger.warning(f"Migration failed: {e}")

    def _load_cache(self) -> None:
        """Load CID cache from gzip-compressed JSON file."""
        try:
            # First try loading compressed cache
            if os.path.exists(self.cache_path):
                with gzip.open(self.cache_path, "rt", encoding="utf-8") as f:
                    self._cid_cache = json.load(f)
                logger.info(f"Loaded {len(self._cid_cache)} CID mappings from compressed cache")

            # Migrate legacy uncompressed cache if it exists
            self._migrate_legacy_cache()

        except Exception as e:
            logger.warning(f"Failed to load CID cache: {e}")
            self._cid_cache = {}

    def _save_cache(self) -> None:
        """Save CID cache to gzip-compressed JSON file."""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with gzip.open(self.cache_path, "wt", encoding="utf-8") as f:
                json.dump(self._cid_cache, f)
            self._cache_dirty = False
        except Exception as e:
            logger.warning(f"Failed to save CID cache: {e}")

    def _mark_dirty(self) -> None:
        """Mark cache as needing save."""
        self._cache_dirty = True

    def _load_skipped_cache(self) -> None:
        """Load skipped hashes from gzip-compressed JSON file."""
        try:
            if os.path.exists(self.skipped_cache_path):
                with gzip.open(self.skipped_cache_path, "rt", encoding="utf-8") as f:
                    self._skipped_cache = set(json.load(f))
                logger.info(f"Loaded {len(self._skipped_cache)} skipped hashes from cache")
        except Exception as e:
            logger.warning(f"Failed to load skipped cache: {e}")
            self._skipped_cache = set()

    def _save_skipped_cache(self) -> None:
        """Save skipped hashes to gzip-compressed JSON file."""
        try:
            os.makedirs(os.path.dirname(self.skipped_cache_path), exist_ok=True)
            with gzip.open(self.skipped_cache_path, "wt", encoding="utf-8") as f:
                json.dump(list(self._skipped_cache), f)
            self._skipped_dirty = False
        except Exception as e:
            logger.warning(f"Failed to save skipped cache: {e}")

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.fetch_timeout, connect=10.0),
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=30.0,
                ),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def cache_info(self) -> CacheInfo:
        """Return local cache info."""
        return await self.local_store.cache_info()

    async def add_to_ipfs(self, data: bytes) -> t.Optional[str]:
        """
        Add data to IPFS and return its CID.

        Args:
            data: The data to add

        Returns:
            CID string if successful, None otherwise
        """
        try:
            client = await self._get_client()
            # IPFS add endpoint expects multipart form data
            files = {"file": ("data", data)}
            resp = await client.post(
                f"{self.api_url}/add",
                files=files,
                params={"quiet": "true", "pin": "true"},
            )
            if resp.status_code == 200:
                result = resp.json()
                cid = result.get("Hash")
                logger.debug(f"Added to IPFS: {cid} ({len(data)} bytes)")
                return cid
            else:
                logger.warning(f"IPFS add failed: {resp.status_code}")
                return None
        except Exception as e:
            logger.warning(f"IPFS add error: {e}")
            return None

    async def add_to_ipfs_streaming(self, data_stream: t.AsyncIterable[bytes]) -> t.Optional[str]:
        """
        Stream data directly to IPFS without buffering entire content in memory.

        Args:
            data_stream: Async iterable yielding data chunks

        Returns:
            CID string if successful, None otherwise
        """
        try:
            client = await self._get_client()
            boundary = f"----peerix-{uuid.uuid4().hex}"

            async def body_generator():
                # Multipart header
                yield f"--{boundary}\r\n".encode()
                yield b'Content-Disposition: form-data; name="file"; filename="nar"\r\n'
                yield b"Content-Type: application/octet-stream\r\n\r\n"
                # Stream the actual data
                async for chunk in data_stream:
                    yield chunk
                # Multipart footer
                yield f"\r\n--{boundary}--\r\n".encode()

            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
            resp = await client.post(
                f"{self.api_url}/add",
                content=body_generator(),
                headers=headers,
                params={"quiet": "true", "pin": "true"},
            )
            if resp.status_code == 200:
                result = resp.json()
                cid = result.get("Hash")
                logger.debug(f"Streamed to IPFS: {cid}")
                return cid
            else:
                logger.warning(f"IPFS streaming add failed: {resp.status_code}")
                return None
        except Exception as e:
            logger.warning(f"IPFS streaming add error: {e}")
            return None

    async def get_from_ipfs(self, cid: str) -> t.Optional[bytes]:
        """
        Get data from IPFS by CID.

        Args:
            cid: The content ID to fetch

        Returns:
            Data bytes if successful, None otherwise
        """
        try:
            client = await self._get_client()
            resp = await client.post(
                f"{self.api_url}/cat",
                params={"arg": cid},
            )
            if resp.status_code == 200:
                logger.debug(f"Fetched from IPFS: {cid} ({len(resp.content)} bytes)")
                return resp.content
            else:
                logger.debug(f"IPFS cat failed for {cid}: {resp.status_code}")
                return None
        except Exception as e:
            logger.debug(f"IPFS fetch error for {cid}: {e}")
            return None

    async def get_from_ipfs_streaming(self, cid: str) -> t.Optional[t.AsyncIterable[bytes]]:
        """
        Stream data from IPFS by CID without buffering entire content.

        Args:
            cid: The content ID to fetch

        Returns:
            Async iterable of data chunks if successful, None otherwise
        """
        try:
            client = await self._get_client()
            # Use stream=True for streaming response
            async with client.stream(
                "POST",
                f"{self.api_url}/cat",
                params={"arg": cid},
            ) as resp:
                if resp.status_code != 200:
                    logger.debug(f"IPFS cat failed for {cid}: {resp.status_code}")
                    return None

                async def stream_chunks():
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        yield chunk

                # We need to consume within the context manager, so collect and yield
                chunks = []
                async for chunk in resp.aiter_bytes(chunk_size=65536):
                    chunks.append(chunk)

                async def yield_chunks():
                    for chunk in chunks:
                        yield chunk

                return yield_chunks()
        except Exception as e:
            logger.debug(f"IPFS streaming fetch error for {cid}: {e}")
            return None

    async def announce_to_dht(self, cid: str) -> bool:
        """
        Announce content to the IPFS DHT for discoverability.

        This is crucial for content to be found by peers behind NAT.
        Uses routing/provide API to publish provider records to the DHT.

        Args:
            cid: The content ID to announce

        Returns:
            True if announcement succeeded, False otherwise
        """
        try:
            client = await self._get_client()
            # routing/provide announces our peer as a provider for this CID
            resp = await client.post(
                f"{self.api_url}/routing/provide",
                params={"arg": cid},
                timeout=30.0,  # DHT operations can be slow
            )
            if resp.status_code == 200:
                logger.debug(f"Announced to DHT: {cid}")
                self._total_dht_announced += 1
                if self._scan_progress["active"]:
                    self._scan_progress["dht_announced"] += 1
                return True
            else:
                logger.warning(f"DHT announcement failed for {cid}: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"DHT announcement error for {cid}: {e}")
            return False

    async def check_ipfs_has(self, cid: str) -> bool:
        """
        Check if content is available in IPFS network.

        Uses routing/findprovs (the new API, replacing deprecated dht/findprovs).
        The response is NDJSON with Type=4 indicating provider found.
        """
        try:
            client = await self._get_client()
            # Use routing/findprovs (new API replacing dht/findprovs)
            resp = await client.post(
                f"{self.api_url}/routing/findprovs",
                params={"arg": cid, "num-providers": "1"},
                timeout=10.0,
            )
            if resp.status_code != 200:
                return False
            # Response is NDJSON - check for Type=4 (provider found)
            # or any entry with non-null Responses
            for line in resp.text.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # Type 4 = provider found, or check Responses
                    if data.get("Type") == 4:
                        return True
                    responses = data.get("Responses")
                    if responses and len(responses) > 0:
                        return True
                except json.JSONDecodeError:
                    continue
            return False
        except Exception:
            return False

    async def _fetch_upstream_narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """Fetch narinfo from upstream cache."""
        try:
            client = await self._get_client()
            url = f"{self.upstream_cache}/{hsh}.narinfo"
            resp = await client.get(url, timeout=10.0)
            if resp.status_code == 200:
                logger.debug(f"Fetched narinfo from upstream for {hsh}")
                return NarInfo.parse(resp.text)
            return None
        except Exception as e:
            logger.debug(f"Failed to fetch upstream narinfo for {hsh}: {e}")
            return None

    async def batch_narinfo(
        self,
        hashes: t.List[str],
        concurrency: int = 10,
    ) -> t.Dict[str, t.Optional[NarInfo]]:
        """
        Fetch narinfo for multiple hashes in parallel.

        Args:
            hashes: List of store path hashes to look up
            concurrency: Maximum parallel lookups (default: 10)

        Returns:
            Dict mapping hash to NarInfo (or None if not found)
        """
        results: t.Dict[str, t.Optional[NarInfo]] = {}
        semaphore = trio.Semaphore(concurrency)

        async def fetch_one(hsh: str) -> None:
            async with semaphore:
                results[hsh] = await self.narinfo(hsh)

        async with trio.open_nursery() as nursery:
            for hsh in hashes:
                nursery.start_soon(fetch_one, hsh)

        return results

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """
        Query narinfo, checking IPFS for the NAR.

        Discovery strategies:
        1. Check local CID cache
        2. Query tracker for CID mapping
        3. Fall back to local store
        """
        # Check local CID cache first
        cid = self._cid_cache.get(hsh)

        # If not in cache, try tracker
        if cid is None and self.tracker_client is not None:
            try:
                cid = await self.tracker_client.get_cid(hsh)
                if cid:
                    # Cache it locally
                    self._cid_cache[hsh] = cid
                    self._mark_dirty()
                    logger.debug(f"Got CID from tracker for {hsh}: {cid}")
            except Exception as e:
                logger.debug(f"Tracker CID lookup failed for {hsh}: {e}")

        # If we have a CID, return narinfo pointing to IPFS
        # Skip availability check - it's too slow (10s timeout) and causes nix to
        # use cache.nixos.org instead. If NAR fetch fails, nix will fallback.
        if cid:
            # Try local store first for narinfo metadata
            ni = await self.local_store.narinfo(hsh)
            if ni is None:
                # Try upstream cache for narinfo
                ni = await self._fetch_upstream_narinfo(hsh)
            if ni:
                # Rewrite URL to use IPFS CID (PrefixStore adds v5/ipfs/ prefix)
                logger.info(f"Found {hsh} in IPFS: {cid}")
                return ni._replace(url=cid)
            else:
                # We know the CID but can't get narinfo
                logger.debug(f"Have CID but no narinfo for {hsh}")

        # Fall back to local store
        return await self.local_store.narinfo(hsh)

    async def nar(self, url: str) -> t.AsyncIterable[bytes]:
        """
        Fetch NAR data, from IPFS if URL is a CID.

        Args:
            url: NAR URL (CID starting with Qm or local path)

        Returns:
            Async iterable of NAR data chunks
        """
        # Check if URL is an IPFS CID (starts with Qm for CIDv0 or bafy for CIDv1)
        if url.startswith("Qm") or url.startswith("bafy"):
            cid = url
            data = await self.get_from_ipfs(cid)
            if data is None:
                raise FileNotFoundError(f"IPFS content not found: {cid}")

            # Yield data in chunks
            chunk_size = 65536
            for i in range(0, len(data), chunk_size):
                yield data[i:i + chunk_size]
        else:
            # Fall back to local store
            async for chunk in await self.local_store.nar(url):
                yield chunk

    async def publish_nar(self, hsh: str) -> t.Optional[str]:
        """
        Publish a NAR to IPFS using streaming upload.

        Streams the NAR directly to IPFS without buffering the entire
        content in memory.

        Args:
            hsh: The store path hash

        Returns:
            CID if successful, None otherwise
        """
        # Check if already published
        if hsh in self._cid_cache:
            return self._cid_cache[hsh]

        # Get narinfo to find the NAR
        ni = await self.local_store.narinfo(hsh)
        if ni is None:
            return None

        # Stream NAR data directly to IPFS
        try:
            nar_stream = await self.local_store.nar(ni.url)
            cid = await self.add_to_ipfs_streaming(nar_stream)
        except Exception as e:
            logger.warning(f"Failed to stream NAR for {hsh}: {e}")
            return None

        if cid:
            self._cid_cache[hsh] = cid
            self._mark_dirty()
            logger.info(f"Published {hsh} to IPFS: {cid}")

            # Announce to DHT for discoverability across NAT
            await self.announce_to_dht(cid)

        return cid

    def _is_excluded(self, store_path: str, extra_patterns: t.List[str] = None) -> bool:
        """Check if a store path should be excluded from IPFS publishing."""
        basename = os.path.basename(store_path)
        patterns = DEFAULT_EXCLUDE_PATTERNS + (extra_patterns or [])
        for pattern in patterns:
            if fnmatch.fnmatch(basename, pattern):
                return True
        return False

    async def scan_and_publish(
        self,
        extra_patterns: t.List[str] = None,
        concurrency: int = 10,
    ) -> t.Tuple[int, int]:
        """
        Scan local nix store and publish applicable packages to IPFS.

        Scans all store paths (after filtering sensitive packages).
        Before publishing, checks tracker for existing CIDs to avoid
        re-uploading content that's already in the network.
        Uploads are parallelized with configurable concurrency.

        Args:
            extra_patterns: Additional fnmatch patterns to exclude
            concurrency: Maximum number of parallel IPFS uploads (default: 10)

        Returns:
            Tuple of (published_count, skipped_count)
        """
        import time
        logger.info(f"Scanning nix store for IPFS publishing (concurrency={concurrency})...")

        # Fetch existing CIDs from tracker to avoid re-publishing
        tracker_cids: t.Dict[str, str] = {}
        if self.tracker_client is not None:
            try:
                tracker_cids = await self.tracker_client.get_all_cids()
                logger.info(f"Fetched {len(tracker_cids)} existing CIDs from tracker")
            except Exception as e:
                logger.warning(f"Failed to fetch CIDs from tracker: {e}")

        # Get all store paths
        store_hashes = scan_store_paths(limit=0)  # 0 = no limit
        logger.info(f"Found {len(store_hashes)} store paths to process")

        # Count how many are already cached or skipped (instant hits)
        already_in_cache = sum(1 for h in store_hashes if h in self._cid_cache)
        already_skipped = sum(1 for h in store_hashes if h in self._skipped_cache)
        total_work_estimate = len(store_hashes) - already_in_cache - already_skipped

        # Initialize progress tracking
        self._scan_progress = {
            "active": True,
            "total": len(store_hashes),
            "total_work": total_work_estimate,
            "processed": 0,
            "published": 0,
            "from_tracker": 0,
            "skipped": 0,
            "already_cached": 0,
            "dht_announced": 0,
            "current_hash": None,
            "current_path": None,
            "started_at": time.time(),
        }
        self._reset_kalman()

        # Counters (safe since trio is single-threaded)
        counters = {"published": 0, "skipped": 0, "already_cached": 0, "from_tracker": 0}
        semaphore = trio.Semaphore(concurrency)

        async def publish_one(hsh: str) -> None:
            """Publish a single store path to IPFS."""
            # Skip if already in local cache
            if hsh in self._cid_cache:
                counters["already_cached"] += 1
                self._scan_progress["already_cached"] = counters["already_cached"]
                self._scan_progress["processed"] += 1
                return

            # Skip if previously skipped (persisted)
            if hsh in self._skipped_cache:
                counters["already_cached"] += 1  # Count as cached for progress
                self._scan_progress["already_cached"] = counters["already_cached"]
                self._scan_progress["processed"] += 1
                return

            async with semaphore:
                # Update current processing info
                self._scan_progress["current_hash"] = hsh

                # Double-check cache
                if hsh in self._cid_cache:
                    counters["already_cached"] += 1
                    self._scan_progress["already_cached"] = counters["already_cached"]
                    self._scan_progress["processed"] += 1
                    return

                try:
                    ni = await self.local_store.narinfo(hsh)
                    if ni is None:
                        self._skipped_cache.add(hsh)
                        self._skipped_dirty = True
                        counters["skipped"] += 1
                        self._scan_progress["skipped"] = counters["skipped"]
                        self._scan_progress["processed"] += 1
                        return

                    # Update current path being processed
                    self._scan_progress["current_path"] = ni.storePath

                    # Check exclusion patterns
                    if self._is_excluded(ni.storePath, extra_patterns):
                        logger.debug(f"Excluded: {ni.storePath}")
                        self._skipped_cache.add(hsh)
                        self._skipped_dirty = True
                        counters["skipped"] += 1
                        self._scan_progress["skipped"] = counters["skipped"]
                        self._scan_progress["processed"] += 1
                        return

                    # Check if CID exists on tracker (use store hash as key)
                    if hsh in tracker_cids:
                        # Use existing CID from tracker, skip IPFS upload
                        cid = tracker_cids[hsh]
                        self._cid_cache[hsh] = cid
                        self._mark_dirty()
                        counters["from_tracker"] += 1
                        self._scan_progress["from_tracker"] = counters["from_tracker"]
                        self._scan_progress["processed"] += 1
                        logger.debug(f"Using tracker CID for {hsh}: {cid}")
                        return

                    # Not on tracker - publish to IPFS
                    cid = await self.publish_nar(hsh)
                    if cid:
                        counters["published"] += 1
                        self._scan_progress["published"] = counters["published"]
                        logger.debug(f"Published {hsh} -> {cid}")
                        # Register new CID with tracker
                        if self.tracker_client is not None:
                            try:
                                await self.tracker_client.register_cid(hsh, cid)
                            except Exception as e:
                                logger.debug(f"Failed to register CID: {e}")
                    else:
                        self._skipped_cache.add(hsh)
                        self._skipped_dirty = True
                        counters["skipped"] += 1
                        self._scan_progress["skipped"] = counters["skipped"]

                    self._scan_progress["processed"] += 1

                except Exception as e:
                    logger.debug(f"Failed to process {hsh}: {e}")
                    self._skipped_cache.add(hsh)
                    self._skipped_dirty = True
                    counters["skipped"] += 1
                    self._scan_progress["skipped"] = counters["skipped"]
                    self._scan_progress["processed"] += 1

        # Periodic cache saver (every 60s during scan)
        scan_done_event = trio.Event()

        async def periodic_save() -> None:
            while True:
                # Wait up to 60s or until scan completes
                with trio.move_on_after(60):
                    await scan_done_event.wait()
                    return  # Scan finished, exit
                # Timeout - do periodic save
                if self._cache_dirty:
                    self._save_cache()
                    logger.debug("Periodic save: CID cache")
                if self._skipped_dirty:
                    self._save_skipped_cache()
                    logger.debug("Periodic save: skipped cache")

        async def run_scan_work() -> None:
            async with trio.open_nursery() as work_nursery:
                for hsh in store_hashes:
                    work_nursery.start_soon(publish_one, hsh)

        # Run work and periodic save in parallel
        async with trio.open_nursery() as nursery:
            nursery.start_soon(periodic_save)
            await run_scan_work()
            scan_done_event.set()  # Signal periodic_save to exit

        # Final save of caches
        if self._cache_dirty:
            self._save_cache()
        if self._skipped_dirty:
            self._save_skipped_cache()

        # Mark scan as complete
        self._scan_progress["active"] = False
        self._scan_progress["current_hash"] = None
        self._scan_progress["current_path"] = None

        logger.info(
            f"Store scan complete: {counters['published']} published, "
            f"{counters['from_tracker']} from tracker, "
            f"{counters['skipped']} skipped, {counters['already_cached']} already cached"
        )
        return counters["published"], counters["skipped"]

    async def run_periodic_scan(
        self,
        interval: float = DEFAULT_SCAN_INTERVAL,
        extra_patterns: t.List[str] = None,
        concurrency: int = 10,
    ) -> None:
        """
        Run periodic store scanning in background.

        Scans all store paths (no limit), filters sensitive packages,
        and publishes to IPFS. Package hash sync is handled separately
        via delta sync in app.py.

        Args:
            interval: Seconds between scans (default: 3600 = 1 hour)
            extra_patterns: Additional exclusion patterns
            concurrency: Maximum number of parallel IPFS uploads (default: 10)
        """
        logger.info(f"Starting periodic IPFS store scan (interval={interval}s, concurrency={concurrency})")

        while True:
            try:
                published, skipped = await self.scan_and_publish(extra_patterns, concurrency)
            except Exception as e:
                logger.warning(f"Periodic scan failed: {e}")

            await trio.sleep(interval)


class IPFSNarInfoStore(Store):
    """
    Store that publishes narinfo+NAR as a single IPFS object.

    This allows fetching both metadata and content from IPFS,
    enabling fully decentralized discovery.
    """

    def __init__(
        self,
        local_store: Store,
        ipfs_store: IPFSStore,
    ):
        self.local_store = local_store
        self.ipfs_store = ipfs_store

    async def cache_info(self) -> CacheInfo:
        return await self.local_store.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """Query narinfo from IPFS or local store."""
        # Try IPFS first
        ni = await self.ipfs_store.narinfo(hsh)
        if ni:
            return ni

        # Fall back to local
        return await self.local_store.narinfo(hsh)

    async def nar(self, url: str) -> t.AsyncIterable[bytes]:
        """Fetch NAR from IPFS or local store."""
        async for chunk in self.ipfs_store.nar(url):
            yield chunk
