"""
IPFS-based Store implementation for peerix.

Uses the local IPFS daemon to store and retrieve NARs.
Content is addressed by CID, with a mapping from NarHash to CID.
"""
import typing as t
import logging
import hashlib
import json
import os

import httpx
import trio

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.ipfs")

# Default IPFS API endpoint
IPFS_API_URL = "http://127.0.0.1:5001/api/v0"

# Path to store NarHash → CID mappings
CID_CACHE_PATH = "/var/lib/peerix/cid_cache.json"


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
    ):
        """
        Initialize the IPFS store.

        Args:
            local_store: The underlying local store
            api_url: IPFS HTTP API URL
            cache_path: Path to CID cache file
            publish_local: Whether to publish local NARs to IPFS
            fetch_timeout: Timeout for IPFS fetches
            tracker_client: Optional tracker client for CID registry
        """
        self.local_store = local_store
        self.api_url = api_url.rstrip("/")
        self.cache_path = cache_path
        self.publish_local = publish_local
        self.fetch_timeout = fetch_timeout
        self.tracker_client = tracker_client

        self._client: t.Optional[httpx.AsyncClient] = None
        self._cid_cache: t.Dict[str, str] = {}  # NarHash -> CID
        self._load_cache()

    def set_tracker_client(self, tracker_client: t.Any) -> None:
        """Set the tracker client for CID registry."""
        self.tracker_client = tracker_client
        logger.info("IPFSStore: tracker client configured for CID lookups")

    def _load_cache(self) -> None:
        """Load CID cache from disk."""
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, "r") as f:
                    self._cid_cache = json.load(f)
                logger.info(f"Loaded {len(self._cid_cache)} CID mappings from cache")
        except Exception as e:
            logger.warning(f"Failed to load CID cache: {e}")
            self._cid_cache = {}

    def _save_cache(self) -> None:
        """Save CID cache to disk."""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w") as f:
                json.dump(self._cid_cache, f)
        except Exception as e:
            logger.warning(f"Failed to save CID cache: {e}")

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.fetch_timeout)
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

    async def check_ipfs_has(self, cid: str) -> bool:
        """
        Check if content is available in IPFS network.

        Uses routing/findprovs (the new API, replacing deprecated dht/findprovs).
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
            # Check if we got any providers in the response
            data = resp.json()
            responses = data.get("Responses", [])
            return len(responses) > 0
        except Exception:
            return False

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
                    self._save_cache()
                    logger.debug(f"Got CID from tracker for {hsh}: {cid}")
            except Exception as e:
                logger.debug(f"Tracker CID lookup failed for {hsh}: {e}")

        # If we have a CID, check if content is available in IPFS
        if cid:
            if await self.check_ipfs_has(cid):
                # We need narinfo metadata from local store
                ni = await self.local_store.narinfo(hsh)
                if ni:
                    # Rewrite URL to use IPFS
                    ipfs_url = f"ipfs/{cid}"
                    logger.info(f"Found {hsh} in IPFS: {cid}")
                    return ni._replace(url=ipfs_url)
                else:
                    # We know the CID but don't have narinfo locally
                    logger.debug(f"Have CID but no narinfo for {hsh}")
            else:
                logger.debug(f"CID {cid} not available in IPFS network")

        # Fall back to local store
        return await self.local_store.narinfo(hsh)

    async def nar(self, url: str) -> t.AsyncIterable[bytes]:
        """
        Fetch NAR data, from IPFS if URL starts with ipfs/.

        Args:
            url: NAR URL (ipfs/{cid} or local path)

        Returns:
            Async iterable of NAR data chunks
        """
        if url.startswith("ipfs/"):
            cid = url[5:]  # Remove "ipfs/" prefix
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
        Publish a NAR to IPFS and cache the CID mapping.

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

        # Collect NAR data
        nar_data = b""
        try:
            async for chunk in await self.local_store.nar(ni.url):
                nar_data += chunk
        except Exception as e:
            logger.warning(f"Failed to read NAR for {hsh}: {e}")
            return None

        # Add to IPFS
        cid = await self.add_to_ipfs(nar_data)
        if cid:
            self._cid_cache[hsh] = cid
            self._save_cache()
            logger.info(f"Published {hsh} to IPFS: {cid}")

            # Register with tracker
            if self.tracker_client is not None:
                try:
                    await self.tracker_client.register_cid(hsh, cid)
                    logger.debug(f"Registered CID with tracker: {hsh} -> {cid}")
                except Exception as e:
                    logger.warning(f"Failed to register CID with tracker: {e}")

        return cid


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
