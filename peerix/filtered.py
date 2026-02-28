import typing as t
import fnmatch
import logging
import os
import time

import httpx

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.filtered")


DEFAULT_EXCLUDE_PATTERNS = [
    # System builds
    "*-nixos-system-*",
    "*-etc-*",
    "*-nixos-*-config",
    "*-unit-*.service",
    "*-system-path",
    "*-booted-system",
    "*-toplevel",
    "*-activation-script-*",
    "*-systemd-*",
    # Secrets / sensitive
    "*-sops-nix-*",
    "*-agenix-*",
    "*-secret-*",
    "*-secrets-*",
    "*-password-*",
    "*-private-key-*",
    "*-credentials-*",
    "*.key",
    "*.pem",
    # User-specific
    "*-home-manager-*",
    "*-home-files-*",
]


class FilteredStore(Store):

    def __init__(self, backend: Store, extra_patterns: t.Sequence[str] = (),
                 use_defaults: bool = True):
        self.backend = backend
        self.patterns: t.List[str] = []
        if use_defaults:
            self.patterns.extend(DEFAULT_EXCLUDE_PATTERNS)
        self.patterns.extend(extra_patterns)

    def _is_excluded(self, store_path: str) -> bool:
        basename = os.path.basename(store_path)
        for pattern in self.patterns:
            if fnmatch.fnmatch(basename, pattern):
                logger.debug(f"Filtered out {basename} (matched {pattern})")
                return True
        return False

    async def cache_info(self) -> CacheInfo:
        return await self.backend.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        info = await self.backend.narinfo(hsh)
        if info is None:
            return None
        if self._is_excluded(info.storePath):
            return None
        return info

    def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        return self.backend.nar(url)


class NixpkgsFilteredStore(Store):
    """
    Filter store that only serves packages available in nixpkgs cache.

    Checks cache.nixos.org to verify package exists before serving.
    Uses a local cache to avoid repeated lookups.
    """

    def __init__(
        self,
        backend: Store,
        cache_url: str = "https://cache.nixos.org",
        cache_ttl: int = 3600,  # 1 hour
        negative_ttl: int = 300,  # 5 minutes for "not found" results
    ):
        self.backend = backend
        self.cache_url = cache_url.rstrip("/")
        self.cache_ttl = cache_ttl
        self.negative_ttl = negative_ttl
        # Cache: hash -> (exists: bool, timestamp: float)
        self._cache: t.Dict[str, t.Tuple[bool, float]] = {}
        self._client: t.Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def close(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _is_cached(self, hsh: str) -> t.Optional[bool]:
        """Check local cache. Returns None if not cached or expired."""
        if hsh not in self._cache:
            return None
        exists, ts = self._cache[hsh]
        ttl = self.cache_ttl if exists else self.negative_ttl
        if time.time() - ts > ttl:
            del self._cache[hsh]
            return None
        return exists

    async def _check_nixpkgs(self, hsh: str) -> bool:
        """Check if hash exists in nixpkgs cache."""
        # Check local cache first
        cached = self._is_cached(hsh)
        if cached is not None:
            return cached

        # Query cache.nixos.org
        try:
            client = await self._get_client()
            resp = await client.head(f"{self.cache_url}/{hsh}.narinfo")
            exists = resp.status_code == 200
            self._cache[hsh] = (exists, time.time())
            if not exists:
                logger.debug(f"Filtered {hsh}: not in nixpkgs cache")
            return exists
        except Exception as e:
            logger.warning(f"Failed to check nixpkgs cache for {hsh}: {e}")
            # On error, allow the package (fail open)
            return True

    async def cache_info(self) -> CacheInfo:
        return await self.backend.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        # Check if exists in nixpkgs first
        if not await self._check_nixpkgs(hsh):
            return None
        return await self.backend.narinfo(hsh)

    def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        return self.backend.nar(url)
