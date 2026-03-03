"""
Cache registry for multi-cache support.

Manages trusted binary caches and their public keys.
Can auto-detect from /etc/nix/nix.conf.
"""
import logging
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import CachesConfig, TrustedCache

logger = logging.getLogger("peerix.cache_registry")

# Default nix.conf locations
NIX_CONF_PATHS = [
    Path("/etc/nix/nix.conf"),
    Path.home() / ".config" / "nix" / "nix.conf",
]


@dataclass
class CacheInfo:
    """Information about a binary cache."""
    url: str
    public_key: str
    key_name: str  # e.g., "cache.nixos.org-1"


class CacheRegistry:
    """
    Registry of trusted binary caches.

    Manages mapping between cache URLs, public keys, and key names.
    Supports auto-detection from nix.conf.
    """

    def __init__(self, config: Optional[CachesConfig] = None):
        self._caches: Dict[str, CacheInfo] = {}
        self._key_to_cache: Dict[str, str] = {}  # key_name -> cache_url

        if config:
            self._load_from_config(config)

    def _load_from_config(self, config: CachesConfig) -> None:
        """Load caches from config."""
        # Add default cache
        if config.default and config.default_key:
            self.add_cache(config.default, config.default_key)

        # Add explicit trusted caches
        for cache in config.trusted_caches:
            self.add_cache(cache.url, cache.public_key)

        # Auto-detect from nix.conf if enabled
        if config.auto_detect:
            self._auto_detect_caches()

    def _auto_detect_caches(self) -> None:
        """Auto-detect caches from /etc/nix/nix.conf."""
        substituters = []
        trusted_keys = {}

        for nix_conf_path in NIX_CONF_PATHS:
            if not nix_conf_path.exists():
                continue

            try:
                content = nix_conf_path.read_text()
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue

                    # Parse substituters
                    if line.startswith("substituters") or line.startswith("extra-substituters"):
                        # Handle both "substituters = ..." and "substituters=..."
                        match = re.match(r"(?:extra-)?substituters\s*=\s*(.+)", line)
                        if match:
                            urls = match.group(1).split()
                            substituters.extend(urls)

                    # Parse trusted-public-keys
                    if line.startswith("trusted-public-keys") or line.startswith("extra-trusted-public-keys"):
                        match = re.match(r"(?:extra-)?trusted-public-keys\s*=\s*(.+)", line)
                        if match:
                            keys = match.group(1).split()
                            for key in keys:
                                # Key format: "name:base64key"
                                if ":" in key:
                                    key_name = key.split(":")[0]
                                    trusted_keys[key_name] = key

            except Exception as e:
                logger.debug(f"Failed to read {nix_conf_path}: {e}")

        # Match substituters to keys by domain
        for url in substituters:
            # Skip if already registered
            if url in self._caches:
                continue

            # Try to find matching key
            # Extract domain from URL for matching
            domain = _extract_domain(url)
            for key_name, full_key in trusted_keys.items():
                # Key names often start with domain (e.g., "cache.nixos.org-1")
                if key_name.startswith(domain) or domain in key_name:
                    self.add_cache(url, full_key)
                    logger.debug(f"Auto-detected cache: {url} with key {key_name}")
                    break

        if substituters:
            logger.info(f"Auto-detected {len(self._caches)} caches from nix.conf")

    def add_cache(self, url: str, public_key: str) -> None:
        """
        Add a trusted cache.

        Args:
            url: Cache URL (e.g., "https://cache.nixos.org")
            public_key: Full public key including name (e.g., "cache.nixos.org-1:6NCH...")
        """
        # Normalize URL (remove trailing slash)
        url = url.rstrip("/")

        # Extract key name from public key
        key_name = public_key.split(":")[0] if ":" in public_key else ""

        self._caches[url] = CacheInfo(
            url=url,
            public_key=public_key,
            key_name=key_name,
        )

        if key_name:
            self._key_to_cache[key_name] = url

    def get_cache_for_key(self, key_name: str) -> Optional[str]:
        """
        Get cache URL for a signature key name.

        Args:
            key_name: Signature key name (e.g., "cache.nixos.org-1")

        Returns:
            Cache URL or None if not found
        """
        return self._key_to_cache.get(key_name)

    def get_key_for_cache(self, cache_url: str) -> Optional[str]:
        """
        Get public key for a cache URL.

        Args:
            cache_url: Cache URL

        Returns:
            Full public key or None if not found
        """
        cache_url = cache_url.rstrip("/")
        cache = self._caches.get(cache_url)
        return cache.public_key if cache else None

    def get_cache_info(self, cache_url: str) -> Optional[CacheInfo]:
        """Get full cache info for a URL."""
        cache_url = cache_url.rstrip("/")
        return self._caches.get(cache_url)

    def is_trusted(self, cache_url: str) -> bool:
        """
        Check if a cache URL is trusted.

        Args:
            cache_url: Cache URL to check

        Returns:
            True if cache is in trusted list
        """
        cache_url = cache_url.rstrip("/")
        return cache_url in self._caches

    def is_key_trusted(self, key_name: str) -> bool:
        """
        Check if a signature key is from a trusted cache.

        Args:
            key_name: Signature key name (e.g., "cache.nixos.org-1")

        Returns:
            True if key is from a trusted cache
        """
        return key_name in self._key_to_cache

    def get_all_caches(self) -> List[CacheInfo]:
        """Get all registered caches."""
        return list(self._caches.values())

    def get_trusted_caches_payload(self) -> List[Dict[str, str]]:
        """
        Get trusted caches in format for tracker announcement.

        Returns:
            List of {"url": "...", "public_key": "..."} dicts
        """
        return [
            {"url": cache.url, "public_key": cache.public_key}
            for cache in self._caches.values()
        ]

    def find_origin_by_signature(self, signature: str) -> Optional[Tuple[str, str]]:
        """
        Find cache origin from a narinfo signature.

        Signatures have format: "key_name:base64_signature"

        Args:
            signature: Full signature string from narinfo

        Returns:
            Tuple of (cache_url, public_key) or None
        """
        if ":" not in signature:
            return None

        key_name = signature.split(":")[0]
        cache_url = self._key_to_cache.get(key_name)
        if cache_url:
            cache = self._caches.get(cache_url)
            if cache:
                return (cache_url, cache.public_key)
        return None


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    # Remove protocol
    if "://" in url:
        url = url.split("://", 1)[1]
    # Remove path
    if "/" in url:
        url = url.split("/", 1)[0]
    # Remove port
    if ":" in url:
        url = url.split(":", 1)[0]
    return url


# Global registry instance
_registry: Optional[CacheRegistry] = None


def get_cache_registry() -> Optional[CacheRegistry]:
    """Get the global cache registry."""
    return _registry


def init_cache_registry(config: Optional[CachesConfig] = None) -> CacheRegistry:
    """Initialize the global cache registry."""
    global _registry
    _registry = CacheRegistry(config)
    logger.info(f"Initialized cache registry with {len(_registry._caches)} caches")
    return _registry
