"""
Origin detector for multi-cache support.

Detects which binary cache a local store path came from by examining signatures.
"""
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .cache_registry import CacheRegistry, get_cache_registry

logger = logging.getLogger("peerix.origin_detector")

# Default path for caching origin mappings
DEFAULT_ORIGIN_CACHE_FILE = "/var/lib/peerix/origin_cache.json"


@dataclass
class OriginInfo:
    """Information about a package's origin."""
    cache_url: str
    public_key: str
    package_name: str


class OriginDetector:
    """
    Detects package origin by examining local narinfo signatures.

    Caches results to avoid repeated detection for the same packages.
    """

    def __init__(
        self,
        cache_registry: Optional[CacheRegistry] = None,
        cache_file: str = DEFAULT_ORIGIN_CACHE_FILE,
    ):
        self._registry = cache_registry or get_cache_registry()
        self._cache_file = cache_file
        self._origin_cache: Dict[str, OriginInfo] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cached origin mappings from disk."""
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, "r") as f:
                    data = json.load(f)
                    for hash_key, info in data.items():
                        self._origin_cache[hash_key] = OriginInfo(
                            cache_url=info.get("cache_url", ""),
                            public_key=info.get("public_key", ""),
                            package_name=info.get("package_name", ""),
                        )
                logger.info(f"Loaded {len(self._origin_cache)} origin mappings from cache")
        except Exception as e:
            logger.debug(f"Failed to load origin cache: {e}")
            self._origin_cache = {}

    def save_cache(self) -> None:
        """Save origin mappings to disk."""
        try:
            os.makedirs(os.path.dirname(self._cache_file), exist_ok=True)
            data = {
                hash_key: {
                    "cache_url": info.cache_url,
                    "public_key": info.public_key,
                    "package_name": info.package_name,
                }
                for hash_key, info in self._origin_cache.items()
            }
            with open(self._cache_file, "w") as f:
                json.dump(data, f)
            logger.debug(f"Saved {len(self._origin_cache)} origin mappings")
        except Exception as e:
            logger.warning(f"Failed to save origin cache: {e}")

    def detect_origin(self, store_hash: str) -> Optional[OriginInfo]:
        """
        Detect origin for a store path hash.

        Strategy:
        1. Check cache for known mapping
        2. Query local nix store for narinfo/signature
        3. Match signature key to known caches

        Args:
            store_hash: 32-character store path hash

        Returns:
            OriginInfo or None if origin cannot be determined
        """
        # Check cache first
        if store_hash in self._origin_cache:
            return self._origin_cache[store_hash]

        # Get store path from hash
        store_path = self._get_store_path(store_hash)
        if not store_path:
            return None

        # Extract package name
        package_name = self._extract_package_name(store_path)

        # Try to get signature from local store
        signature = self._get_local_signature(store_path)
        if signature and self._registry:
            result = self._registry.find_origin_by_signature(signature)
            if result:
                cache_url, public_key = result
                origin = OriginInfo(
                    cache_url=cache_url,
                    public_key=public_key,
                    package_name=package_name,
                )
                self._origin_cache[store_hash] = origin
                return origin

        return None

    def detect_origin_batch(self, store_hashes: list) -> Dict[str, OriginInfo]:
        """
        Detect origins for multiple store hashes.

        More efficient than calling detect_origin repeatedly.

        Args:
            store_hashes: List of 32-character store path hashes

        Returns:
            Dict mapping hash -> OriginInfo (only includes found origins)
        """
        results = {}
        uncached = []

        # First pass: check cache
        for h in store_hashes:
            if h in self._origin_cache:
                results[h] = self._origin_cache[h]
            else:
                uncached.append(h)

        if not uncached:
            return results

        # Batch query store paths
        store_paths = self._get_store_paths_batch(uncached)

        # Detect origins for uncached hashes
        for store_hash in uncached:
            store_path = store_paths.get(store_hash)
            if not store_path:
                continue

            package_name = self._extract_package_name(store_path)
            signature = self._get_local_signature(store_path)

            if signature and self._registry:
                result = self._registry.find_origin_by_signature(signature)
                if result:
                    cache_url, public_key = result
                    origin = OriginInfo(
                        cache_url=cache_url,
                        public_key=public_key,
                        package_name=package_name,
                    )
                    self._origin_cache[store_hash] = origin
                    results[store_hash] = origin

        return results

    def get_cached_origin(self, store_hash: str) -> Optional[OriginInfo]:
        """Get origin from cache without detection."""
        return self._origin_cache.get(store_hash)

    def set_origin(self, store_hash: str, origin: OriginInfo) -> None:
        """Manually set origin for a hash (e.g., from peer announcement)."""
        self._origin_cache[store_hash] = origin

    def _get_store_path(self, store_hash: str) -> Optional[str]:
        """Get full store path from hash by listing /nix/store."""
        try:
            store_dir = Path("/nix/store")
            for entry in store_dir.iterdir():
                if entry.name.startswith(store_hash):
                    return str(entry)
        except Exception as e:
            logger.debug(f"Failed to find store path for {store_hash}: {e}")
        return None

    def _get_store_paths_batch(self, store_hashes: list) -> Dict[str, str]:
        """Get store paths for multiple hashes efficiently."""
        hash_set = set(store_hashes)
        results = {}
        try:
            store_dir = Path("/nix/store")
            for entry in store_dir.iterdir():
                prefix = entry.name[:32]
                if prefix in hash_set:
                    results[prefix] = str(entry)
                    if len(results) == len(hash_set):
                        break
        except Exception as e:
            logger.debug(f"Failed to batch get store paths: {e}")
        return results

    def _extract_package_name(self, store_path: str) -> str:
        """Extract package name from store path."""
        if not store_path:
            return ""
        basename = os.path.basename(store_path)
        # Format: hash-name -> name
        if len(basename) > 33 and basename[32] == "-":
            return basename[33:]
        return basename

    def _get_local_signature(self, store_path: str) -> Optional[str]:
        """
        Get signature for a store path from local nix database.

        Uses `nix path-info --sigs` to query the signature.
        """
        try:
            result = subprocess.run(
                ["nix", "path-info", "--sigs", store_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Output format: "/nix/store/xxx sig1 sig2 ..."
                parts = result.stdout.strip().split()
                if len(parts) > 1:
                    # Return first signature
                    return parts[1]
        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout getting signature for {store_path}")
        except FileNotFoundError:
            logger.debug("nix command not found")
        except Exception as e:
            logger.debug(f"Failed to get signature for {store_path}: {e}")
        return None


# Global detector instance
_detector: Optional[OriginDetector] = None


def get_origin_detector() -> Optional[OriginDetector]:
    """Get the global origin detector."""
    return _detector


def init_origin_detector(
    cache_registry: Optional[CacheRegistry] = None,
    cache_file: str = DEFAULT_ORIGIN_CACHE_FILE,
) -> OriginDetector:
    """Initialize the global origin detector."""
    global _detector
    _detector = OriginDetector(cache_registry, cache_file)
    return _detector
