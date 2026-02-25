"""
Scanner for local nix store paths.

Collects store path hashes to announce to the tracker.
"""
import typing as t
import logging
import subprocess
import hashlib
import os

logger = logging.getLogger("peerix.store_scanner")

# Cache for store state hash to avoid re-scanning
_last_store_hash: t.Optional[str] = None
_cached_hashes: t.List[str] = []


def get_store_path_hash(path: str) -> t.Optional[str]:
    """Extract the 32-character hash from a store path."""
    # Store paths look like: /nix/store/abc123...-name
    # We want the abc123... part (32 chars)
    if not path.startswith("/nix/store/"):
        return None
    rest = path[len("/nix/store/"):]
    if len(rest) < 32:
        return None
    return rest[:32]


def compute_store_hash() -> str:
    """
    Compute a hash of the store state based on directory listing.

    Uses the sorted list of store path names to create a digest.
    This is fast because it only reads directory entries, not file contents.
    """
    try:
        entries = sorted(os.listdir("/nix/store"))
        # Hash the sorted list of entries
        content = "\n".join(entries).encode("utf-8")
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception as e:
        logger.warning(f"Failed to compute store hash: {e}")
        return ""


def scan_store_paths(limit: int = 1000, skip_derivations: bool = False) -> t.List[str]:
    """
    Scan the local nix store and return a list of store path hashes.

    Args:
        limit: Maximum number of paths to return (0 = unlimited)
        skip_derivations: If True, skip .drv files (default: False)

    Returns:
        List of 32-character store path hashes
    """
    global _last_store_hash, _cached_hashes

    # Check if store state has changed
    current_hash = compute_store_hash()
    if current_hash and current_hash == _last_store_hash and _cached_hashes:
        logger.debug(f"Store unchanged (hash={current_hash}), using cached {len(_cached_hashes)} paths")
        return _cached_hashes

    hashes = []

    try:
        # Fast path: directly list /nix/store directory
        # This is much faster than nix path-info --all for large stores
        store_path = "/nix/store"
        for entry in os.scandir(store_path):
            name = entry.name
            # Skip derivation files
            if skip_derivations and name.endswith(".drv"):
                continue
            # Extract 32-char hash from name
            if len(name) >= 32:
                hashes.append(name[:32])
                if limit > 0 and len(hashes) >= limit:
                    break

    except PermissionError:
        logger.warning("Permission denied reading /nix/store")
        return _cached_hashes if _cached_hashes else []
    except FileNotFoundError:
        logger.warning("/nix/store not found")
        return []
    except Exception as e:
        logger.warning(f"Store scan failed: {e}")
        return _cached_hashes if _cached_hashes else []

    # Update cache
    _last_store_hash = current_hash
    _cached_hashes = hashes

    logger.info(f"Scanned {len(hashes)} store paths (hash={current_hash})")
    return hashes


def scan_recent_paths(hours: int = 24, limit: int = 500) -> t.List[str]:
    """
    Scan for recently accessed store paths.

    This is more efficient than scanning all paths and focuses on
    paths that are likely to be requested by other peers.

    Args:
        hours: Look for paths accessed within this many hours
        limit: Maximum number of paths to return

    Returns:
        List of 32-character store path hashes
    """
    hashes = []
    store_path = "/nix/store"

    try:
        # List store directory entries, sorted by mtime
        entries = []
        for entry in os.scandir(store_path):
            if entry.is_dir() or entry.is_symlink():
                try:
                    stat = entry.stat(follow_symlinks=False)
                    entries.append((entry.name, stat.st_mtime))
                except OSError:
                    continue

        # Sort by modification time (most recent first)
        entries.sort(key=lambda x: x[1], reverse=True)

        # Extract hashes from most recent entries
        for name, _ in entries[:limit]:
            if len(name) >= 32:
                hashes.append(name[:32])

    except Exception as e:
        logger.warning(f"Recent path scan failed: {e}")
        # Fall back to full scan
        return scan_store_paths(limit)

    logger.info(f"Scanned {len(hashes)} recent store paths")
    return hashes
