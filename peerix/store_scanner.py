"""
Scanner for local nix store paths.

Collects store path hashes to announce to the tracker.
"""
import typing as t
import logging
import subprocess
import os

logger = logging.getLogger("peerix.store_scanner")


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


def scan_store_paths(limit: int = 1000) -> t.List[str]:
    """
    Scan the local nix store and return a list of store path hashes.

    Args:
        limit: Maximum number of paths to return

    Returns:
        List of 32-character store path hashes
    """
    hashes = []

    try:
        # Use nix path-info --all to list all store paths
        result = subprocess.run(
            ["nix", "path-info", "--all"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            logger.warning(f"nix path-info failed: {result.stderr}")
            return []

        for line in result.stdout.strip().split("\n"):
            path = line.strip()
            if not path:
                continue
            h = get_store_path_hash(path)
            if h:
                hashes.append(h)
                if len(hashes) >= limit:
                    break

    except subprocess.TimeoutExpired:
        logger.warning("nix path-info timed out")
    except FileNotFoundError:
        logger.warning("nix command not found")
    except Exception as e:
        logger.warning(f"Store scan failed: {e}")

    logger.info(f"Scanned {len(hashes)} store paths")
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
