"""
Configuration file support for peerix.

Loads configuration from ~/.config/peerix/config.toml.
CLI arguments take precedence over config file values.
"""
import tomllib
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger("peerix.config")

CONFIG_PATH = Path.home() / ".config" / "peerix" / "config.toml"


@dataclass
class ServerConfig:
    """HTTP server configuration."""
    port: int = 12304
    priority: int = 5
    timeout: float = 10.0
    verbose: bool = False


@dataclass
class TrackerConfig:
    """Tracker and peer discovery configuration."""
    url: Optional[str] = "https://sophronesis.dev/peerix"
    peer_id: Optional[str] = None  # Default: hostname


@dataclass
class StoreConfig:
    """Store scanning and filtering configuration."""
    scan_interval: int = 3600
    filter_mode: str = "nixpkgs"  # "nixpkgs" or "rules"
    filter_concurrency: int = 10
    filter_patterns: List[str] = field(default_factory=list)
    no_filter: bool = False
    no_verify: bool = False
    upstream_cache: str = "https://cache.nixos.org"


@dataclass
class TrustedCache:
    """A trusted binary cache with its public key."""
    url: str
    public_key: str


@dataclass
class CachesConfig:
    """Cache trust configuration for multi-cache support."""
    # Default cache (always trusted)
    default: str = "https://cache.nixos.org"
    default_key: str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    # Additional trusted caches
    trusted_caches: List[TrustedCache] = field(default_factory=list)
    # Auto-detect from /etc/nix/nix.conf
    auto_detect: bool = True
    # Enable multi-cache origin tracking
    track_origins: bool = True


@dataclass
class SigningConfig:
    """NAR signing configuration."""
    private_key: Optional[str] = None


@dataclass
class SecurityConfig:
    """Security-related settings."""
    allow_insecure_http: bool = False


@dataclass
class PeerixConfig:
    """Complete peerix configuration."""
    server: ServerConfig = field(default_factory=ServerConfig)
    tracker: TrackerConfig = field(default_factory=TrackerConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    signing: SigningConfig = field(default_factory=SigningConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    caches: CachesConfig = field(default_factory=CachesConfig)


DEFAULT_CONFIG_CONTENT = """\
# Peerix configuration file
# https://github.com/sophronesis/peerix
#
# Mode is determined by tracker.url:
#   - url set (default) → Iroh mode (P2P with NAT traversal)
#   - url = "" or not set → LAN mode (UDP broadcast)

[server]
port = 12304
priority = 5           # Lower = higher priority (cache.nixos.org is 10)
timeout = 10.0         # Connection timeout in seconds
verbose = false

[tracker]
url = "https://sophronesis.dev/peerix"
# peer_id = "my-hostname"  # Default: system hostname

[store]
scan_interval = 3600   # Seconds between store scans (0 to disable)
filter_mode = "nixpkgs"  # "nixpkgs" (only cache.nixos.org packages) or "rules"
filter_concurrency = 10
no_filter = false
no_verify = false
upstream_cache = "https://cache.nixos.org"

[signing]
# private_key = "/path/to/cache-priv-key.pem"

[security]
allow_insecure_http = false  # Allow HTTP (non-TLS) - INSECURE

[caches]
# Multi-cache origin tracking
# Peers can share packages from multiple trusted binary caches
default = "https://cache.nixos.org"
default_key = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
auto_detect = true     # Read substituters and keys from /etc/nix/nix.conf
track_origins = true   # Track which cache each package came from

# Additional trusted caches (example):
# [[caches.trusted_caches]]
# url = "https://my-cache.example.com"
# public_key = "my-cache-1:abc123..."
"""


def create_default_config(path: Path) -> None:
    """Create default config file if it doesn't exist."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_CONFIG_CONTENT)
        logger.info(f"Created default config at {path}")
    except Exception as e:
        logger.warning(f"Failed to create default config: {e}")


def load_config(path: Optional[Path] = None, create_if_missing: bool = False) -> PeerixConfig:
    """
    Load configuration from TOML file.

    Args:
        path: Optional path to config file. Defaults to ~/.config/peerix/config.toml
        create_if_missing: Create default config if file doesn't exist

    Returns:
        PeerixConfig with values from file, or defaults if file doesn't exist
    """
    config_path = path or CONFIG_PATH

    if not config_path.exists():
        if create_if_missing:
            create_default_config(config_path)
        return PeerixConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        server_data = data.get("server", {})
        tracker_data = data.get("tracker", {})
        store_data = data.get("store", {})
        signing_data = data.get("signing", {})
        security_data = data.get("security", {})
        caches_data = data.get("caches", {})

        # Parse trusted_caches list if present
        trusted_caches_raw = caches_data.pop("trusted_caches", [])
        trusted_caches = []
        for cache in trusted_caches_raw:
            if isinstance(cache, dict) and "url" in cache and "public_key" in cache:
                trusted_caches.append(TrustedCache(
                    url=cache["url"],
                    public_key=cache["public_key"]
                ))

        config = PeerixConfig(
            server=ServerConfig(**server_data),
            tracker=TrackerConfig(**tracker_data),
            store=StoreConfig(**store_data),
            signing=SigningConfig(**signing_data),
            security=SecurityConfig(**security_data),
            caches=CachesConfig(trusted_caches=trusted_caches, **caches_data),
        )

        logger.info(f"Loaded config from {config_path}")
        return config

    except tomllib.TOMLDecodeError as e:
        logger.warning(f"Failed to parse config file {config_path}: {e}")
        return PeerixConfig()
    except TypeError as e:
        logger.warning(f"Invalid config option in {config_path}: {e}")
        return PeerixConfig()
    except Exception as e:
        logger.warning(f"Failed to load config from {config_path}: {e}")
        return PeerixConfig()


def apply_config_to_args(args, config: PeerixConfig) -> None:
    """
    Apply config file values to args where CLI didn't override.

    CLI arguments take precedence. Config values are only applied
    if the CLI argument wasn't explicitly set.

    Modifies args in place.

    Args:
        args: argparse Namespace object
        config: PeerixConfig loaded from file
    """
    # Server settings
    if not hasattr(args, '_cli_port'):
        args.port = config.server.port
    if not hasattr(args, '_cli_priority'):
        args.priority = config.server.priority
    if not hasattr(args, '_cli_timeout'):
        args.timeout = config.server.timeout
    if not hasattr(args, '_cli_verbose') and config.server.verbose:
        args.verbose = True

    # Tracker settings
    if not hasattr(args, '_cli_tracker'):
        args.tracker = config.tracker.url
    if not hasattr(args, '_cli_peer_id'):
        args.peer_id = config.tracker.peer_id

    # Store settings
    if not hasattr(args, '_cli_scan_interval'):
        args.scan_interval = config.store.scan_interval
    if not hasattr(args, '_cli_filter_mode'):
        args.filter_mode = config.store.filter_mode
    if not hasattr(args, '_cli_filter_concurrency'):
        args.filter_concurrency = config.store.filter_concurrency
    if not hasattr(args, '_cli_no_filter') and config.store.no_filter:
        args.no_filter = True
    if not hasattr(args, '_cli_no_verify') and config.store.no_verify:
        args.no_verify = True
    if not hasattr(args, '_cli_upstream_cache'):
        args.upstream_cache = config.store.upstream_cache
    if config.store.filter_patterns and not getattr(args, 'filter_patterns', None):
        args.filter_patterns = config.store.filter_patterns

    # Signing settings
    if not hasattr(args, '_cli_private_key'):
        args.private_key = config.signing.private_key

    # Security settings
    if not hasattr(args, '_cli_allow_insecure_http') and config.security.allow_insecure_http:
        args.allow_insecure_http = True
