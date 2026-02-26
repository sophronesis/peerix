"""
Configuration file support for peerix.

Loads configuration from ~/.config/peerix/config.toml.
CLI arguments take precedence over config file values.
"""
import tomllib
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


logger = logging.getLogger("peerix.config")

CONFIG_PATH = Path.home() / ".config" / "peerix" / "config.toml"


@dataclass
class DaemonConfig:
    port: int = 12304
    timeout: int = 50
    mode: str = "ipfs"
    verbose: bool = False
    priority: int = 5


@dataclass
class IpfsConfig:
    tracker_url: Optional[str] = None
    scan_interval: int = 3600
    concurrency: int = 10


@dataclass
class SigningConfig:
    private_key: Optional[str] = None


@dataclass
class PeerixConfig:
    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    ipfs: IpfsConfig = field(default_factory=IpfsConfig)
    signing: SigningConfig = field(default_factory=SigningConfig)


def load_config(path: Optional[Path] = None) -> PeerixConfig:
    """
    Load configuration from TOML file.

    Args:
        path: Optional path to config file. Defaults to ~/.config/peerix/config.toml

    Returns:
        PeerixConfig with values from file, or defaults if file doesn't exist
    """
    config_path = path or CONFIG_PATH

    if not config_path.exists():
        return PeerixConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        daemon_data = data.get("daemon", {})
        ipfs_data = data.get("ipfs", {})
        signing_data = data.get("signing", {})

        config = PeerixConfig(
            daemon=DaemonConfig(**daemon_data),
            ipfs=IpfsConfig(**ipfs_data),
            signing=SigningConfig(**signing_data),
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


# Default values used by argparse (for detecting if CLI arg was provided)
CLI_DEFAULTS = {
    "port": 12304,
    "timeout": 50,
    "mode": "ipfs",
    "loglevel": logging.INFO,
    "priority": 5,
    "tracker_url": None,
    "scan_interval": 3600,
    "ipfs_concurrency": 10,
    "private_key": None,
}


def merge_args_with_config(args, config: PeerixConfig) -> None:
    """
    Merge CLI arguments with config file values.

    CLI arguments take precedence. Config values are only applied
    if the CLI argument is at its default value.

    Modifies args in place.

    Args:
        args: argparse Namespace object
        config: PeerixConfig loaded from file
    """
    # Daemon settings
    if getattr(args, "port", CLI_DEFAULTS["port"]) == CLI_DEFAULTS["port"]:
        args.port = config.daemon.port

    if getattr(args, "timeout", CLI_DEFAULTS["timeout"]) == CLI_DEFAULTS["timeout"]:
        args.timeout = config.daemon.timeout

    if getattr(args, "mode", CLI_DEFAULTS["mode"]) == CLI_DEFAULTS["mode"]:
        args.mode = config.daemon.mode

    if getattr(args, "priority", CLI_DEFAULTS["priority"]) == CLI_DEFAULTS["priority"]:
        args.priority = config.daemon.priority

    # Verbose/loglevel - config can enable verbose mode
    if getattr(args, "loglevel", CLI_DEFAULTS["loglevel"]) == CLI_DEFAULTS["loglevel"]:
        if config.daemon.verbose:
            args.loglevel = logging.DEBUG

    # IPFS settings
    if getattr(args, "tracker_url", CLI_DEFAULTS["tracker_url"]) == CLI_DEFAULTS["tracker_url"]:
        args.tracker_url = config.ipfs.tracker_url

    if getattr(args, "scan_interval", CLI_DEFAULTS["scan_interval"]) == CLI_DEFAULTS["scan_interval"]:
        args.scan_interval = config.ipfs.scan_interval

    if getattr(args, "ipfs_concurrency", CLI_DEFAULTS["ipfs_concurrency"]) == CLI_DEFAULTS["ipfs_concurrency"]:
        args.ipfs_concurrency = config.ipfs.concurrency

    # Signing settings
    if getattr(args, "private_key", CLI_DEFAULTS["private_key"]) == CLI_DEFAULTS["private_key"]:
        args.private_key = config.signing.private_key
