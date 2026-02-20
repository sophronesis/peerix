"""
DHT discovery for peerix via libp2p Kademlia DHT.

Provides peer discovery and content routing using DHT keys:
- /peerix/v1/network/{network_id}: Network-wide peer discovery
- /peerix/v1/nar/{narHash}: Content-addressed NAR discovery
- /peerix/v1/path/{storePathHash}: Store path discovery (compatibility)
"""
import typing as t
import logging
import hashlib
import asyncio
from dataclasses import dataclass

from libp2p.peer.id import ID as PeerID
from libp2p.peer.peerinfo import PeerInfo

if t.TYPE_CHECKING:
    from peerix.libp2p_host import LibP2PHost


logger = logging.getLogger("peerix.libp2p.dht")


# DHT key prefixes
DHT_PREFIX_NETWORK = "/peerix/v1/network"
DHT_PREFIX_NAR = "/peerix/v1/nar"
DHT_PREFIX_PATH = "/peerix/v1/path"

# Announcement intervals
ANNOUNCE_INTERVAL = 60  # seconds
DISCOVERY_INTERVAL = 30  # seconds


@dataclass
class DHTConfig:
    """Configuration for DHT operations."""
    network_id: t.Optional[str] = None
    announce_interval: float = ANNOUNCE_INTERVAL
    discovery_interval: float = DISCOVERY_INTERVAL
    max_providers_per_key: int = 20


class PeerixDHT:
    """
    DHT-based discovery for peerix peers.

    Handles:
    - Network peer announcement and discovery
    - Content-addressed NAR provider tracking
    - Store path provider tracking (for compatibility)
    """

    def __init__(self, host: "LibP2PHost", config: DHTConfig):
        self.host = host
        self.config = config
        self._announce_task: t.Optional[asyncio.Task] = None
        self._discovery_task: t.Optional[asyncio.Task] = None
        self._discovered_peers: t.Set[str] = set()
        self._is_running = False

    @property
    def network_key(self) -> str:
        """Get the DHT key for network discovery."""
        if self.config.network_id:
            network_hash = hashlib.sha256(self.config.network_id.encode()).hexdigest()
            return f"{DHT_PREFIX_NETWORK}/{network_hash}"
        return f"{DHT_PREFIX_NETWORK}/default"

    async def start(self) -> None:
        """Start DHT announcement and discovery tasks."""
        if self._is_running:
            return

        self._is_running = True
        logger.info(f"Starting DHT with network key: {self.network_key}")

        # Start periodic announcement
        self._announce_task = asyncio.create_task(self._announce_loop())

        # Start periodic discovery
        self._discovery_task = asyncio.create_task(self._discovery_loop())

    async def stop(self) -> None:
        """Stop DHT tasks."""
        self._is_running = False

        if self._announce_task:
            self._announce_task.cancel()
            try:
                await self._announce_task
            except asyncio.CancelledError:
                pass
            self._announce_task = None

        if self._discovery_task:
            self._discovery_task.cancel()
            try:
                await self._discovery_task
            except asyncio.CancelledError:
                pass
            self._discovery_task = None

        logger.info("DHT stopped")

    async def announce(self) -> None:
        """Announce ourselves as a peerix peer on the network."""
        await self.host.provide(self.network_key)
        logger.debug(f"Announced on network: {self.network_key}")

    async def discover_peers(self) -> t.List[PeerInfo]:
        """Discover peerix peers on the network."""
        providers = await self.host.find_providers(
            self.network_key,
            count=self.config.max_providers_per_key
        )

        new_peers = []
        for provider in providers:
            peer_id_str = str(provider.peer_id)
            if peer_id_str not in self._discovered_peers:
                self._discovered_peers.add(peer_id_str)
                new_peers.append(provider)
                logger.info(f"Discovered new peer: {provider.peer_id}")

        return new_peers

    async def announce_nar(self, nar_hash: str) -> None:
        """
        Announce that we have a NAR with the given hash.

        Args:
            nar_hash: The NAR hash (sha256:base32... format)
        """
        # Normalize the hash for DHT key
        key = self._nar_key(nar_hash)
        await self.host.provide(key)
        logger.debug(f"Announced NAR: {key}")

    async def find_nar_providers(self, nar_hash: str) -> t.List[PeerInfo]:
        """
        Find peers that have a NAR with the given hash.

        Args:
            nar_hash: The NAR hash to find providers for

        Returns:
            List of peer infos that have this NAR
        """
        key = self._nar_key(nar_hash)
        providers = await self.host.find_providers(
            key,
            count=self.config.max_providers_per_key
        )
        logger.debug(f"Found {len(providers)} providers for NAR: {nar_hash}")
        return providers

    async def announce_path(self, store_path_hash: str) -> None:
        """
        Announce that we have a store path with the given hash.

        This is for compatibility with input-addressed paths.

        Args:
            store_path_hash: The store path hash (32 char prefix)
        """
        key = f"{DHT_PREFIX_PATH}/{store_path_hash}"
        await self.host.provide(key)
        logger.debug(f"Announced path: {key}")

    async def find_path_providers(self, store_path_hash: str) -> t.List[PeerInfo]:
        """
        Find peers that have a store path with the given hash.

        Args:
            store_path_hash: The store path hash to find

        Returns:
            List of peer infos that have this path
        """
        key = f"{DHT_PREFIX_PATH}/{store_path_hash}"
        providers = await self.host.find_providers(
            key,
            count=self.config.max_providers_per_key
        )
        logger.debug(f"Found {len(providers)} providers for path: {store_path_hash}")
        return providers

    def _nar_key(self, nar_hash: str) -> str:
        """Convert NAR hash to DHT key."""
        # NAR hashes come in formats like:
        # - sha256:base32...
        # - sha256-base64...
        # Normalize to a consistent DHT key
        if nar_hash.startswith("sha256:"):
            hash_part = nar_hash[7:]  # Remove "sha256:" prefix
        elif nar_hash.startswith("sha256-"):
            hash_part = nar_hash[7:]  # Remove "sha256-" prefix
        else:
            hash_part = nar_hash

        # Use SHA256 of the hash for consistent key length
        normalized = hashlib.sha256(hash_part.encode()).hexdigest()
        return f"{DHT_PREFIX_NAR}/{normalized}"

    async def _announce_loop(self) -> None:
        """Periodically announce ourselves."""
        while self._is_running:
            try:
                await self.announce()
            except Exception as e:
                logger.warning(f"Announcement failed: {e}")

            await asyncio.sleep(self.config.announce_interval)

    async def _discovery_loop(self) -> None:
        """Periodically discover new peers."""
        while self._is_running:
            try:
                new_peers = await self.discover_peers()

                # Connect to newly discovered peers
                for peer in new_peers:
                    try:
                        await self.host.connect(peer)
                    except Exception as e:
                        logger.debug(f"Failed to connect to discovered peer {peer.peer_id}: {e}")

            except Exception as e:
                logger.warning(f"Discovery failed: {e}")

            await asyncio.sleep(self.config.discovery_interval)

    def get_discovered_peers(self) -> t.Set[str]:
        """Get the set of discovered peer IDs."""
        return self._discovered_peers.copy()


def compute_network_id_from_tracker(tracker_url: str) -> str:
    """
    Compute a network ID from a tracker URL.

    This allows existing tracker-based networks to automatically
    join the same libp2p network when migrating.

    Args:
        tracker_url: The tracker URL (e.g., "https://peerix.example.com")

    Returns:
        A consistent network ID string
    """
    # SHA256 of the tracker URL gives a unique but reproducible ID
    return hashlib.sha256(tracker_url.encode()).hexdigest()
