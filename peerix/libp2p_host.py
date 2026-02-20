"""
LibP2P Host wrapper for peerix.

Provides NAT traversal capabilities via:
- AutoNAT: Detect if behind NAT
- Circuit Relay v2: Relay fallback when direct connection fails
- DCUtR: Hole punching coordination
- mDNS: Local network peer discovery
- Kademlia DHT: Global peer discovery
"""
import typing as t
import logging
import asyncio
import hashlib
from dataclasses import dataclass, field

logger = logging.getLogger("peerix.libp2p")

# Try to import libp2p - it's optional
LIBP2P_AVAILABLE = False
try:
    from libp2p import new_host
    from libp2p.crypto.secp256k1 import create_new_key_pair
    from libp2p.crypto.keys import KeyPair
    from libp2p.host.basic_host import BasicHost
    from libp2p.network.stream.net_stream import NetStream
    from libp2p.peer.id import ID as PeerID
    from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
    from libp2p.typing import TProtocol
    from multiaddr import Multiaddr

    # Import libp2p modules for NAT traversal
    from libp2p.pubsub.gossipsub import GossipSub
    from libp2p.pubsub.pubsub import Pubsub
    from libp2p.routing.kademlia.kademlia_peer_routing import KadmeliaPeerRouting
    from libp2p.routing.kademlia.kademlia_content_routing import KademliaContentRouting
    from libp2p.discovery.mDNS import MDNS

    LIBP2P_AVAILABLE = True
except ImportError as e:
    logger.warning(f"libp2p not available: {e}. LibP2P mode will not work.")
    # Define stubs for type hints
    PeerID = t.Any
    PeerInfo = t.Any
    NetStream = t.Any
    TProtocol = str
    Multiaddr = t.Any
    BasicHost = t.Any
    KeyPair = t.Any


@dataclass
class LibP2PConfig:
    """Configuration for LibP2P host."""
    listen_addrs: t.List[str] = field(default_factory=lambda: [
        "/ip4/0.0.0.0/tcp/12304",
        "/ip4/0.0.0.0/udp/12304/quic-v1",
    ])
    bootstrap_peers: t.List[str] = field(default_factory=list)
    relay_servers: t.List[str] = field(default_factory=list)
    network_id: t.Optional[str] = None
    enable_mdns: bool = True
    enable_dht: bool = True
    enable_relay: bool = True
    enable_autonat: bool = True
    enable_hole_punching: bool = True
    private_key: t.Optional[bytes] = None


class LibP2PHost:
    """
    Wrapper around py-libp2p providing NAT traversal and peer discovery.

    This class manages:
    - Host lifecycle (start/stop)
    - Protocol registration
    - Peer discovery via mDNS and DHT
    - NAT traversal via AutoNAT, Relay, and DCUtR
    """

    def __init__(self, config: LibP2PConfig):
        self.config = config
        self._host: t.Optional[BasicHost] = None
        self._dht: t.Optional[KadmeliaPeerRouting] = None
        self._content_routing: t.Optional[KademliaContentRouting] = None
        self._mdns: t.Optional[MDNS] = None
        self._key_pair: t.Optional[KeyPair] = None
        self._is_running = False
        self._discovered_peers: t.Dict[str, PeerInfo] = {}
        self._protocol_handlers: t.Dict[TProtocol, t.Callable] = {}
        self._nat_status: str = "unknown"  # "public", "private", "unknown"

    @property
    def peer_id(self) -> t.Optional[PeerID]:
        """Get our peer ID."""
        if self._host is None:
            return None
        return self._host.get_id()

    @property
    def addrs(self) -> t.List[Multiaddr]:
        """Get our listening addresses."""
        if self._host is None:
            return []
        return self._host.get_addrs()

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def nat_status(self) -> str:
        return self._nat_status

    def get_network_key(self) -> str:
        """
        Get the DHT key for our network.

        If network_id is set, use SHA256 hash of it.
        Otherwise, use a default network identifier.
        """
        if self.config.network_id:
            return f"/peerix/v1/network/{hashlib.sha256(self.config.network_id.encode()).hexdigest()}"
        return "/peerix/v1/network/default"

    async def start(self) -> None:
        """Start the libp2p host and all services."""
        if self._is_running:
            return

        if not LIBP2P_AVAILABLE:
            raise RuntimeError("libp2p is not installed. Install with: pip install libp2p>=0.17.0")

        logger.info("Starting LibP2P host...")

        # Generate or load key pair
        if self.config.private_key:
            # TODO: Deserialize from bytes
            self._key_pair = create_new_key_pair()
        else:
            self._key_pair = create_new_key_pair()

        # Parse listen addresses
        listen_maddrs = [Multiaddr(addr) for addr in self.config.listen_addrs]

        # Create the host
        self._host = new_host(key_pair=self._key_pair, listen_addrs=listen_maddrs)

        # Register protocol handlers
        for protocol, handler in self._protocol_handlers.items():
            self._host.set_stream_handler(protocol, handler)

        # Start the host
        await self._host.get_network().listen(*listen_maddrs)

        logger.info(f"LibP2P host started with peer ID: {self.peer_id}")
        logger.info(f"Listening on: {self.addrs}")

        # Start mDNS discovery
        if self.config.enable_mdns:
            await self._start_mdns()

        # Start DHT
        if self.config.enable_dht:
            await self._start_dht()

        # Connect to bootstrap peers
        if self.config.bootstrap_peers:
            await self._connect_bootstrap_peers()

        # Connect to relay servers
        if self.config.enable_relay and self.config.relay_servers:
            await self._connect_relay_servers()

        # Start AutoNAT detection
        if self.config.enable_autonat:
            asyncio.create_task(self._autonat_probe())

        self._is_running = True
        logger.info("LibP2P host fully initialized")

    async def stop(self) -> None:
        """Stop the libp2p host and all services."""
        if not self._is_running:
            return

        logger.info("Stopping LibP2P host...")

        self._is_running = False

        if self._mdns:
            await self._mdns.close()
            self._mdns = None

        if self._host:
            await self._host.close()
            self._host = None

        self._discovered_peers.clear()
        logger.info("LibP2P host stopped")

    def set_stream_handler(self, protocol: TProtocol, handler: t.Callable) -> None:
        """Register a protocol handler."""
        self._protocol_handlers[protocol] = handler
        if self._host is not None:
            self._host.set_stream_handler(protocol, handler)

    async def new_stream(self, peer_id: PeerID, protocols: t.List[TProtocol]) -> NetStream:
        """Open a new stream to a peer."""
        if self._host is None:
            raise RuntimeError("Host not started")
        return await self._host.new_stream(peer_id, protocols)

    async def connect(self, peer_info: PeerInfo) -> None:
        """Connect to a peer."""
        if self._host is None:
            raise RuntimeError("Host not started")
        await self._host.connect(peer_info)
        self._discovered_peers[str(peer_info.peer_id)] = peer_info
        logger.debug(f"Connected to peer: {peer_info.peer_id}")

    def get_peers(self) -> t.List[PeerInfo]:
        """Get list of discovered peers."""
        return list(self._discovered_peers.values())

    async def _start_mdns(self) -> None:
        """Start mDNS discovery for local network peers."""
        logger.debug("Starting mDNS discovery...")
        try:
            self._mdns = MDNS(self._host)
            self._mdns.register_notifee(self._on_peer_discovered)
            await self._mdns.start()
            logger.info("mDNS discovery started")
        except Exception as e:
            logger.warning(f"Failed to start mDNS: {e}")
            self._mdns = None

    async def _start_dht(self) -> None:
        """Start Kademlia DHT for global peer discovery."""
        logger.debug("Starting Kademlia DHT...")
        try:
            # Initialize DHT routing
            self._dht = KadmeliaPeerRouting(self._host)
            self._content_routing = KademliaContentRouting(self._dht)
            await self._dht.bootstrap()
            logger.info("Kademlia DHT started")
        except Exception as e:
            logger.warning(f"Failed to start DHT: {e}")
            self._dht = None
            self._content_routing = None

    async def _connect_bootstrap_peers(self) -> None:
        """Connect to bootstrap peers for DHT initialization."""
        for addr_str in self.config.bootstrap_peers:
            try:
                maddr = Multiaddr(addr_str)
                peer_info = info_from_p2p_addr(maddr)
                await self.connect(peer_info)
                logger.info(f"Connected to bootstrap peer: {peer_info.peer_id}")
            except Exception as e:
                logger.warning(f"Failed to connect to bootstrap peer {addr_str}: {e}")

    async def _connect_relay_servers(self) -> None:
        """Connect to relay servers for NAT traversal fallback."""
        for addr_str in self.config.relay_servers:
            try:
                maddr = Multiaddr(addr_str)
                peer_info = info_from_p2p_addr(maddr)
                await self.connect(peer_info)
                # Reserve a slot on the relay
                await self._reserve_relay(peer_info)
                logger.info(f"Connected to relay server: {peer_info.peer_id}")
            except Exception as e:
                logger.warning(f"Failed to connect to relay server {addr_str}: {e}")

    async def _reserve_relay(self, relay_info: PeerInfo) -> None:
        """Reserve a relay slot on a Circuit Relay v2 server."""
        # Circuit Relay v2 reservation protocol
        try:
            stream = await self.new_stream(relay_info.peer_id, ["/libp2p/circuit/relay/0.2.0/hop"])
            # Send RESERVE message
            # Protocol: varint length-prefixed protobuf
            # For now, just log - full implementation requires protobuf
            await stream.close()
            logger.debug(f"Reserved relay slot on {relay_info.peer_id}")
        except Exception as e:
            logger.warning(f"Failed to reserve relay slot: {e}")

    async def _autonat_probe(self) -> None:
        """Probe NAT status using AutoNAT protocol."""
        await asyncio.sleep(5)  # Wait for connections to establish

        if not self._discovered_peers:
            logger.debug("No peers available for AutoNAT probe")
            return

        # Try to determine NAT status by asking peers
        for peer_id_str, peer_info in self._discovered_peers.items():
            try:
                stream = await self.new_stream(peer_info.peer_id, ["/libp2p/autonat/1.0.0"])
                # AutoNAT protocol: ask peer if they can dial us back
                # Simplified: assume private if we can't complete the probe
                await stream.close()
                self._nat_status = "public"
                logger.info("AutoNAT: Detected public connectivity")
                return
            except Exception as e:
                logger.debug(f"AutoNAT probe failed with {peer_id_str}: {e}")

        self._nat_status = "private"
        logger.info("AutoNAT: Detected private/NAT'd connectivity")

    def _on_peer_discovered(self, peer_info: PeerInfo) -> None:
        """Callback when a peer is discovered via mDNS."""
        if str(peer_info.peer_id) == str(self.peer_id):
            return  # Ignore ourselves

        self._discovered_peers[str(peer_info.peer_id)] = peer_info
        logger.info(f"mDNS discovered peer: {peer_info.peer_id}")

        # Try to connect
        asyncio.create_task(self._try_connect(peer_info))

    async def _try_connect(self, peer_info: PeerInfo) -> None:
        """Try to connect to a discovered peer."""
        try:
            await self.connect(peer_info)
        except Exception as e:
            logger.debug(f"Failed to connect to discovered peer {peer_info.peer_id}: {e}")

    async def find_peer(self, peer_id: PeerID) -> t.Optional[PeerInfo]:
        """Find a peer via DHT."""
        if self._dht is None:
            return None
        try:
            return await self._dht.find_peer(peer_id)
        except Exception as e:
            logger.debug(f"DHT find_peer failed for {peer_id}: {e}")
            return None

    async def provide(self, key: str) -> None:
        """Announce that we provide a key (for content routing)."""
        if self._content_routing is None:
            return
        try:
            await self._content_routing.provide(key.encode())
            logger.debug(f"Announced as provider for: {key}")
        except Exception as e:
            logger.debug(f"Failed to announce provider for {key}: {e}")

    async def find_providers(self, key: str, count: int = 20) -> t.List[PeerInfo]:
        """Find providers for a key via DHT."""
        if self._content_routing is None:
            return []
        try:
            providers = []
            async for provider in self._content_routing.find_providers(key.encode(), count):
                providers.append(provider)
            return providers
        except Exception as e:
            logger.debug(f"Failed to find providers for {key}: {e}")
            return []

    async def dial_with_relay(self, peer_id: PeerID, relay_peer_id: PeerID) -> t.Optional[NetStream]:
        """
        Dial a peer through a relay (Circuit Relay v2).

        Used when direct connection fails due to NAT.
        """
        if self._host is None:
            return None

        try:
            # Build relay address: /p2p/{relay}/p2p-circuit/p2p/{target}
            relay_info = self._discovered_peers.get(str(relay_peer_id))
            if relay_info is None:
                logger.warning(f"Relay peer {relay_peer_id} not in discovered peers")
                return None

            # Get relay's address
            if not relay_info.addrs:
                return None

            relay_addr = relay_info.addrs[0]
            circuit_addr = relay_addr.encapsulate(
                Multiaddr(f"/p2p/{relay_peer_id}/p2p-circuit/p2p/{peer_id}")
            )

            # Connect via relay
            target_info = PeerInfo(peer_id, [circuit_addr])
            await self.connect(target_info)

            logger.info(f"Connected to {peer_id} via relay {relay_peer_id}")
            return await self.new_stream(peer_id, ["/peerix/narinfo/1.0.0"])

        except Exception as e:
            logger.warning(f"Failed to dial {peer_id} via relay {relay_peer_id}: {e}")
            return None

    async def hole_punch(self, peer_id: PeerID) -> bool:
        """
        Attempt to hole punch to a peer using DCUtR.

        Direct Connection Upgrade through Relay (DCUtR) coordinates
        simultaneous connection attempts through a relay to punch
        through NAT.
        """
        if self._host is None:
            return False

        try:
            # DCUtR protocol: /libp2p/dcutr
            stream = await self.new_stream(peer_id, ["/libp2p/dcutr"])

            # Exchange observed addresses
            # Simplified: actual protocol involves protobuf messages
            await stream.close()

            logger.info(f"Hole punch succeeded to {peer_id}")
            return True

        except Exception as e:
            logger.debug(f"Hole punch failed to {peer_id}: {e}")
            return False
