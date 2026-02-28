"""
Iroh-based P2P prototype for Peerix.

This module provides NAT-traversing peer-to-peer connectivity using Iroh.
Peers are identified by public keys, not IP addresses.
"""

import asyncio
import logging
import typing as t
from dataclasses import dataclass

import httpx
import iroh

logger = logging.getLogger(__name__)

# Tracker announce interval (seconds)
ANNOUNCE_INTERVAL = 60
# Peer discovery interval (seconds)
DISCOVERY_INTERVAL = 30

# Protocol identifiers (ALPN)
NARINFO_PROTOCOL = b"peerix/narinfo/1"
NAR_PROTOCOL = b"peerix/nar/1"


@dataclass
class PeerInfo:
    """Information about a peer."""
    node_id: str  # Public key (base32)
    addrs: t.List[str]  # Known addresses (for bootstrapping)


class NarinfoProtocol(iroh.ProtocolHandler):
    """Protocol handler for narinfo requests."""

    def __init__(self, local_store):
        self.local_store = local_store

    async def accept(self, conn: iroh.Connection):
        """Handle incoming narinfo request."""
        try:
            remote_id = conn.remote_node_id()
            logger.debug(f"Narinfo request from {remote_id}")

            # Accept bidirectional stream
            bi = await conn.accept_bi()
            recv = bi.recv()
            send = bi.send()

            # Read the hash being requested
            data = await recv.read_to_end(64)
            nar_hash = data.decode('utf-8').strip()
            logger.debug(f"Looking up narinfo for {nar_hash}")

            # Look up in local store
            narinfo = await self.local_store.narinfo(nar_hash)

            if narinfo:
                response = narinfo.dump().encode('utf-8')
                logger.debug(f"Sending narinfo ({len(response)} bytes)")
            else:
                response = b"NOTFOUND"
                logger.debug(f"Narinfo not found for {nar_hash}")

            await send.write_all(response)
            await send.finish()

        except Exception as e:
            logger.error(f"Error handling narinfo request: {e}")

    async def shutdown(self):
        """Clean up on shutdown."""
        pass


class NarinfoProtocolCreator(iroh.ProtocolCreator):
    """Factory for NarinfoProtocol."""

    def __init__(self, local_store):
        self.local_store = local_store

    def create(self, endpoint) -> iroh.ProtocolHandler:
        return NarinfoProtocol(self.local_store)


class NarProtocol(iroh.ProtocolHandler):
    """Protocol handler for NAR streaming."""

    def __init__(self, local_store):
        self.local_store = local_store

    async def accept(self, conn: iroh.Connection):
        """Handle incoming NAR request."""
        try:
            remote_id = conn.remote_node_id()
            logger.debug(f"NAR request from {remote_id}")

            # Accept bidirectional stream
            bi = await conn.accept_bi()
            recv = bi.recv()
            send = bi.send()

            # Read the URL being requested
            url_data = await recv.read_to_end(1024)
            url = url_data.decode('utf-8').strip()
            logger.debug(f"Streaming NAR for {url}")

            # Stream NAR data
            try:
                async for chunk in self.local_store.nar(url):
                    await send.write_all(chunk)
                await send.finish()
            except Exception as e:
                logger.error(f"Error streaming NAR: {e}")
                await send.finish()

        except Exception as e:
            logger.error(f"Error handling NAR request: {e}")

    async def shutdown(self):
        """Clean up on shutdown."""
        pass


class NarProtocolCreator(iroh.ProtocolCreator):
    """Factory for NarProtocol."""

    def __init__(self, local_store):
        self.local_store = local_store

    def create(self, endpoint) -> iroh.ProtocolHandler:
        return NarProtocol(self.local_store)


class IrohNode:
    """
    Iroh-based P2P node for Peerix.

    Handles:
    - Creating endpoint with automatic NAT traversal
    - Serving narinfo/nar requests
    - Connecting to peers by public key
    """

    def __init__(self, local_store, tracker_url: str = None, peer_id: str = None):
        self.local_store = local_store
        self.tracker_url = tracker_url.rstrip("/") if tracker_url else None
        self.peer_id = peer_id or "iroh-node"  # Human-readable peer ID
        self.iroh: t.Optional[iroh.Iroh] = None
        self.node: t.Optional[iroh.Node] = None
        self.endpoint: t.Optional[iroh.Endpoint] = None
        self.net: t.Optional[iroh.Net] = None
        self._running = False
        self._node_id: t.Optional[str] = None
        # Store known peer addresses: node_id (str) -> NodeAddr
        self._known_peers: t.Dict[str, iroh.NodeAddr] = {}
        # HTTP client for tracker communication
        self._http_client: t.Optional[httpx.AsyncClient] = None

    async def start(self):
        """Start the Iroh node."""
        logger.info("Starting Iroh node...")

        # Set the event loop for iroh FFI callbacks
        iroh.iroh_ffi.uniffi_set_event_loop(asyncio.get_running_loop())

        # Set up protocol handlers
        protocols = {
            NARINFO_PROTOCOL: NarinfoProtocolCreator(self.local_store),
            NAR_PROTOCOL: NarProtocolCreator(self.local_store),
        }

        # Create node options
        options = iroh.NodeOptions()
        options.protocols = protocols

        # Create iroh instance (in-memory for now, could use persistent storage)
        self.iroh = await iroh.Iroh.memory_with_options(options)

        # Get sub-objects
        self.node = self.iroh.node()
        self.endpoint = self.node.endpoint()
        self.net = self.iroh.net()

        self._node_id = str(await self.net.node_id())
        logger.info(f"Iroh node started with ID: {self._node_id}")

        # Get our addresses for sharing
        node_addr = await self.net.node_addr()
        logger.info(f"Node address: {node_addr}")

        self._running = True

        # Initialize HTTP client for tracker
        if self.tracker_url:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0)
            )

        return self._node_id

    async def stop(self):
        """Stop the Iroh node."""
        self._running = False
        if self.node:
            try:
                await asyncio.wait_for(self.node.shutdown(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Node shutdown timed out")
            except Exception as e:
                logger.warning(f"Node shutdown error: {e}")
            self.iroh = None
            self.node = None
            self.endpoint = None
            self.net = None
        logger.info("Iroh node stopped")

    async def get_node_id(self) -> str:
        """Get our node ID (public key)."""
        if self.net:
            return str(await self.net.node_id())
        return None

    async def get_node_addr(self) -> t.Optional[iroh.NodeAddr]:
        """Get our full node address (for sharing with peers)."""
        if self.net:
            return await self.net.node_addr()
        return None

    async def add_peer(self, node_id: str, node_addr: iroh.NodeAddr):
        """Add a peer's address for later connection."""
        if self.net:
            await self.net.add_node_addr(node_addr)
            self._known_peers[node_id] = node_addr
            logger.debug(f"Added peer {node_id}")

    def _get_node_addr(self, node_id: str) -> iroh.NodeAddr:
        """Get NodeAddr for a node_id, creating minimal one if not known."""
        if node_id in self._known_peers:
            return self._known_peers[node_id]
        # Create NodeAddr from just the public key (iroh will use relay if needed)
        pub_key = iroh.PublicKey.from_string(node_id)
        return iroh.NodeAddr(pub_key, None, [])

    async def connect(self, node_id: str, protocol: bytes = NARINFO_PROTOCOL) -> iroh.Connection:
        """
        Connect to a peer by node ID.

        Iroh handles NAT traversal automatically:
        1. Tries direct connection
        2. Falls back to hole punching
        3. Falls back to relay if needed
        """
        if not self.endpoint:
            raise RuntimeError("Node not started")

        logger.debug(f"Connecting to {node_id}...")
        node_addr = self._get_node_addr(node_id)
        conn = await self.endpoint.connect(node_addr, protocol)
        logger.debug(f"Connected to {node_id}")
        return conn

    async def fetch_narinfo(self, node_id: str, nar_hash: str) -> t.Optional[str]:
        """Fetch narinfo from a peer."""
        try:
            conn = await self.connect(node_id, NARINFO_PROTOCOL)

            # Open bidirectional stream
            bi = await conn.open_bi()
            send = bi.send()
            recv = bi.recv()

            # Send hash request
            await send.write_all(nar_hash.encode('utf-8'))
            await send.finish()

            # Read response
            response = await recv.read_to_end(65536)

            if response == b"NOTFOUND":
                return None

            return response.decode('utf-8')

        except Exception as e:
            logger.warning(f"Failed to fetch narinfo from {node_id}: {e}")
            return None

    async def fetch_nar(self, node_id: str, url: str) -> t.AsyncIterator[bytes]:
        """Fetch NAR data from a peer (streaming)."""
        conn = await self.connect(node_id, NAR_PROTOCOL)

        # Open bidirectional stream
        bi = await conn.open_bi()
        send = bi.send()
        recv = bi.recv()

        # Send URL request
        await send.write_all(url.encode('utf-8'))
        await send.finish()

        # Stream response
        while True:
            chunk = await recv.read(65536)
            if not chunk:
                break
            yield chunk

    # ========== Tracker Integration ==========

    async def announce_to_tracker(self) -> bool:
        """Announce our Iroh node to the tracker."""
        if not self.tracker_url or not self._http_client:
            return False

        try:
            node_addr = await self.get_node_addr()
            if not node_addr:
                return False

            # Extract address info
            relay_url = node_addr.relay_url()
            direct_addrs = node_addr.direct_addresses()

            payload = {
                "node_id": self._node_id,
                "peer_id": self.peer_id,
                "relay_url": relay_url,
                "direct_addrs": direct_addrs,
            }

            resp = await self._http_client.post(
                f"{self.tracker_url}/iroh/announce",
                json=payload,
                timeout=30.0,
            )

            if resp.status_code == 200:
                logger.info(f"Announced to tracker: {self._node_id[:16]}...")
                return True
            else:
                logger.warning(f"Tracker announce failed: {resp.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Tracker announce error: {e}")
            return False

    async def discover_peers(self) -> t.List[t.Dict]:
        """Discover Iroh peers from the tracker."""
        if not self.tracker_url or not self._http_client:
            return []

        try:
            resp = await self._http_client.get(
                f"{self.tracker_url}/iroh/peers",
                timeout=30.0,
            )

            if resp.status_code != 200:
                logger.warning(f"Peer discovery failed: {resp.status_code}")
                return []

            data = resp.json()
            peers = data.get("peers", [])

            # Filter out ourselves
            peers = [p for p in peers if p["node_id"] != self._node_id]
            logger.debug(f"Discovered {len(peers)} peers from tracker")
            return peers

        except Exception as e:
            logger.warning(f"Peer discovery error: {e}")
            return []

    async def add_peer_from_tracker(self, peer_info: t.Dict) -> bool:
        """Add a peer using info from the tracker."""
        try:
            node_id = peer_info["node_id"]
            relay_url = peer_info.get("relay_url")
            direct_addrs = peer_info.get("direct_addrs", [])

            # Create PublicKey from node_id string
            pub_key = iroh.PublicKey.from_string(node_id)

            # Create NodeAddr with address info
            node_addr = iroh.NodeAddr(pub_key, relay_url, direct_addrs)

            # Add to our known peers
            await self.add_peer(node_id, node_addr)
            return True

        except Exception as e:
            logger.warning(f"Failed to add peer from tracker: {e}")
            return False

    async def sync_with_tracker(self):
        """Announce ourselves and discover peers from tracker."""
        if not self.tracker_url:
            return

        # Announce ourselves
        await self.announce_to_tracker()

        # Discover and add peers
        peers = await self.discover_peers()
        for peer_info in peers:
            if peer_info["node_id"] not in self._known_peers:
                await self.add_peer_from_tracker(peer_info)

    async def run_tracker_sync(self):
        """Background task to periodically sync with tracker."""
        if not self.tracker_url:
            logger.info("No tracker URL configured, skipping tracker sync")
            return

        logger.info(f"Starting tracker sync with {self.tracker_url}")

        while self._running:
            try:
                await self.sync_with_tracker()
            except Exception as e:
                logger.warning(f"Tracker sync error: {e}")

            await asyncio.sleep(ANNOUNCE_INTERVAL)


async def test_single_node():
    """Simple test of Iroh node startup."""
    print("Testing single Iroh node...", flush=True)

    # Create a simple mock store
    class MockStore:
        async def narinfo(self, hash):
            return f"StorePath: /nix/store/{hash}-test\nNarHash: sha256:test\nNarSize: 100\nReferences:\n"
        async def nar(self, url):
            yield b"test nar data"

    store = MockStore()
    node = IrohNode(store)

    try:
        print("Starting node...", flush=True)
        node_id = await node.start()
        print(f"Node started: {node_id}", flush=True)

        print("Getting node address...", flush=True)
        addr = await node.get_node_addr()
        print(f"Node address: {addr}", flush=True)

        # Keep running for a bit
        print("Sleeping 2s...", flush=True)
        await asyncio.sleep(2)
        print("Node running successfully!", flush=True)

    finally:
        print("Stopping node...", flush=True)
        await node.stop()
        print("Node stopped", flush=True)


async def test_two_nodes():
    """Test two nodes connecting to each other."""
    print("\nTesting two-node connectivity...", flush=True)

    class MockNarInfo:
        """Mock NarInfo that has a dump() method."""
        def __init__(self, content):
            self.content = content
        def dump(self):
            return self.content

    class MockStore:
        def __init__(self, name):
            self.name = name

        async def narinfo(self, hash):
            print(f"[{self.name}] narinfo requested for {hash}", flush=True)
            content = f"StorePath: /nix/store/{hash}-{self.name}\nNarHash: sha256:{self.name}\nNarSize: 100\nReferences:\n"
            return MockNarInfo(content)

        async def nar(self, url):
            yield f"NAR data from {self.name}".encode()

    # Create two nodes
    store1 = MockStore("node1")
    store2 = MockStore("node2")

    node1 = IrohNode(store1)
    node2 = IrohNode(store2)

    try:
        # Start both nodes
        print("Starting node 1...", flush=True)
        node1_id = await node1.start()
        print("Starting node 2...", flush=True)
        node2_id = await node2.start()

        print(f"Node 1: {node1_id}", flush=True)
        print(f"Node 2: {node2_id}", flush=True)

        # Get node1's address and add it to node2
        print("Getting node1 address...", flush=True)
        node1_addr = await node1.get_node_addr()
        print(f"Node 1 addr: {node1_addr}", flush=True)

        # Add node1's address to node2 so it can find it
        print("Adding node1 addr to node2...", flush=True)
        await node2.add_peer(node1_id, node1_addr)
        print("Address added", flush=True)

        # Node 2 fetches narinfo from Node 1
        print("\nNode 2 fetching narinfo from Node 1...", flush=True)
        narinfo = await asyncio.wait_for(
            node2.fetch_narinfo(node1_id, "testhash123"),
            timeout=10.0
        )

        if narinfo:
            print(f"Got narinfo:\n{narinfo}", flush=True)
        else:
            print("Failed to get narinfo", flush=True)

        await asyncio.sleep(1)

    except asyncio.TimeoutError:
        print("Timeout waiting for narinfo!", flush=True)
    finally:
        print("Stopping nodes...", flush=True)
        await node1.stop()
        await node2.stop()
        print("\nBoth nodes stopped", flush=True)


async def test_tracker_connectivity(tracker_url: str, peer_id: str):
    """Test Iroh node with tracker integration."""
    print(f"\nTesting Iroh node with tracker: {tracker_url}", flush=True)

    class MockNarInfo:
        def __init__(self, content):
            self.content = content
        def dump(self):
            return self.content

    class MockStore:
        def __init__(self, name):
            self.name = name

        async def narinfo(self, hash):
            print(f"[{self.name}] narinfo requested for {hash}", flush=True)
            content = f"StorePath: /nix/store/{hash}-{self.name}\nNarHash: sha256:{self.name}\nNarSize: 100\nReferences:\n"
            return MockNarInfo(content)

        async def nar(self, url):
            yield f"NAR data from {self.name}".encode()

    store = MockStore(peer_id)
    node = IrohNode(store, tracker_url=tracker_url, peer_id=peer_id)

    try:
        # Start node
        print("Starting Iroh node...", flush=True)
        node_id = await node.start()
        print(f"Node ID: {node_id}", flush=True)

        # Get and display our address
        node_addr = await node.get_node_addr()
        relay_url = node_addr.relay_url()
        direct_addrs = node_addr.direct_addresses()
        print(f"Relay URL: {relay_url}", flush=True)
        print(f"Direct addresses: {direct_addrs}", flush=True)

        # Sync with tracker
        print("\nSyncing with tracker...", flush=True)
        await node.sync_with_tracker()

        # Show discovered peers
        print(f"\nKnown peers: {len(node._known_peers)}", flush=True)
        for pid, addr in node._known_peers.items():
            print(f"  - {pid[:16]}...", flush=True)

        # If we have peers, try to fetch narinfo from each
        if node._known_peers:
            print("\nTesting connectivity to peers...", flush=True)
            for peer_node_id in node._known_peers:
                print(f"\nConnecting to {peer_node_id[:16]}...", flush=True)
                try:
                    narinfo = await asyncio.wait_for(
                        node.fetch_narinfo(peer_node_id, "testhash"),
                        timeout=10.0
                    )
                    if narinfo:
                        print(f"  SUCCESS! Got narinfo ({len(narinfo)} bytes)", flush=True)
                    else:
                        print(f"  Got NOTFOUND response", flush=True)
                except asyncio.TimeoutError:
                    print(f"  TIMEOUT", flush=True)
                except Exception as e:
                    print(f"  ERROR: {e}", flush=True)
        else:
            print("\nNo peers discovered yet. Run this on another machine to test connectivity.", flush=True)

        # Keep running to accept incoming connections
        print("\nNode running. Press Ctrl+C to stop.", flush=True)
        print("Other nodes can connect to:", flush=True)
        print(f"  Node ID: {node_id}", flush=True)

        # Run periodic tracker sync
        while True:
            await asyncio.sleep(ANNOUNCE_INTERVAL)
            await node.sync_with_tracker()
            print(f"[sync] Known peers: {len(node._known_peers)}", flush=True)

    except KeyboardInterrupt:
        print("\nStopping...", flush=True)
    finally:
        await node.stop()
        print("Node stopped", flush=True)


async def main():
    """Run all tests."""
    await test_single_node()
    await test_two_nodes()


def cli():
    """Command-line interface for testing Iroh connectivity."""
    import argparse
    import socket

    parser = argparse.ArgumentParser(description="Iroh P2P test node")
    parser.add_argument("--tracker", "-t", type=str, required=True,
                        help="Tracker URL (e.g., http://tracker.example.com:12305)")
    parser.add_argument("--peer-id", "-p", type=str, default=socket.gethostname(),
                        help="Human-readable peer ID (default: hostname)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    asyncio.run(test_tracker_connectivity(args.tracker, args.peer_id))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Run internal tests
        logging.basicConfig(level=logging.INFO)
        asyncio.run(main())
    else:
        # Run CLI
        cli()
