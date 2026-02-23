"""
LibP2P-based Store implementation for peerix.

Implements the Store interface using libp2p streams for
narinfo queries and NAR transfers.
"""
import typing as t
import logging

import trio

from libp2p.peer.peerinfo import PeerInfo

from peerix.store import NarInfo, CacheInfo, Store
from peerix.libp2p_protocols import (
    PROTOCOL_NARINFO,
    PROTOCOL_NAR,
    request_narinfo,
    request_nar,
)

if t.TYPE_CHECKING:
    from peerix.libp2p_host import LibP2PHost
    from peerix.libp2p_dht import PeerixDHT


logger = logging.getLogger("peerix.libp2p.store")


class LibP2PStore(Store):
    """
    Store implementation that fetches narinfo and NAR data via libp2p.

    Queries are routed to discovered peers via libp2p streams,
    with DHT-based content routing for finding providers.
    """

    def __init__(
        self,
        local_store: Store,
        host: "LibP2PHost",
        dht: "PeerixDHT",
        request_timeout: float = 30.0,
        nar_timeout: float = 300.0,
    ):
        """
        Initialize the LibP2P store.

        Args:
            local_store: The underlying local store for cache_info
            host: The libp2p host for network operations
            dht: The DHT instance for peer discovery
            request_timeout: Timeout for narinfo requests (seconds)
            nar_timeout: Timeout for NAR transfers (seconds)
        """
        self.local_store = local_store
        self.host = host
        self.dht = dht
        self.request_timeout = request_timeout
        self.nar_timeout = nar_timeout

        # Track active transfers for metrics
        self._active_transfers: t.Dict[str, int] = {}

    async def cache_info(self) -> CacheInfo:
        """Return local cache info."""
        return await self.local_store.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """
        Query narinfo from libp2p peers.

        First tries to find providers for the specific store path,
        then falls back to querying all discovered peers.

        Args:
            hsh: The store path hash to query

        Returns:
            NarInfo if found, None otherwise
        """
        # Strategy 1: Find providers via DHT
        providers = await self.dht.find_path_providers(hsh)
        if providers:
            for provider in providers:
                result = await self._query_peer_narinfo(provider, hsh)
                if result:
                    return result

        # Strategy 2: Query all discovered peers
        peers = self.host.get_peers()
        if not peers:
            logger.debug(f"No libp2p peers available for {hsh}")
            return None

        # Query peers in parallel, return first successful result
        result: t.Optional[NarInfo] = None

        async def query_peer(peer: PeerInfo, cancel_scope: trio.CancelScope) -> None:
            nonlocal result
            try:
                with trio.move_on_after(self.request_timeout):
                    r = await self._query_peer_narinfo(peer, hsh)
                    if r is not None and result is None:
                        result = r
                        cancel_scope.cancel()
            except Exception as e:
                logger.debug(f"Query failed: {e}")

        async with trio.open_nursery() as nursery:
            for peer in peers:
                nursery.start_soon(query_peer, peer, nursery.cancel_scope)

        if result is None:
            logger.debug(f"No libp2p peer has {hsh}")

        return result

    async def _query_peer_narinfo(self, peer: PeerInfo, hsh: str) -> t.Optional[NarInfo]:
        """Query a specific peer for narinfo."""
        try:
            with trio.fail_after(10.0):
                stream = await self.host.new_stream(peer.peer_id, [PROTOCOL_NARINFO])

            with trio.fail_after(self.request_timeout):
                result = await request_narinfo(stream, hsh)

            if result is not None:
                # Rewrite URL to route through our libp2p endpoint
                libp2p_url = f"libp2p/{peer.peer_id}/{hsh}/{result.url}"
                logger.info(f"Found {hsh} at libp2p peer {peer.peer_id}")
                return result._replace(url=libp2p_url)

        except trio.TooSlowError:
            logger.debug(f"Timeout querying peer {peer.peer_id} for {hsh}")
        except Exception as e:
            logger.debug(f"Failed to query peer {peer.peer_id} for {hsh}: {e}")

        return None

    async def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        """
        Fetch NAR data from a libp2p peer.

        URL format: libp2p/{peer_id}/{hash}/{nar_url}

        Args:
            url: The NAR URL from narinfo

        Returns:
            Async iterable of NAR data chunks
        """
        logger.debug(f"NAR request for URL: {url}")

        # Parse the URL
        parts = url.split("/", 3)
        if len(parts) < 4 or parts[0] != "libp2p":
            logger.warning(f"Invalid libp2p NAR URL format: {url}, parts={parts}")
            raise FileNotFoundError(f"Invalid libp2p NAR URL: {url}")

        _, peer_id_str, hsh, nar_url = parts
        logger.debug(f"Parsed NAR URL: peer={peer_id_str}, hash={hsh}, nar_url={nar_url}")

        # Find the peer
        peer = self._find_peer_by_id(peer_id_str)
        logger.debug(f"Found peer by ID: {peer}")
        if peer is None:
            # Try to find via DHT
            logger.debug(f"Peer not found locally, trying DHT for {hsh}")
            providers = await self.dht.find_path_providers(hsh)
            for p in providers:
                if str(p.peer_id) == peer_id_str:
                    peer = p
                    break

        if peer is None:
            logger.warning(f"Peer {peer_id_str} not found. Known peers: {[str(p.peer_id) for p in self.host.get_peers()]}")
            raise FileNotFoundError(f"Peer {peer_id_str} not found for NAR: {url}")

        return self._stream_nar(peer, nar_url, hsh)

    async def _stream_nar(
        self,
        peer: PeerInfo,
        nar_url: str,
        hsh: str
    ) -> t.AsyncIterable[bytes]:
        """Stream NAR data from a peer."""
        self._active_transfers[hsh] = 0

        try:
            with trio.fail_after(10.0):
                stream = await self.host.new_stream(peer.peer_id, [PROTOCOL_NAR])

            total_bytes = 0
            async for chunk in request_nar(stream, nar_url):
                total_bytes += len(chunk)
                self._active_transfers[hsh] = total_bytes
                yield chunk

            logger.info(f"LibP2P transfer from {peer.peer_id}: {total_bytes} bytes")

        except trio.TooSlowError:
            raise FileNotFoundError(f"Timeout streaming NAR from {peer.peer_id}")
        except Exception as e:
            raise FileNotFoundError(f"NAR stream failed from {peer.peer_id}: {e}")
        finally:
            self._active_transfers.pop(hsh, None)

    def _find_peer_by_id(self, peer_id_str: str) -> t.Optional[PeerInfo]:
        """Find a peer by ID string in our discovered peers."""
        for peer in self.host.get_peers():
            if str(peer.peer_id) == peer_id_str:
                return peer
        return None


class HybridStore(Store):
    """
    Hybrid store that combines libp2p and HTTP tracker-based discovery.

    Tries libp2p first for lower latency, falls back to HTTP tracker
    for compatibility with non-libp2p peers.
    """

    def __init__(
        self,
        local_store: Store,
        libp2p_store: LibP2PStore,
        tracker_store: t.Optional[Store] = None,
    ):
        """
        Initialize the hybrid store.

        Args:
            local_store: The underlying local store
            libp2p_store: The libp2p-based store
            tracker_store: Optional HTTP tracker-based store for fallback
        """
        self.local_store = local_store
        self.libp2p_store = libp2p_store
        self.tracker_store = tracker_store

    async def cache_info(self) -> CacheInfo:
        """Return local cache info."""
        return await self.local_store.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """
        Query narinfo from both libp2p and tracker peers.

        Queries both in parallel and returns the first successful result.
        """
        result: t.Optional[NarInfo] = None

        async def query_store(store: Store, cancel_scope: trio.CancelScope) -> None:
            nonlocal result
            try:
                r = await store.narinfo(hsh)
                if r is not None and result is None:
                    result = r
                    cancel_scope.cancel()
            except Exception as e:
                logger.debug(f"Hybrid query failed: {e}")

        async with trio.open_nursery() as nursery:
            nursery.start_soon(query_store, self.libp2p_store, nursery.cancel_scope)
            if self.tracker_store is not None:
                nursery.start_soon(query_store, self.tracker_store, nursery.cancel_scope)

        return result

    async def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        """
        Fetch NAR data from the appropriate store based on URL prefix.
        """
        if url.startswith("libp2p/"):
            return await self.libp2p_store.nar(url)
        elif self.tracker_store is not None:
            return await self.tracker_store.nar(url)
        else:
            raise FileNotFoundError(f"No store available for NAR URL: {url}")
