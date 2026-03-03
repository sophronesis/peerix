"""
Asyncio-based LAN peer discovery using UDP broadcast.

This provides zero-config peer discovery on local networks
without requiring a tracker or Iroh relay.
"""

import asyncio
import socket
import logging
import typing as t
from dataclasses import dataclass

import psutil
import httpx

logger = logging.getLogger("peerix.lan_discovery")


def get_broadcast_addresses() -> t.List[str]:
    """Get broadcast addresses for all private network interfaces."""
    import ipaddress
    broadcasts = []
    for interface, iaddrs in psutil.net_if_addrs().items():
        for iaddr in iaddrs:
            if iaddr.broadcast is None or iaddr.family != socket.AF_INET:
                continue
            try:
                ifa = ipaddress.IPv4Interface(f"{iaddr.address}/{iaddr.netmask}")
                if ifa.network.is_private:
                    broadcasts.append(str(ifa.network.broadcast_address))
            except Exception:
                continue
    return list(set(broadcasts))


def get_local_addresses() -> t.Set[str]:
    """Get all local IP addresses."""
    local = set()
    for interface, iaddrs in psutil.net_if_addrs().items():
        for iaddr in iaddrs:
            if iaddr.family == socket.AF_INET:
                local.add(iaddr.address)
    return local


@dataclass
class LANPeer:
    """A discovered LAN peer."""
    address: str
    port: int
    last_seen: float = 0.0


class LANDiscovery:
    """
    UDP broadcast-based LAN peer discovery.

    Protocol:
    - Request: byte[0]=0, bytes[1:5]=request_id, bytes[5:]=hash
    - Response: byte[0]=1, bytes[1:5]=request_id, bytes[5:9]=port, bytes[9:]=url
    """

    def __init__(self, local_store, port: int = 12304, timeout: float = 0.5):
        self.local_store = local_store
        self.port = port
        self.timeout = timeout
        self._sock: t.Optional[asyncio.DatagramProtocol] = None
        self._transport: t.Optional[asyncio.DatagramTransport] = None
        self._request_id = 0
        self._pending: t.Dict[int, asyncio.Future] = {}
        self._running = False
        self._local_addrs = get_local_addresses()
        self._http_client: t.Optional[httpx.AsyncClient] = None

    async def start(self):
        """Start the LAN discovery service."""
        logger.info(f"Starting LAN discovery on port {self.port}")

        # Create UDP socket
        loop = asyncio.get_running_loop()
        self._transport, self._sock = await loop.create_datagram_endpoint(
            lambda: LANProtocol(self),
            local_addr=("0.0.0.0", self.port),
            allow_broadcast=True,
        )

        # Set socket options
        sock = self._transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self._http_client = httpx.AsyncClient(timeout=10.0)
        self._running = True
        logger.info(f"LAN discovery started, broadcasts: {get_broadcast_addresses()}")

    async def stop(self):
        """Stop the LAN discovery service."""
        self._running = False
        if self._transport:
            self._transport.close()
            self._transport = None
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        logger.info("LAN discovery stopped")

    async def discover_narinfo(self, hash_part: str) -> t.Optional[t.Tuple[str, str, int]]:
        """
        Broadcast request for a narinfo and wait for response.

        Returns:
            Tuple of (narinfo_content, peer_address, port) if found, None otherwise
        """
        if not self._transport:
            return None

        # Generate request ID
        self._request_id += 1
        request_id = self._request_id

        # Create request: type(1) + id(4) + hash
        request = bytes([0]) + request_id.to_bytes(4, "big") + hash_part.encode("utf-8")

        # Create future for response
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        # Broadcast to all interfaces
        broadcasts = get_broadcast_addresses()
        for addr in broadcasts:
            try:
                self._transport.sendto(request, (addr, self.port))
                logger.debug(f"Sent LAN request for {hash_part} to {addr}:{self.port}")
            except Exception as e:
                logger.debug(f"Failed to send to {addr}: {e}")

        # Wait for response with timeout
        try:
            result = await asyncio.wait_for(future, timeout=self.timeout)
            peer_addr, peer_port, url = result

            # Fetch narinfo from peer
            narinfo_url = f"http://{peer_addr}:{peer_port}/{url}"
            logger.info(f"LAN peer {peer_addr}:{peer_port} has {hash_part}")

            resp = await self._http_client.get(narinfo_url)
            if resp.status_code == 200:
                return (resp.text, peer_addr, peer_port)

        except asyncio.TimeoutError:
            logger.debug(f"No LAN response for {hash_part}")
        except Exception as e:
            logger.debug(f"LAN discovery error: {e}")
        finally:
            self._pending.pop(request_id, None)

        return None

    async def _handle_request(self, data: bytes, addr: t.Tuple[str, int]):
        """Handle incoming narinfo request."""
        if addr[0] in self._local_addrs:
            return  # Ignore our own broadcasts

        request_id = int.from_bytes(data[1:5], "big")
        hash_part = data[5:].decode("utf-8")

        logger.debug(f"LAN request from {addr[0]}:{addr[1]} for {hash_part}")

        # Check if we have it
        narinfo = await self.local_store.narinfo(hash_part)
        if narinfo is None:
            return

        # Send response: type(1) + id(4) + port(4) + url
        response = (
            bytes([1]) +
            request_id.to_bytes(4, "big") +
            self.port.to_bytes(4, "big") +
            f"local/{hash_part}.narinfo".encode("utf-8")
        )

        self._transport.sendto(response, addr)
        logger.debug(f"Sent LAN response for {hash_part} to {addr[0]}:{addr[1]}")

    def _handle_response(self, data: bytes, addr: t.Tuple[str, int]):
        """Handle incoming narinfo response."""
        request_id = int.from_bytes(data[1:5], "big")
        port = int.from_bytes(data[5:9], "big")
        url = data[9:].decode("utf-8")

        if request_id in self._pending:
            future = self._pending[request_id]
            if not future.done():
                future.set_result((addr[0], port, url))


class LANProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol handler for LAN discovery."""

    def __init__(self, discovery: LANDiscovery):
        self.discovery = discovery

    def datagram_received(self, data: bytes, addr: t.Tuple[str, int]):
        """Handle received datagram."""
        if len(data) < 5:
            return

        msg_type = data[0]
        if msg_type == 0:  # Request
            asyncio.create_task(self.discovery._handle_request(data, addr))
        elif msg_type == 1:  # Response
            self.discovery._handle_response(data, addr)

    def error_received(self, exc: Exception):
        """Handle error."""
        logger.debug(f"LAN protocol error: {exc}")
