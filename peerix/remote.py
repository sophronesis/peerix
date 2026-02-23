import typing as t

import socket
import logging
import ipaddress
import contextlib

import trio
import psutil
import httpx


from peerix.store import NarInfo, Store


logger = logging.getLogger("peerix.remote")



def get_brdcasts():
    for interface, iaddrs in psutil.net_if_addrs().items():
        for iaddr in iaddrs:
            if iaddr.broadcast is None or iaddr.family != socket.AF_INET:
                continue

            ifa = ipaddress.IPv4Interface(f"{iaddr.address}/{iaddr.netmask}")
            if not ifa.network.is_private:
                continue

            yield str(ifa.network.broadcast_address)


def get_myself():
    for interface, iaddrs in psutil.net_if_addrs().items():
        for iaddr in iaddrs:
            if iaddr.broadcast is None or iaddr.family != socket.AF_INET:
                continue

            yield str(iaddr.address)


class DiscoveryProtocol(Store):
    idx: int
    sock: trio.socket.SocketType
    waiters: t.Dict[int, trio.Event]
    results: t.Dict[int, t.Tuple[int, str, t.Tuple[str, int]]]
    store: Store
    client: httpx.AsyncClient
    local_port: int
    prefix: str
    timeout: float
    _running: bool
    _nursery: t.Optional[trio.Nursery]

    def __init__(self, store: Store, client: httpx.AsyncClient, sock: trio.socket.SocketType,
                 local_port: int, prefix: str, timeout: float):
        self.idx = 0
        self.waiters = {}
        self.results = {}
        self.store = store
        self.client = client
        self.sock = sock
        self.local_port = local_port
        self.prefix = prefix
        self.timeout = timeout
        self._running = False
        self._nursery = None

    async def start(self, nursery: trio.Nursery):
        self._running = True
        self._nursery = nursery
        nursery.start_soon(self._receive_loop)

    def stop(self):
        self._running = False
        self.sock.close()

    async def _receive_loop(self):
        while self._running:
            try:
                data, addr = await self.sock.recvfrom(65535)
                await self._handle_datagram(data, addr)
            except trio.ClosedResourceError:
                break
            except Exception as e:
                logger.debug(f"Error receiving datagram: {e}")

    async def _handle_datagram(self, data: bytes, addr: t.Tuple[str, int]) -> None:
        if addr[0] in set(get_myself()):
            logger.debug(f"Ignoring packet from {addr[0]}")
            return

        # 1 => Response to a command of mine.
        if data[0] == 1:
            idx = int.from_bytes(data[1:5], "big")
            if idx not in self.waiters:
                return

            self.results[idx] = (int.from_bytes(data[5:9], "big"), data[9:].decode("utf-8"), addr)
            self.waiters[idx].set()

        # 0 => Request from another server.
        elif data[0] == 0:
            if self._nursery:
                self._nursery.start_soon(self._respond, data, addr)

    async def cache_info(self):
        return await self.store.cache_info()

    async def _respond(self, data: bytes, addr: t.Tuple[str, int]) -> None:
        hsh = data[5:].decode("utf-8")
        logger.info(f"Got request from {addr[0]}:{addr[1]} for {hsh}")
        narinfo = await self.store.narinfo(hsh)
        if narinfo is None:
            logger.debug(f"{hsh} not found")
            return

        logger.debug(f"{hsh} was found.")
        response = b"".join([
            b"\x01",
            data[1:5],
            self.local_port.to_bytes(4, "big"),
            self.prefix.encode("utf-8"),
            b"/",
            hsh.encode("utf-8"),
            b".narinfo"
        ])
        await self.sock.sendto(response, addr)

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        event = trio.Event()
        self.idx = (idx := self.idx) + 1
        self.waiters[idx] = event

        logging.info(f"Requesting {hsh} from direct local network.")
        request = b"".join([b"\x00", idx.to_bytes(4, "big"), hsh.encode("utf-8")])

        for addr in set(get_brdcasts()):
            logging.debug(f"Sending request for {hsh} to {addr}:{self.local_port}")
            try:
                await self.sock.sendto(request, (addr, self.local_port))
            except Exception as e:
                logger.debug(f"Failed to send to {addr}: {e}")

        try:
            with trio.move_on_after(self.timeout):
                await event.wait()
                if idx in self.results:
                    port, url, addr = self.results.pop(idx)
                    logging.info(f"{addr[0]}:{addr[1]} responded for {hsh} with http://{addr[0]}:{port}/{url}")

                    resp = await self.client.get(f"http://{addr[0]}:{port}/{url}")
                    if resp.status_code != 200:
                        return None
                    info = NarInfo.parse(resp.text)
                    return info._replace(url=f"{addr[0]}/{port}/{hsh}/{info.url}")
        finally:
            self.waiters.pop(idx, None)
            self.results.pop(idx, None)

        logging.debug(f"No response for {hsh}")
        return None

    async def nar(self, sp: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        try:
            return await self._nar_req(sp)
        except FileNotFoundError:
            addr1, addr2, hsh, _ = sp.split("/", 2)
            logging.warning(f"Remote({addr1}:{addr2})-store path is dead: {sp}")
            pass

        _, _, hsh, _ = sp.split("/", 3)
        narinfo = await self.narinfo(hsh)
        if narinfo is None:
            logging.warning(f"All sources are gone.")
            raise FileNotFoundError()

        return await self._nar_req(narinfo.url)

    async def _nar_req(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        addr1, addr2, _, p = url.split("/", 3)
        # Use streaming response
        return self._nar_stream(f"http://{addr1}:{addr2}/{p}")

    async def _nar_stream(self, url: str) -> t.AsyncIterable[bytes]:
        async with self.client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise FileNotFoundError()
            async for chunk in resp.aiter_bytes():
                yield chunk


@contextlib.asynccontextmanager
async def remote(store: Store, local_port: int, local_addr: str = "0.0.0.0", prefix: str = "local", timeout: float = 0.05):
    # Create UDP socket with broadcast enabled
    sock = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    await sock.bind((local_addr, local_port))

    async with httpx.AsyncClient() as client:
        protocol = DiscoveryProtocol(store, client, sock, local_port, prefix, timeout)
        async with trio.open_nursery() as nursery:
            await protocol.start(nursery)
            try:
                yield protocol
            finally:
                protocol.stop()
                nursery.cancel_scope.cancel()
