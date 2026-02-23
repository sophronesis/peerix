import typing as t
import logging

import trio
import httpx

from peerix.store import NarInfo, CacheInfo, Store
from peerix.tracker_client import TrackerClient


logger = logging.getLogger("peerix.wan")


class TrackerStore(Store):

    def __init__(self, store: Store, tracker_client: TrackerClient,
                 client: httpx.AsyncClient):
        self.store = store
        self.tracker_client = tracker_client
        self.client = client

    async def cache_info(self) -> CacheInfo:
        return await self.store.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        peers = await self.tracker_client.get_peers()
        if not peers:
            logger.debug(f"No WAN peers available for {hsh}")
            return None

        for peer in peers:
            addr = peer["addr"]
            port = peer["port"]
            peer_id = peer["peer_id"]
            try:
                resp = await self.client.get(
                    f"http://{addr}:{port}/local/{hsh}.narinfo",
                    timeout=10.0,
                )
                if resp.status_code != 200:
                    continue
                info = NarInfo.parse(resp.text)
                # Rewrite URL to route through our WAN endpoint
                wan_url = f"wan/{addr}/{port}/{peer_id}/{hsh}/{info.url}"
                logger.info(f"Found {hsh} at WAN peer {peer_id} ({addr}:{port})")
                return info._replace(url=wan_url)
            except (httpx.HTTPError, trio.TooSlowError) as e:
                logger.debug(f"Failed to query peer {peer_id} at {addr}:{port}: {e}")
                continue

        logger.debug(f"No WAN peer has {hsh}")
        return None

    async def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        # URL format: wan/{addr}/{port}/{peer_id}/{hash}/{nar_url}
        parts = url.split("/", 5)
        if len(parts) < 6 or parts[0] != "wan":
            raise FileNotFoundError(f"Invalid WAN NAR URL: {url}")

        _, addr, port_str, peer_id, hsh, nar_url = parts
        port = int(port_str)

        # Init transfer for reputation tracking
        transfer_id = await self.tracker_client.init_transfer(peer_id)

        try:
            return self._stream_nar(addr, port, nar_url, transfer_id, peer_id)
        except (httpx.HTTPError, trio.TooSlowError) as e:
            if transfer_id is not None:
                await self.tracker_client.report_transfer(transfer_id, "receiver", 0)
            raise FileNotFoundError(f"NAR fetch failed from {addr}:{port}: {e}")

    async def _stream_nar(self, addr: str, port: int, nar_url: str,
                          transfer_id: t.Optional[int],
                          peer_id: str) -> t.AsyncIterable[bytes]:
        total_bytes = 0
        try:
            async with self.client.stream(
                "GET",
                f"http://{addr}:{port}/local/nar/{nar_url}",
                timeout=300.0,
            ) as resp:
                if resp.status_code != 200:
                    raise FileNotFoundError(f"NAR fetch failed from {addr}:{port}: {resp.status_code}")
                async for chunk in resp.aiter_bytes():
                    total_bytes += len(chunk)
                    yield chunk
        finally:
            if transfer_id is not None:
                await self.tracker_client.report_transfer(
                    transfer_id, "receiver", total_bytes
                )
                logger.info(f"WAN transfer from {peer_id}: {total_bytes} bytes")
