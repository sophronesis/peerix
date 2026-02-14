import typing as t
import logging
import asyncio

import aiohttp

from peerix.store import NarInfo, CacheInfo, Store
from peerix.tracker_client import TrackerClient


logger = logging.getLogger("peerix.wan")


class TrackerStore(Store):

    def __init__(self, store: Store, tracker_client: TrackerClient,
                 session: aiohttp.ClientSession):
        self.store = store
        self.tracker_client = tracker_client
        self.session = session

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
                async with self.session.get(
                    f"http://{addr}:{port}/local/{hsh}.narinfo",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        continue
                    info = NarInfo.parse(await resp.text())
                    # Rewrite URL to route through our WAN endpoint
                    wan_url = f"wan/{addr}/{port}/{peer_id}/{hsh}/{info.url}"
                    logger.info(f"Found {hsh} at WAN peer {peer_id} ({addr}:{port})")
                    return info._replace(url=wan_url)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Failed to query peer {peer_id} at {addr}:{port}: {e}")
                continue

        logger.debug(f"No WAN peer has {hsh}")
        return None

    async def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        # URL format: wan/{addr}/{port}/{peer_id}/{hash}/{nar_url}
        logger.debug(f"WAN nar() called with url: {url}")
        parts = url.split("/", 5)
        if len(parts) < 6 or parts[0] != "wan":
            raise FileNotFoundError(f"Invalid WAN NAR URL: {url}")

        _, addr, port_str, peer_id, hsh, nar_url = parts
        port = int(port_str)
        logger.debug(f"WAN nar fetch: http://{addr}:{port}/{nar_url}")

        # Init transfer for reputation tracking
        transfer_id = await self.tracker_client.init_transfer(peer_id)

        try:
            resp = await self.session.get(
                f"http://{addr}:{port}/{nar_url}",
                timeout=aiohttp.ClientTimeout(total=300),
            )
            if resp.status != 200:
                raise FileNotFoundError(f"NAR fetch failed from {addr}:{port}/{nar_url}: {resp.status}")

            return self._stream_nar(resp, transfer_id, peer_id)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if transfer_id is not None:
                await self.tracker_client.report_transfer(transfer_id, "receiver", 0)
            raise FileNotFoundError(f"NAR fetch failed from {addr}:{port}: {e}")

    async def _stream_nar(self, resp: aiohttp.ClientResponse,
                          transfer_id: t.Optional[int],
                          peer_id: str) -> t.AsyncIterable[bytes]:
        total_bytes = 0
        try:
            content = resp.content
            while not content.at_eof():
                chunk = await content.readany()
                total_bytes += len(chunk)
                yield chunk
        finally:
            resp.close()
            await resp.wait_for_close()
            if transfer_id is not None:
                await self.tracker_client.report_transfer(
                    transfer_id, "receiver", total_bytes
                )
                logger.info(f"WAN transfer from {peer_id}: {total_bytes} bytes")
