import typing as t
import logging
import asyncio

import aiohttp


logger = logging.getLogger("peerix.tracker_client")


class TrackerClient:

    def __init__(self, tracker_url: str, peer_id: str, local_port: int):
        self.tracker_url = tracker_url.rstrip("/")
        self.peer_id = peer_id
        self.local_port = local_port
        self._session: t.Optional[aiohttp.ClientSession] = None
        self._heartbeat_task: t.Optional[asyncio.Task] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def start_heartbeat(self):
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self):
        while True:
            try:
                await self.announce()
            except Exception as e:
                logger.warning(f"Heartbeat announce failed: {e}")
            await asyncio.sleep(60)

    async def announce(self):
        session = await self._get_session()
        async with session.post(f"{self.tracker_url}/announce", json={
            "peer_id": self.peer_id,
            "port": self.local_port,
        }) as resp:
            if resp.status != 200:
                logger.warning(f"Announce failed: {resp.status}")

    async def get_peers(self) -> t.List[t.Dict]:
        session = await self._get_session()
        async with session.get(f"{self.tracker_url}/peers") as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            # Filter out ourselves
            return [p for p in data.get("peers", []) if p["peer_id"] != self.peer_id]

    async def init_transfer(self, receiver_id: str) -> t.Optional[int]:
        session = await self._get_session()
        async with session.post(f"{self.tracker_url}/transfer/init", json={
            "sender_id": self.peer_id,
            "receiver_id": receiver_id,
        }) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            return data.get("transfer_id")

    async def report_transfer(self, transfer_id: int, role: str, byte_count: int):
        session = await self._get_session()
        try:
            async with session.post(f"{self.tracker_url}/report", json={
                "transfer_id": transfer_id,
                "peer_id": self.peer_id,
                "role": role,
                "bytes": byte_count,
            }) as resp:
                if resp.status != 200:
                    logger.warning(f"Report failed for transfer {transfer_id}: {resp.status}")
        except Exception as e:
            logger.warning(f"Report failed for transfer {transfer_id}: {e}")

    async def close(self):
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        if self._session is not None and not self._session.closed:
            await self._session.close()
