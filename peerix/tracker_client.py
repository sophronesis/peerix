import typing as t
import logging

import trio
import httpx


logger = logging.getLogger("peerix.tracker_client")


class TrackerClient:

    def __init__(self, tracker_url: str, peer_id: str, local_port: int):
        self.tracker_url = tracker_url.rstrip("/")
        self.peer_id = peer_id
        self.local_port = local_port
        self._client: t.Optional[httpx.AsyncClient] = None
        self._cancel_scope: t.Optional[trio.CancelScope] = None
        self._nursery: t.Optional[trio.Nursery] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient()
        return self._client

    async def start_heartbeat(self):
        # Start heartbeat in background
        # Note: The nursery must be passed from outside or we need a different approach
        # For now, we'll start it as a standalone coroutine that gets cancelled on close
        self._cancel_scope = trio.CancelScope()
        # We can't start background tasks here without a nursery
        # The heartbeat will be started lazily on first announce

    async def run_heartbeat(self, task_status=trio.TASK_STATUS_IGNORED):
        """Run the heartbeat loop. Should be called from within a nursery."""
        task_status.started()
        while True:
            try:
                await self.announce()
            except Exception as e:
                logger.warning(f"Heartbeat announce failed: {e}")
            await trio.sleep(60)

    async def announce(self):
        client = await self._get_client()
        resp = await client.post(f"{self.tracker_url}/announce", json={
            "peer_id": self.peer_id,
            "port": self.local_port,
        })
        if resp.status_code != 200:
            logger.warning(f"Announce failed: {resp.status_code}")

    async def get_peers(self) -> t.List[t.Dict]:
        client = await self._get_client()
        resp = await client.get(f"{self.tracker_url}/peers")
        if resp.status_code != 200:
            return []
        data = resp.json()
        # Filter out ourselves
        return [p for p in data.get("peers", []) if p["peer_id"] != self.peer_id]

    async def init_transfer(self, receiver_id: str) -> t.Optional[int]:
        client = await self._get_client()
        resp = await client.post(f"{self.tracker_url}/transfer/init", json={
            "sender_id": self.peer_id,
            "receiver_id": receiver_id,
        })
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("transfer_id")

    async def report_transfer(self, transfer_id: int, role: str, byte_count: int):
        client = await self._get_client()
        try:
            resp = await client.post(f"{self.tracker_url}/report", json={
                "transfer_id": transfer_id,
                "peer_id": self.peer_id,
                "role": role,
                "bytes": byte_count,
            })
            if resp.status_code != 200:
                logger.warning(f"Report failed for transfer {transfer_id}: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Report failed for transfer {transfer_id}: {e}")

    async def close(self):
        if self._cancel_scope is not None:
            self._cancel_scope.cancel()
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
