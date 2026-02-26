import typing as t
import logging
import json
import os

import trio
import httpx


logger = logging.getLogger("peerix.tracker_client")

# Default path for persisting announced state
DEFAULT_STATE_FILE = "/var/lib/peerix/announced_state.json"


class TrackerClient:

    def __init__(self, tracker_url: str, peer_id: str, local_port: int,
                 state_file: str = DEFAULT_STATE_FILE):
        self.tracker_url = tracker_url.rstrip("/")
        self.peer_id = peer_id
        self.local_port = local_port
        self._client: t.Optional[httpx.AsyncClient] = None
        self._package_hashes: t.List[str] = []  # Store path hashes to announce
        self._state_file = state_file
        self._last_announced_hashes: t.Set[str] = set()
        self._load_announced_state()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=30.0,
                ),
            )
        return self._client

    def _load_announced_state(self) -> None:
        """Load the set of previously announced hashes from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    data = json.load(f)
                    self._last_announced_hashes = set(data.get("hashes", []))
                    logger.info(f"Loaded {len(self._last_announced_hashes)} announced hashes from state")
        except Exception as e:
            logger.warning(f"Failed to load announced state: {e}")
            self._last_announced_hashes = set()

    def _save_announced_state(self) -> None:
        """Save the set of announced hashes to disk."""
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            with open(self._state_file, "w") as f:
                json.dump({"hashes": list(self._last_announced_hashes)}, f)
        except Exception as e:
            logger.warning(f"Failed to save announced state: {e}")

    async def batch_register_packages(self, hashes: t.List[str]) -> bool:
        """
        Register many package hashes at once with the tracker.

        Args:
            hashes: List of store path hashes to register

        Returns:
            True if successful
        """
        client = await self._get_client()
        try:
            resp = await client.post(
                f"{self.tracker_url}/packages/batch",
                json={"peer_id": self.peer_id, "hashes": hashes},
                timeout=60.0,
            )
            if resp.status_code == 200:
                self._last_announced_hashes = set(hashes)
                self._save_announced_state()
                logger.info(f"Batch registered {len(hashes)} packages with tracker")
                return True
            else:
                logger.warning(f"Batch register failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Batch register error: {e}")
            return False

    async def delta_sync_packages(self, current_hashes: t.Set[str]) -> bool:
        """
        Sync package hashes with tracker using delta updates.

        Only sends added/removed hashes since last sync. Falls back to
        batch register if this is the first sync.

        Args:
            current_hashes: Current set of store path hashes

        Returns:
            True if successful
        """
        # First sync - send all hashes
        if not self._last_announced_hashes:
            logger.info("First sync, sending all hashes via batch register")
            return await self.batch_register_packages(list(current_hashes))

        # Compute delta
        added = current_hashes - self._last_announced_hashes
        removed = self._last_announced_hashes - current_hashes

        # Nothing changed
        if not added and not removed:
            logger.debug("No package changes, skipping delta sync")
            return True

        client = await self._get_client()
        try:
            resp = await client.post(
                f"{self.tracker_url}/packages/delta",
                json={
                    "peer_id": self.peer_id,
                    "added": list(added),
                    "removed": list(removed),
                },
                timeout=60.0,
            )
            if resp.status_code == 200:
                self._last_announced_hashes = current_hashes.copy()
                self._save_announced_state()
                logger.info(f"Delta sync: +{len(added)} -{len(removed)} packages")
                return True
            else:
                logger.warning(f"Delta sync failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Delta sync error: {e}")
            return False

    async def run_heartbeat(self, task_status=trio.TASK_STATUS_IGNORED):
        """Run the heartbeat loop. Should be called from within a nursery."""
        task_status.started()
        while True:
            try:
                await self.announce()
            except Exception as e:
                logger.warning(f"Heartbeat announce failed: {type(e).__name__}: {e}")
            await trio.sleep(60)

    def set_package_hashes(self, hashes: t.List[str]):
        """Set the list of store path hashes to announce."""
        self._package_hashes = hashes

    async def announce(self):
        client = await self._get_client()
        payload = {
            "peer_id": self.peer_id,
            "port": self.local_port,
        }
        if self._package_hashes:
            payload["packages"] = self._package_hashes

        resp = await client.post(f"{self.tracker_url}/announce", json=payload, timeout=30.0)
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

    async def find_providers(self, store_hash: str) -> t.List[t.Dict]:
        """Find peers that have a specific store path hash."""
        client = await self._get_client()
        resp = await client.get(f"{self.tracker_url}/find/{store_hash}")
        if resp.status_code != 200:
            return []
        data = resp.json()
        # Filter out ourselves
        return [p for p in data.get("providers", []) if p["peer_id"] != self.peer_id]

    async def get_cid(self, nar_hash: str) -> t.Optional[str]:
        """Get IPFS CID for a NarHash."""
        client = await self._get_client()
        resp = await client.get(f"{self.tracker_url}/cid/{nar_hash}")
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("cid")

    async def batch_get_cid(self, nar_hashes: t.List[str]) -> t.Dict[str, str]:
        """
        Get IPFS CIDs for multiple NarHashes in one request.

        Args:
            nar_hashes: List of NarHash values to look up

        Returns:
            Dict mapping NarHash to CID (only includes found mappings)
        """
        if not nar_hashes:
            return {}

        client = await self._get_client()
        try:
            resp = await client.post(
                f"{self.tracker_url}/cids/batch",
                json={"nar_hashes": nar_hashes},
                timeout=30.0,
            )
            if resp.status_code != 200:
                logger.warning(f"Batch CID lookup failed: {resp.status_code}")
                return {}
            data = resp.json()
            return data.get("cids", {})
        except Exception as e:
            logger.warning(f"Batch CID lookup error: {e}")
            return {}

    async def get_all_cids(self) -> t.Dict[str, str]:
        """Get all NarHash→CID mappings from tracker."""
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.tracker_url}/cids", timeout=60.0)
            if resp.status_code != 200:
                logger.warning(f"Failed to fetch CIDs: {resp.status_code}")
                return {}
            data = resp.json()
            cids = data.get("cids", {})
            logger.info(f"Fetched {len(cids)} CID mappings from tracker")
            return cids
        except Exception as e:
            logger.warning(f"Error fetching CIDs: {e}")
            return {}

    async def register_cid(self, nar_hash: str, cid: str) -> bool:
        """Register an IPFS CID for a NarHash."""
        client = await self._get_client()
        resp = await client.post(f"{self.tracker_url}/cid", json={
            "nar_hash": nar_hash,
            "cid": cid,
            "peer_id": self.peer_id,
        })
        return resp.status_code == 200

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
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
