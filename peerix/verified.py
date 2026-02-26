import typing as t
import logging
import time

import httpx

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.verified")

CACHE_TTL = 3600  # 1 hour


class VerifiedStore(Store):

    def __init__(self, backend: Store, upstream_cache: str = "https://cache.nixos.org"):
        self.backend = backend
        self.upstream_cache = upstream_cache.rstrip("/")
        self._verification_cache: t.Dict[str, t.Tuple[bool, float]] = {}
        self._client: t.Optional[httpx.AsyncClient] = None

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

    async def close(self):
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def _verify_hash(self, hsh: str, nar_hash: str) -> bool:
        now = time.monotonic()

        cached = self._verification_cache.get(hsh)
        if cached is not None:
            result, ts = cached
            if now - ts < CACHE_TTL:
                return result

        client = await self._get_client()
        try:
            resp = await client.get(f"{self.upstream_cache}/{hsh}.narinfo")
            if resp.status_code != 200:
                logger.debug(f"{hsh} not found in upstream cache")
                self._verification_cache[hsh] = (False, now)
                return False

            text = resp.text
            upstream_nar_hash = None
            for line in text.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                if k.strip() == "NarHash":
                    upstream_nar_hash = v.strip()
                    break

            if upstream_nar_hash is None:
                logger.warning(f"{hsh} upstream narinfo has no NarHash")
                self._verification_cache[hsh] = (False, now)
                return False

            match = nar_hash == upstream_nar_hash
            if not match:
                logger.warning(f"{hsh} NarHash mismatch: local={nar_hash} upstream={upstream_nar_hash}")
            else:
                logger.debug(f"{hsh} verified against upstream")

            self._verification_cache[hsh] = (match, now)
            return match

        except httpx.HTTPError as e:
            logger.warning(f"Failed to verify {hsh} against upstream: {e}")
            return False

    async def cache_info(self) -> CacheInfo:
        return await self.backend.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        info = await self.backend.narinfo(hsh)
        if info is None:
            return None

        if not await self._verify_hash(hsh, info.narHash):
            return None

        return info

    def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        return self.backend.nar(url)
