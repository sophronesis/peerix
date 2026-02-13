import typing as t
import logging
import time

import aiohttp

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.verified")

CACHE_TTL = 3600  # 1 hour


class VerifiedStore(Store):

    def __init__(self, backend: Store, upstream_cache: str = "https://cache.nixos.org"):
        self.backend = backend
        self.upstream_cache = upstream_cache.rstrip("/")
        self._verification_cache: t.Dict[str, t.Tuple[bool, float]] = {}
        self._session: t.Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def _verify_hash(self, hsh: str, nar_hash: str) -> bool:
        now = time.monotonic()

        cached = self._verification_cache.get(hsh)
        if cached is not None:
            result, ts = cached
            if now - ts < CACHE_TTL:
                return result

        session = await self._get_session()
        try:
            async with session.get(f"{self.upstream_cache}/{hsh}.narinfo") as resp:
                if resp.status != 200:
                    logger.debug(f"{hsh} not found in upstream cache")
                    self._verification_cache[hsh] = (False, now)
                    return False

                text = await resp.text()
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

        except aiohttp.ClientError as e:
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
