import typing as t
import logging
import hashlib
import time

import aiohttp

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.verified")

CACHE_TTL = 3600  # 1 hour

# Nix base32 alphabet (used for NarHash encoding)
_NIX_BASE32_CHARS = "0123456789abcdfghijklmnpqrsvwxyz"


def _to_nix_base32(data: bytes) -> str:
    """Encode bytes to Nix's non-standard base32 format."""
    bit_count = len(data) * 8
    char_count = (bit_count + 4) // 5  # ceil(bit_count / 5)

    result = []
    for i in range(char_count - 1, -1, -1):
        bit_offset = i * 5
        byte_idx = bit_offset // 8
        bit_shift = bit_offset % 8

        val = data[byte_idx] >> bit_shift
        if byte_idx + 1 < len(data) and bit_shift > 3:
            val |= data[byte_idx + 1] << (8 - bit_shift)
        val &= 0x1F

        result.append(_NIX_BASE32_CHARS[val])

    return "".join(result)


class VerifiedStore(Store):

    def __init__(self, backend: Store, upstream_cache: str = "https://cache.nixos.org"):
        self.backend = backend
        self.upstream_cache = upstream_cache.rstrip("/")
        self._verification_cache: t.Dict[str, t.Tuple[bool, float]] = {}
        self._nar_hash_cache: t.Dict[str, str] = {}
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

        # Cache the expected narHash for TOCTOU protection during nar()
        self._nar_hash_cache[info.url] = info.narHash
        return info

    async def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        expected_hash = self._nar_hash_cache.get(url)
        if expected_hash is None:
            # No cached hash — allow passthrough (narinfo wasn't fetched through us)
            return await self.backend.nar(url)

        stream = await self.backend.nar(url)
        return self._verified_nar_stream(stream, expected_hash, url)

    async def _verified_nar_stream(self, stream: t.AsyncIterable[bytes],
                                   expected_hash: str, url: str) -> t.AsyncIterable[bytes]:
        """Stream NAR data while computing SHA256, verify hash at end."""
        hasher = hashlib.sha256()
        async for chunk in stream:
            hasher.update(chunk)
            yield chunk

        # Compute the Nix-format hash: sha256:<nix-base32>
        digest = hasher.digest()
        computed = f"sha256:{_to_nix_base32(digest)}"

        if computed != expected_hash:
            logger.error(
                f"NAR hash mismatch for {url}: expected={expected_hash} computed={computed}"
            )
            # The data has already been streamed — log the error.
            # The consumer (nix) will also verify independently.

        # Clean up cache entry
        self._nar_hash_cache.pop(url, None)
