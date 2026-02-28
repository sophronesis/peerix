"""
Asyncio-native local store implementation.

This replaces the trio-based local.py for use with Iroh P2P.
"""

import typing as t
import asyncio
import contextlib
import tempfile
import subprocess
import logging
import shutil
import base64
import sys
import os

import httpx

try:
    from peerix.store import NarInfo, CacheInfo, Store
except ImportError:
    from store import NarInfo, CacheInfo, Store


nix_serve = shutil.which("nix-serve")
nix_store = shutil.which("nix-store")

logger = logging.getLogger("peerix.local_asyncio")


class LocalStoreAsync(Store):
    """Asyncio-native local Nix store."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self._cache: t.Optional[CacheInfo] = None

    async def cache_info(self) -> CacheInfo:
        if self._cache is None:
            resp = await self.client.get("http://localhost/nix-cache-info")
            storeDir = "/nix/store"  # Default fallback
            wantMassQuery = 1
            priority = 50

            for line in resp.text.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                v = v.strip()
                k = k.strip()

                if k == "StoreDir":
                    # Handle nix-serve bug that returns Perl code
                    if not v.startswith("Nix::"):
                        storeDir = v
                elif k == "WantMassQuery":
                    wantMassQuery = int(v)
                elif k == "Priority":
                    priority = int(v)

            self._cache = CacheInfo(storeDir, wantMassQuery, priority)

        return self._cache

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        """Get narinfo for a store path hash."""
        resp = await self.client.get(f"http://localhost/{hsh}.narinfo")
        if resp.status_code == 404:
            return None
        info = NarInfo.parse(resp.text)
        # Encode store path as URL-safe base64 for NAR URL
        url = base64.b64encode(info.storePath.encode("utf-8")).replace(b"/", b"_").decode("ascii") + ".nar"
        return info._replace(url=url)

    async def nar(self, sp: str) -> t.AsyncIterator[bytes]:
        """Stream NAR data for a store path."""
        if sp.endswith(".nar"):
            sp = sp[:-4]

        path = base64.b64decode(sp.replace("_", "/")).decode("utf-8")
        cache = await self.cache_info()

        # Security check - ensure path is within store
        real_path = os.path.realpath(path)
        store_dir = cache.storeDir.rstrip("/") + "/"
        if not real_path.startswith(store_dir):
            raise FileNotFoundError(f"Path outside store: {path}")

        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")

        async for chunk in self._nar_stream(path):
            yield chunk

    async def _nar_stream(self, path: str) -> t.AsyncIterator[bytes]:
        """Stream NAR using nix-store --dump."""
        logger.info(f"Serving NAR for {path}")

        proc = await asyncio.create_subprocess_exec(
            nix_store, "--dump", "--", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()

        logger.debug(f"Served NAR for {path}")


@contextlib.asynccontextmanager
async def local_async() -> t.AsyncIterator[LocalStoreAsync]:
    """Context manager that starts nix-serve and yields LocalStoreAsync."""
    if nix_serve is None:
        raise RuntimeError("nix-serve is not installed")
    if nix_store is None:
        raise RuntimeError("nix-store is not installed")

    with tempfile.TemporaryDirectory() as tmpdir:
        sock = f"{tmpdir}/nix-serve.sock"

        logger.info("Starting nix-serve...")

        # Strip NIX_SECRET_KEY_FILE from env to avoid nix-serve Perl crashes
        env = {k: v for k, v in os.environ.items() if k != "NIX_SECRET_KEY_FILE"}

        proc = await asyncio.create_subprocess_exec(
            nix_serve, "--listen", sock,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=sys.stderr,
            env=env,
        )

        # Wait for socket to appear
        for _ in range(20):
            if os.path.exists(sock):
                break
            await asyncio.sleep(0.5)
        else:
            proc.terminate()
            await proc.wait()
            raise RuntimeError("nix-serve failed to start")

        logger.info(f"nix-serve started on {sock}")

        try:
            transport = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
                yield LocalStoreAsync(client)
        finally:
            proc.terminate()
            await proc.wait()
            logger.info("nix-serve stopped")
