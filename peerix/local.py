import typing as t

import contextlib
import tempfile
import subprocess
import logging
import shutil
import base64
import sys
import os

import trio
import httpx

from peerix.store import NarInfo, CacheInfo, Store


nix_serve = shutil.which("nix-serve")
if nix_serve is None:
    raise RuntimeError("nix-serve is not installed.")

nix = shutil.which("nix")
if nix is None:
    raise RuntimeError("nix is not installed.")

assert nix_serve is not None
assert nix is not None


logger = logging.getLogger("peerix.local")


class LocalStore(Store):

    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self._cache: t.Optional[CacheInfo] = None

    async def cache_info(self) -> CacheInfo:
        if self._cache is None:
            resp = await self.client.get("http://localhost/nix-cache-info")
            storeDir = ""
            wantMassQuery = -1
            priority = 50

            for line in resp.text.splitlines():
                k, v = line.split(":", 1)
                v = v.strip()
                k = k.strip()

                if k == "StoreDir":
                    storeDir = v
                elif k == "WantMassQuery":
                    wantMassQuery = int(v)
                elif k == "Priority":
                    priority = int(v)

            self._cache = CacheInfo(storeDir, wantMassQuery, priority)

        return self._cache


    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        resp = await self.client.get(f"http://localhost/{hsh}.narinfo")
        if resp.status_code == 404:
            return None
        info = NarInfo.parse(resp.text)
        return info._replace(url=base64.b64encode(info.storePath.encode("utf-8")).replace(b"/", b"_").decode("ascii")+".nar")

    async def nar(self, sp: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        if sp.endswith(".nar"):
            sp = sp[:-4]
        path = base64.b64decode(sp.replace("_", "/")).decode("utf-8")

        # Security: resolve symlinks and normalize path to prevent traversal attacks
        # e.g., /nix/store/../etc/passwd would pass startswith but escape store
        cache = await self.cache_info()
        real_path = os.path.realpath(path)
        store_dir = cache.storeDir.rstrip("/") + "/"
        if not real_path.startswith(store_dir):
            logger.warning(f"Path traversal attempt blocked: {path} -> {real_path}")
            raise FileNotFoundError(f"Path outside store: {path}")

        if not os.path.exists(real_path):
            raise FileNotFoundError()

        return self._nar_pull(real_path)

    async def _nar_pull(self, path: str) -> t.AsyncIterable[bytes]:
        logger.info(f"Serving {path}")
        process = await trio.lowlevel.open_process(
            [nix, "dump-path", "--", path],
            stdout=subprocess.PIPE,
            stderr=None,
            stdin=None,
        )

        assert process.stdout is not None
        try:
            async for chunk in process.stdout:
                yield chunk
        finally:
            process.terminate()
            await process.wait()

        logger.debug(f"Served {path}")


@contextlib.asynccontextmanager
async def local():
    with tempfile.TemporaryDirectory() as tmpdir:
        sock = f"{tmpdir}/server.sock"

        logger.info("Launching nix-serve.")
        process = await trio.lowlevel.open_process(
            [nix_serve, "--listen", sock],
            stdin=None,
            stdout=None,
            stderr=sys.stderr,
        )

        # Wait for socket to appear
        for _ in range(10):
            if os.path.exists(sock):
                break
            await trio.sleep(1)
        else:
            raise RuntimeError("Failed to start up local store.")

        try:
            transport = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=transport) as client:
                yield LocalStore(client)
        finally:
            try:
                process.terminate()
            except ProcessLookupError:
                pass

            await process.wait()
            logger.info("nix-serve exited.")
