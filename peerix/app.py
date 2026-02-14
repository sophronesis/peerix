import logging
import contextlib
import uuid
import os
import base64

import aiohttp
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.applications import Starlette

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

logger = logging.getLogger("peerix.app")

_signing_key = None
_signing_key_name = None


def _load_signing_key():
    global _signing_key, _signing_key_name
    key_file = os.environ.get("NIX_SECRET_KEY_FILE")
    if not key_file or not HAS_NACL:
        return
    with open(key_file, "r") as f:
        content = f.read().strip()
    name, key_b64 = content.split(":", 1)
    key_bytes = base64.b64decode(key_b64)
    _signing_key = SigningKey(key_bytes[:32])
    _signing_key_name = name
    logger.info(f"Loaded signing key: {name}")


def sign_narinfo(ni):
    if _signing_key is None:
        return ni
    # Nix fingerprint format: 1;storePath;narHash;narSize;/nix/store/ref1,/nix/store/ref2,...
    store_dir = "/nix/store"
    refs = ",".join(
        ref if ref.startswith("/") else f"{store_dir}/{ref}"
        for ref in sorted(ni.references)
    ) if ni.references else ""
    fingerprint = f"1;{ni.storePath};{ni.narHash};{ni.narSize};{refs}"
    logger.debug(f"Signing fingerprint: {fingerprint}")
    sig = _signing_key.sign(fingerprint.encode("utf-8")).signature
    sig_str = f"{_signing_key_name}:{base64.b64encode(sig).decode('ascii')}"
    return ni._replace(signatures=list(ni.signatures) + [sig_str])

from peerix.local import local
from peerix.remote import remote
from peerix.prefix import PrefixStore
from peerix.filtered import FilteredStore
from peerix.verified import VerifiedStore
from peerix.wan import TrackerStore
from peerix.tracker_client import TrackerClient


@contextlib.asynccontextmanager
async def setup_stores(local_port: int, timeout: float, mode: str = "lan",
                       tracker_url: str = None, no_verify: bool = False,
                       upstream_cache: str = "https://cache.nixos.org",
                       no_filter: bool = False, filter_patterns: list = None,
                       no_default_filters: bool = False, peer_id: str = None,
                       announce_addr: str = None):
    global l_access, r_access, w_access
    w_access = None
    _load_signing_key()

    async with local() as l:
        l_access = PrefixStore("local/nar", l)

        if mode in ("lan", "both"):
            lp = PrefixStore("local", l)
            async with remote(lp, local_port, "0.0.0.0", lp.prefix, timeout) as r:
                r_access = PrefixStore("v2/remote", r)

                if mode == "both" and tracker_url:
                    w_access = await _setup_wan(
                        l, local_port, tracker_url, no_verify, upstream_cache,
                        no_filter, filter_patterns, no_default_filters, peer_id,
                        announce_addr,
                    )
                    try:
                        yield
                    finally:
                        await _cleanup_wan(w_access)
                else:
                    yield

        elif mode == "wan":
            # In WAN-only mode, set r_access to None — the /{hash}.narinfo
            # endpoint will use WAN store instead.
            r_access = None
            w_access = await _setup_wan(
                l, local_port, tracker_url, no_verify, upstream_cache,
                no_filter, filter_patterns, no_default_filters, peer_id,
            )
            try:
                yield
            finally:
                await _cleanup_wan(w_access)


async def _setup_wan(local_store, local_port, tracker_url, no_verify,
                     upstream_cache, no_filter, filter_patterns,
                     no_default_filters, peer_id, announce_addr=None):
    if peer_id is None:
        peer_id = str(uuid.uuid4())

    # Build the serving chain: local → verified → filtered
    serving_store = local_store
    verified_store = None
    if not no_verify:
        verified_store = VerifiedStore(serving_store, upstream_cache)
        serving_store = verified_store
    if not no_filter:
        serving_store = FilteredStore(
            serving_store,
            extra_patterns=filter_patterns or [],
            use_defaults=not no_default_filters,
        )

    tracker_client = TrackerClient(tracker_url, peer_id, local_port, announce_addr)
    await tracker_client.start_heartbeat()

    session = aiohttp.ClientSession()
    tracker_store = TrackerStore(serving_store, tracker_client, session)
    wan_access = PrefixStore("v3/wan", tracker_store)

    return {
        "access": wan_access,
        "tracker_client": tracker_client,
        "session": session,
        "verified_store": verified_store,
        "serving_store": serving_store,
    }


async def _cleanup_wan(wan_info):
    if wan_info is None:
        return
    await wan_info["tracker_client"].close()
    if not wan_info["session"].closed:
        await wan_info["session"].close()
    vs = wan_info.get("verified_store")
    if vs is not None:
        await vs.close()


app = Starlette()


@app.route("/nix-cache-info")
async def cache_info(_: Request) -> Response:
    ci = await l_access.cache_info()
    ci = ci._replace(priority=20)
    return Response(content=ci.dump())


@app.route("/{hash:str}.narinfo")
async def narinfo(req: Request) -> Response:

    if req.client.host != "127.0.0.1":
        return Response(content="Permission denied.", status_code=403)

    hsh = req.path_params["hash"]

    # Try LAN remote store first
    if r_access is not None:
        ni = await r_access.narinfo(hsh)
        if ni is not None:
            return Response(content=sign_narinfo(ni).dump(), status_code=200, media_type="text/x-nix-narinfo")

    # Try WAN store
    if w_access is not None:
        ni = await w_access["access"].narinfo(hsh)
        if ni is not None:
            return Response(content=sign_narinfo(ni).dump(), status_code=200, media_type="text/x-nix-narinfo")

    return Response(content="Not found", status_code=404)


@app.route("/local/{hash:str}.narinfo")
async def access_narinfo(req: Request) -> Response:
    ni = await l_access.narinfo(req.path_params["hash"])
    if ni is None:
        return Response(content="Not found", status_code=404)
    return Response(content=sign_narinfo(ni).dump(), status_code=200, media_type="text/x-nix-narinfo")


@app.route("/local/nar/{path:str}")
async def push_nar(req: Request) -> Response:
    try:
        return StreamingResponse(
                await l_access.nar(f"local/nar/{req.path_params['path']}"),
                media_type="text/plain"
        )
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# LAN remote NARs
@app.route("/v2/remote/{path:path}")
async def pull_nar(req: Request) -> Response:
    if r_access is None:
        return Response(content="LAN mode not enabled", status_code=404)
    try:
        return StreamingResponse(await r_access.nar(f"v2/remote/{req.path_params['path']}"), media_type="text/plain")
    except FileNotFoundError:
        return Response(content="Gone", status_code=404)


# WAN remote NARs
@app.route("/v3/wan/{path:path}")
async def pull_wan_nar(req: Request) -> Response:
    logger.debug(f"pull_wan_nar: path={req.path_params['path']}")
    if w_access is None:
        return Response(content="WAN mode not enabled", status_code=404)
    try:
        return StreamingResponse(
            await w_access["access"].nar(f"v3/wan/{req.path_params['path']}"),
            media_type="text/plain",
        )
    except FileNotFoundError as e:
        logger.debug(f"pull_wan_nar FileNotFoundError: {e}")
        return Response(content="Gone", status_code=404)
