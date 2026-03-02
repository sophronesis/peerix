"""
Asyncio-based Peerix application using Iroh P2P.

This is a cleaner implementation that replaces trio with asyncio
and uses Iroh for NAT-traversing P2P connectivity.
"""

import asyncio
import logging
import socket
import signal
import typing as t
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse, JSONResponse
from starlette.routing import Route

from .local_asyncio import local_async, LocalStoreAsync
from .iroh_proto import IrohNode, NARINFO_PROTOCOL
from .store import NarInfo

logger = logging.getLogger("peerix.iroh_app")

# Global state
_iroh_node: t.Optional[IrohNode] = None
_local_store: t.Optional[LocalStoreAsync] = None
_cache_priority: int = 5


def get_client_ip(request: Request) -> str:
    """Get client IP, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


def is_localhost(request: Request) -> bool:
    """Check if request is from localhost."""
    client_ip = get_client_ip(request)
    return client_ip in ("127.0.0.1", "::1", "localhost")


# ========== HTTP Endpoints ==========

async def nix_cache_info(request: Request) -> Response:
    """Serve nix-cache-info for the local nix daemon."""
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    cache = await _local_store.cache_info()
    content = f"""StoreDir: {cache.storeDir}
WantMassQuery: {cache.wantMassQuery}
Priority: {_cache_priority}
"""
    return Response(content, media_type="text/plain")


async def narinfo_handler(request: Request) -> Response:
    """
    Handle narinfo requests from local nix daemon.

    First checks local store, then tries Iroh peers.
    """
    if not is_localhost(request):
        return Response("Forbidden", status_code=403)

    hash_part = request.path_params.get("hash", "")
    if not hash_part:
        return Response("Bad request", status_code=400)

    # Remove .narinfo suffix if present
    if hash_part.endswith(".narinfo"):
        hash_part = hash_part[:-8]

    logger.debug(f"Narinfo request for {hash_part}")

    # Try local store first
    narinfo = await _local_store.narinfo(hash_part)
    if narinfo:
        logger.debug(f"Found locally: {narinfo.storePath}")
        return Response(narinfo.dump(), media_type="text/x-nix-narinfo")

    # Try Iroh peers
    if _iroh_node and _iroh_node._known_peers:
        result = await _iroh_node.fetch_narinfo_from_peers(hash_part, max_attempts=3)
        if result:
            narinfo_content, peer_id = result
            logger.info(f"Got narinfo from peer {peer_id[:16]}...")
            # Rewrite URL to route through our Iroh endpoint
            # Parse the narinfo and update URL
            peer_narinfo = NarInfo.parse(narinfo_content)
            # Keep URL as-is for now, we'll handle routing separately
            return Response(narinfo_content, media_type="text/x-nix-narinfo")

    return Response("Not found", status_code=404)


async def local_narinfo_handler(request: Request) -> Response:
    """Handle narinfo requests from other Iroh peers (via HTTP fallback)."""
    hash_part = request.path_params.get("hash", "")
    if hash_part.endswith(".narinfo"):
        hash_part = hash_part[:-8]

    narinfo = await _local_store.narinfo(hash_part)
    if narinfo:
        return Response(narinfo.dump(), media_type="text/x-nix-narinfo")
    return Response("Not found", status_code=404)


async def nar_handler(request: Request) -> Response:
    """Handle NAR requests - stream from local store."""
    nar_path = request.path_params.get("path", "")

    try:
        async def stream_nar():
            async for chunk in _local_store.nar(nar_path):
                yield chunk

        return StreamingResponse(stream_nar(), media_type="application/x-nix-nar")
    except FileNotFoundError:
        return Response("Not found", status_code=404)
    except Exception as e:
        logger.error(f"NAR error: {e}")
        return Response("Internal error", status_code=500)


async def status_handler(request: Request) -> Response:
    """Return node status."""
    status = {
        "mode": "iroh",
        "node_id": _iroh_node._node_id if _iroh_node else None,
        "known_peers": len(_iroh_node._known_peers) if _iroh_node else 0,
        "tracker_url": _iroh_node.tracker_url if _iroh_node else None,
    }

    if _iroh_node and _iroh_node.net:
        try:
            addr = await _iroh_node.get_node_addr()
            status["relay_url"] = addr.relay_url() if addr else None
            status["direct_addrs"] = addr.direct_addresses() if addr else []
        except:
            pass

    return JSONResponse(status)


async def peers_handler(request: Request) -> Response:
    """List known Iroh peers."""
    if not _iroh_node:
        return JSONResponse({"peers": []})

    peers = []
    for node_id in _iroh_node._known_peers:
        peers.append({
            "node_id": node_id,
            "node_id_short": node_id[:16] + "...",
        })

    return JSONResponse({"peers": peers, "count": len(peers)})


# ========== Application Setup ==========

def create_app() -> Starlette:
    """Create the Starlette application."""
    routes = [
        Route("/nix-cache-info", nix_cache_info),
        Route("/{hash}.narinfo", narinfo_handler),
        Route("/local/{hash}.narinfo", local_narinfo_handler),
        Route("/nar/{path:path}", nar_handler),
        Route("/status", status_handler),
        Route("/peers", peers_handler),
    ]

    return Starlette(routes=routes)


async def run_server(
    port: int = 12304,
    tracker_url: str = None,
    peer_id: str = None,
    priority: int = 5,
    connect_timeout: float = 10.0,
    state_dir: t.Optional[Path] = None,
):
    """
    Run the Iroh-based peerix server.

    Args:
        port: HTTP port to listen on
        tracker_url: Tracker URL for peer discovery
        peer_id: Human-readable peer ID
        priority: Cache priority (lower = higher priority)
        connect_timeout: Timeout for Iroh connections
        state_dir: Directory for persistent state (secret key)
    """
    global _iroh_node, _local_store, _cache_priority
    _cache_priority = priority

    # Use hostname as default peer_id
    if not peer_id:
        peer_id = socket.gethostname()

    logger.info(f"Starting Iroh peerix on port {port}")
    logger.info(f"Peer ID: {peer_id}")
    if tracker_url:
        logger.info(f"Tracker: {tracker_url}")

    # Start local store
    async with local_async() as store:
        _local_store = store
        logger.info("LocalStore ready")

        # Start Iroh node
        _iroh_node = IrohNode(
            store,
            tracker_url=tracker_url,
            peer_id=peer_id,
            connect_timeout=connect_timeout,
            state_dir=state_dir,
        )

        try:
            node_id = await _iroh_node.start()
            logger.info(f"Iroh node ID: {node_id}")

            # Get our address info
            addr = await _iroh_node.get_node_addr()
            logger.info(f"Relay: {addr.relay_url()}")
            logger.info(f"Direct addrs: {len(addr.direct_addresses())}")

            # Create and run HTTP server
            app = create_app()

            # Import uvicorn for serving
            import uvicorn

            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)

            # Run server and tracker sync concurrently
            async with asyncio.TaskGroup() as tg:
                tg.create_task(server.serve())
                if tracker_url:
                    tg.create_task(_iroh_node.run_tracker_sync())

        except asyncio.CancelledError:
            logger.info("Shutting down...")
        finally:
            await _iroh_node.stop()
            _iroh_node = None
            _local_store = None


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Iroh-based Peerix server")
    parser.add_argument("--port", "-p", type=int, default=12304,
                        help="HTTP port (default: 12304)")
    parser.add_argument("--tracker", "-t", type=str,
                        help="Tracker URL for peer discovery")
    parser.add_argument("--peer-id", type=str,
                        help="Human-readable peer ID (default: hostname)")
    parser.add_argument("--priority", type=int, default=5,
                        help="Cache priority (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--state-dir", type=str,
                        help="Directory for persistent state (default: /var/lib/peerix)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    try:
        asyncio.run(run_server(
            port=args.port,
            tracker_url=args.tracker,
            peer_id=args.peer_id,
            priority=args.priority,
            connect_timeout=args.timeout,
            state_dir=Path(args.state_dir) if args.state_dir else None,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    main()
