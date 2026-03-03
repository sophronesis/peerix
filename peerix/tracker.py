import json
import math
import time
import sqlite3
import logging
from contextlib import asynccontextmanager

import trio

from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.applications import Starlette


logger = logging.getLogger("peerix.tracker")

PEER_TTL = 120  # seconds before a peer is considered stale
CLEANUP_INTERVAL = 60  # seconds between stale peer cleanups
BYTE_TOLERANCE = 0.05  # 5% tolerance for byte count matching


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            addr TEXT NOT NULL,
            port INTEGER NOT NULL,
            libp2p_peer_id TEXT,
            last_seen REAL NOT NULL
        )
    """)
    # Iroh peers table: stores Iroh node IDs and addresses for NAT traversal
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iroh_peers (
            node_id TEXT PRIMARY KEY,
            peer_id TEXT NOT NULL,
            relay_url TEXT,
            direct_addrs TEXT,
            addr TEXT,
            last_seen REAL NOT NULL
        )
    """)
    # Migration: add addr column if it doesn't exist (for existing databases)
    try:
        conn.execute("ALTER TABLE iroh_peers ADD COLUMN addr TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            sender_bytes INTEGER,
            receiver_bytes INTEGER,
            sender_confirmed INTEGER DEFAULT 0,
            receiver_confirmed INTEGER DEFAULT 0,
            resolved INTEGER DEFAULT 0,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reputation (
            peer_id TEXT PRIMARY KEY,
            total_shared INTEGER DEFAULT 0,
            total_received INTEGER DEFAULT 0,
            successful_transfers INTEGER DEFAULT 0,
            failed_transfers INTEGER DEFAULT 0
        )
    """)
    # Package registry: which peer has which store path hashes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packages (
            hash TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            last_seen REAL NOT NULL,
            origin_cache TEXT,
            public_key TEXT,
            package_name TEXT,
            PRIMARY KEY (hash, peer_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packages_hash ON packages(hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packages_peer ON packages(peer_id)")

    # Migration: add new columns if they don't exist (for existing databases)
    for col in ["origin_cache", "public_key", "package_name"]:
        try:
            conn.execute(f"ALTER TABLE packages ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

    # Peer cache trust registry: which caches each peer trusts
    conn.execute("""
        CREATE TABLE IF NOT EXISTS peer_caches (
            peer_id TEXT NOT NULL,
            cache_url TEXT NOT NULL,
            public_key TEXT NOT NULL,
            PRIMARY KEY (peer_id, cache_url)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_peer_caches_peer ON peer_caches(peer_id)")

    # Allowed caches for tracker validation (Layer 2)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS allowed_caches (
            cache_url TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            enabled INTEGER DEFAULT 1
        )
    """)

    # IPFS CID mappings: NarHash → IPFS CID
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cid_mappings (
            nar_hash TEXT PRIMARY KEY,
            cid TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cid_mappings_cid ON cid_mappings(cid)")
    conn.commit()
    return conn


def compute_score(total_shared: int, successful: int, failed: int) -> float:
    if successful + failed == 0:
        return 0.0
    return (successful / (successful + failed + 1)) * math.log(total_shared + 1)


async def cleanup_stale_peers(conn):
    """Background task to clean up stale peers and packages."""
    while True:
        await trio.sleep(CLEANUP_INTERVAL)
        cutoff = time.time() - PEER_TTL
        conn.execute("DELETE FROM peers WHERE last_seen < ?", (cutoff,))
        conn.execute("DELETE FROM packages WHERE last_seen < ?", (cutoff,))
        conn.execute("DELETE FROM iroh_peers WHERE last_seen < ?", (cutoff,))
        conn.commit()


def create_tracker_app(db_path: str) -> Starlette:
    conn = init_db(db_path)

    @asynccontextmanager
    async def lifespan(app):
        # Start cleanup task in background
        async with trio.open_nursery() as nursery:
            nursery.start_soon(cleanup_stale_peers, conn)
            yield
            nursery.cancel_scope.cancel()

    app = Starlette(lifespan=lifespan)

    @app.route("/announce", methods=["POST"])
    async def announce(req: Request) -> Response:
        body = await req.json()
        peer_id = body.get("peer_id")
        port = body.get("port")
        if not peer_id or port is None:
            return JSONResponse({"error": "peer_id and port required"}, status_code=400)

        # Use X-Real-IP or X-Forwarded-For if behind reverse proxy
        addr = req.headers.get("X-Real-IP") or req.headers.get("X-Forwarded-For", "").split(",")[0].strip() or req.client.host
        now = time.time()
        libp2p_peer_id = body.get("libp2p_peer_id")
        packages = body.get("packages", [])

        conn.execute(
            "INSERT INTO peers (peer_id, addr, port, libp2p_peer_id, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(peer_id) DO UPDATE SET addr=?, port=?, libp2p_peer_id=?, last_seen=?",
            (peer_id, addr, port, libp2p_peer_id, now, addr, port, libp2p_peer_id, now)
        )

        # Update package registry
        if packages:
            # Clear old entries for this peer and insert new ones
            conn.execute("DELETE FROM packages WHERE peer_id = ?", (peer_id,))
            conn.executemany(
                "INSERT INTO packages (hash, peer_id, last_seen) VALUES (?, ?, ?)",
                [(h, peer_id, now) for h in packages]
            )

        conn.commit()

        pkg_count = len(packages) if packages else 0
        logger.info(f"Peer {peer_id} announced from {addr}:{port} (libp2p={libp2p_peer_id}, pkgs={pkg_count})")
        return JSONResponse({"status": "ok"})

    @app.route("/status", methods=["GET"])
    async def status(req: Request) -> Response:
        """Return tracker status with peer and CID counts."""
        cutoff = time.time() - PEER_TTL
        peer_count = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE last_seen >= ?", (cutoff,)
        ).fetchone()[0]
        cid_count = conn.execute("SELECT COUNT(*) FROM cid_mappings").fetchone()[0]
        package_count = conn.execute(
            "SELECT COUNT(DISTINCT hash) FROM packages WHERE last_seen >= ?", (cutoff,)
        ).fetchone()[0]
        return JSONResponse({
            "status": "ok",
            "mode": "ipfs",
            "peers": peer_count,
            "cid_mappings": cid_count,
            "packages": package_count,
        })

    @app.route("/peers", methods=["GET"])
    async def list_peers(req: Request) -> Response:
        cutoff = time.time() - PEER_TTL
        rows = conn.execute(
            "SELECT p.peer_id, p.addr, p.port, p.last_seen, "
            "COALESCE(r.total_shared, 0), COALESCE(r.total_received, 0), "
            "COALESCE(r.successful_transfers, 0), COALESCE(r.failed_transfers, 0) "
            "FROM peers p LEFT JOIN reputation r ON p.peer_id = r.peer_id "
            "WHERE p.last_seen >= ?",
            (cutoff,)
        ).fetchall()

        peers = []
        for row in rows:
            score = compute_score(row[4], row[6], row[7])
            peers.append({
                "peer_id": row[0],
                "addr": row[1],
                "port": row[2],
                "last_seen": row[3],
                "reputation": {
                    "total_shared": row[4],
                    "total_received": row[5],
                    "successful_transfers": row[6],
                    "failed_transfers": row[7],
                    "score": round(score, 4),
                },
            })

        peers.sort(key=lambda p: p["reputation"]["score"], reverse=True)
        return JSONResponse({"peers": peers})

    @app.route("/transfer/init", methods=["POST"])
    async def init_transfer(req: Request) -> Response:
        body = await req.json()
        sender_id = body.get("sender_id")
        receiver_id = body.get("receiver_id")
        if not sender_id or not receiver_id:
            return JSONResponse({"error": "sender_id and receiver_id required"}, status_code=400)

        now = time.time()
        cur = conn.execute(
            "INSERT INTO transfers (sender_id, receiver_id, created_at) VALUES (?, ?, ?)",
            (sender_id, receiver_id, now)
        )
        conn.commit()
        transfer_id = cur.lastrowid

        logger.info(f"Transfer {transfer_id} initiated: {sender_id} -> {receiver_id}")
        return JSONResponse({"transfer_id": transfer_id})

    @app.route("/report", methods=["POST"])
    async def report(req: Request) -> Response:
        body = await req.json()
        transfer_id = body.get("transfer_id")
        peer_id = body.get("peer_id")
        role = body.get("role")
        byte_count = body.get("bytes")

        if not all([transfer_id, peer_id, role, byte_count is not None]):
            return JSONResponse({"error": "transfer_id, peer_id, role, and bytes required"}, status_code=400)

        if role not in ("sender", "receiver"):
            return JSONResponse({"error": "role must be 'sender' or 'receiver'"}, status_code=400)

        row = conn.execute(
            "SELECT sender_id, receiver_id, sender_bytes, receiver_bytes, "
            "sender_confirmed, receiver_confirmed, resolved FROM transfers WHERE id = ?",
            (transfer_id,)
        ).fetchone()

        if row is None:
            return JSONResponse({"error": "transfer not found"}, status_code=404)

        sender_id, receiver_id, sender_bytes, receiver_bytes, sender_confirmed, receiver_confirmed, resolved = row

        if resolved:
            return JSONResponse({"error": "transfer already resolved"}, status_code=409)

        # Validate the reporter is part of this transfer
        if role == "sender" and peer_id != sender_id:
            return JSONResponse({"error": "peer_id does not match sender"}, status_code=403)
        if role == "receiver" and peer_id != receiver_id:
            return JSONResponse({"error": "peer_id does not match receiver"}, status_code=403)

        if role == "sender":
            if sender_confirmed:
                return JSONResponse({"error": "sender already reported"}, status_code=409)
            conn.execute(
                "UPDATE transfers SET sender_bytes = ?, sender_confirmed = 1 WHERE id = ?",
                (byte_count, transfer_id)
            )
            sender_bytes = byte_count
            sender_confirmed = True
        else:
            if receiver_confirmed:
                return JSONResponse({"error": "receiver already reported"}, status_code=409)
            conn.execute(
                "UPDATE transfers SET receiver_bytes = ?, receiver_confirmed = 1 WHERE id = ?",
                (byte_count, transfer_id)
            )
            receiver_bytes = byte_count
            receiver_confirmed = True

        conn.commit()

        # If both have reported, resolve the transfer
        if sender_confirmed and receiver_confirmed:
            max_bytes = max(sender_bytes, receiver_bytes)
            if max_bytes == 0:
                consistent = True
            else:
                consistent = abs(sender_bytes - receiver_bytes) / max_bytes <= BYTE_TOLERANCE

            conn.execute("UPDATE transfers SET resolved = 1 WHERE id = ?", (transfer_id,))

            if consistent:
                logger.info(f"Transfer {transfer_id} resolved successfully ({sender_bytes} bytes)")
                _update_reputation(conn, sender_id, shared=sender_bytes, successful=True)
                _update_reputation(conn, receiver_id, received=receiver_bytes, successful=True)
            else:
                logger.warning(
                    f"Transfer {transfer_id} inconsistent: sender={sender_bytes}, receiver={receiver_bytes}"
                )
                _update_reputation(conn, sender_id, successful=False)
                _update_reputation(conn, receiver_id, successful=False)

            conn.commit()
            return JSONResponse({"status": "resolved", "consistent": consistent})

        return JSONResponse({"status": "pending"})

    @app.route("/find/{hash:str}", methods=["GET"])
    async def find_providers(req: Request) -> Response:
        """
        Find peers that have a specific store path hash.

        Returns providers with origin_cache and public_key metadata if available.
        """
        store_hash = req.path_params["hash"]
        cutoff = time.time() - PEER_TTL

        # Find peers that have this package and are still active
        # Include origin metadata from packages table
        rows = conn.execute("""
            SELECT p.peer_id, p.addr, p.port, p.libp2p_peer_id, p.last_seen,
                   COALESCE(r.total_shared, 0), COALESCE(r.successful_transfers, 0),
                   COALESCE(r.failed_transfers, 0),
                   pkg.origin_cache, pkg.public_key, pkg.package_name
            FROM packages pkg
            JOIN peers p ON pkg.peer_id = p.peer_id
            LEFT JOIN reputation r ON p.peer_id = r.peer_id
            WHERE pkg.hash = ? AND p.last_seen >= ?
        """, (store_hash, cutoff)).fetchall()

        providers = []
        for row in rows:
            score = compute_score(row[5], row[6], row[7])
            provider = {
                "peer_id": row[0],
                "addr": row[1],
                "port": row[2],
                "libp2p_peer_id": row[3],
                "last_seen": row[4],
                "score": round(score, 4),
            }
            # Include origin metadata if available
            if row[8]:  # origin_cache
                provider["origin_cache"] = row[8]
            if row[9]:  # public_key
                provider["public_key"] = row[9]
            if row[10]:  # package_name
                provider["name"] = row[10]
            providers.append(provider)

        # Sort by reputation score
        providers.sort(key=lambda p: p["score"], reverse=True)
        return JSONResponse({"hash": store_hash, "providers": providers})

    @app.route("/cid/{nar_hash:str}", methods=["GET"])
    async def get_cid(req: Request) -> Response:
        """Get IPFS CID for a NarHash."""
        nar_hash = req.path_params["nar_hash"]
        row = conn.execute(
            "SELECT cid, peer_id, created_at FROM cid_mappings WHERE nar_hash = ?",
            (nar_hash,)
        ).fetchone()

        if row is None:
            return JSONResponse({"error": "CID not found"}, status_code=404)

        return JSONResponse({
            "nar_hash": nar_hash,
            "cid": row[0],
            "peer_id": row[1],
            "created_at": row[2],
        })

    @app.route("/cids", methods=["GET"])
    async def get_all_cids(req: Request) -> Response:
        """Get all NarHash→CID mappings. Peers use this to skip re-publishing."""
        rows = conn.execute("SELECT nar_hash, cid FROM cid_mappings").fetchall()
        cids = {row[0]: row[1] for row in rows}
        return JSONResponse({"cids": cids, "count": len(cids)})

    @app.route("/cids/batch", methods=["POST"])
    async def batch_get_cids(req: Request) -> Response:
        """Get CID mappings for multiple NarHashes in one request."""
        body = await req.json()
        nar_hashes = body.get("nar_hashes", [])

        if not isinstance(nar_hashes, list):
            return JSONResponse({"error": "nar_hashes must be a list"}, status_code=400)

        if not nar_hashes:
            return JSONResponse({"cids": {}})

        # Batch lookup using IN clause
        placeholders = ",".join("?" * len(nar_hashes))
        rows = conn.execute(
            f"SELECT nar_hash, cid FROM cid_mappings WHERE nar_hash IN ({placeholders})",
            nar_hashes
        ).fetchall()

        cids = {row[0]: row[1] for row in rows}
        return JSONResponse({"cids": cids, "count": len(cids)})

    @app.route("/cid", methods=["POST"])
    async def register_cid(req: Request) -> Response:
        """Register an IPFS CID for a NarHash."""
        body = await req.json()
        nar_hash = body.get("nar_hash")
        cid = body.get("cid")
        peer_id = body.get("peer_id")

        if not all([nar_hash, cid, peer_id]):
            return JSONResponse({"error": "nar_hash, cid, and peer_id required"}, status_code=400)

        now = time.time()
        conn.execute(
            "INSERT INTO cid_mappings (nar_hash, cid, peer_id, created_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(nar_hash) DO UPDATE SET cid=?, peer_id=?, created_at=?",
            (nar_hash, cid, peer_id, now, cid, peer_id, now)
        )
        conn.commit()

        logger.info(f"Registered CID mapping: {nar_hash} -> {cid} (peer: {peer_id})")
        return JSONResponse({"status": "ok", "nar_hash": nar_hash, "cid": cid})

    @app.route("/reputation/{peer_id:str}", methods=["GET"])
    async def get_reputation(req: Request) -> Response:
        peer_id = req.path_params["peer_id"]
        row = conn.execute(
            "SELECT total_shared, total_received, successful_transfers, failed_transfers "
            "FROM reputation WHERE peer_id = ?",
            (peer_id,)
        ).fetchone()

        if row is None:
            return JSONResponse({
                "peer_id": peer_id,
                "total_shared": 0,
                "total_received": 0,
                "successful_transfers": 0,
                "failed_transfers": 0,
                "score": 0.0,
            })

        score = compute_score(row[0], row[2], row[3])
        return JSONResponse({
            "peer_id": peer_id,
            "total_shared": row[0],
            "total_received": row[1],
            "successful_transfers": row[2],
            "failed_transfers": row[3],
            "score": round(score, 4),
        })

    @app.route("/packages/batch", methods=["POST"])
    async def batch_register_packages(req: Request) -> Response:
        """
        Register many package hashes at once for a peer.

        Supports two formats:
        - Legacy: {"peer_id": "...", "hashes": ["hash1", "hash2"]}
        - New: {"peer_id": "...", "packages": [{"hash": "...", "name": "...", "origin": "...", "public_key": "..."}]}
        """
        body = await req.json()
        peer_id = body.get("peer_id")
        hashes = body.get("hashes", [])
        packages = body.get("packages", [])

        if not peer_id:
            return JSONResponse({"error": "peer_id required"}, status_code=400)

        now = time.time()

        # Clear old entries for this peer
        conn.execute("DELETE FROM packages WHERE peer_id = ?", (peer_id,))

        if packages and isinstance(packages, list):
            # New format with metadata
            valid_packages = []
            rejected_count = 0
            for pkg in packages:
                if not isinstance(pkg, dict) or "hash" not in pkg:
                    continue
                origin_cache = pkg.get("origin")
                public_key = pkg.get("public_key")

                # Layer 2 validation: check if origin cache is allowed
                if origin_cache:
                    allowed = _validate_cache(conn, origin_cache, public_key)
                    if not allowed:
                        rejected_count += 1
                        continue

                valid_packages.append((
                    pkg["hash"],
                    peer_id,
                    now,
                    origin_cache,
                    public_key,
                    pkg.get("name"),
                ))

            if valid_packages:
                conn.executemany(
                    "INSERT INTO packages (hash, peer_id, last_seen, origin_cache, public_key, package_name) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    valid_packages
                )
            conn.commit()
            logger.info(f"Batch register: peer {peer_id} registered {len(valid_packages)} packages (rejected {rejected_count})")
            return JSONResponse({"status": "ok", "count": len(valid_packages), "rejected": rejected_count})

        elif hashes and isinstance(hashes, list):
            # Legacy format (backwards compatible)
            conn.executemany(
                "INSERT INTO packages (hash, peer_id, last_seen) VALUES (?, ?, ?)",
                [(h, peer_id, now) for h in hashes]
            )
            conn.commit()
            logger.info(f"Batch register: peer {peer_id} registered {len(hashes)} packages (legacy)")
            return JSONResponse({"status": "ok", "count": len(hashes)})

        return JSONResponse({"status": "ok", "count": 0})

    @app.route("/packages/delta", methods=["POST"])
    async def delta_sync_packages(req: Request) -> Response:
        """
        Sync only added/removed package hashes for a peer.

        Supports two formats for 'added':
        - Legacy: ["hash1", "hash2"]
        - New: [{"hash": "...", "name": "...", "origin": "...", "public_key": "..."}]

        'removed' is always a list of hash strings.
        """
        body = await req.json()
        peer_id = body.get("peer_id")
        added = body.get("added", [])
        removed = body.get("removed", [])

        if not peer_id:
            return JSONResponse({"error": "peer_id required"}, status_code=400)

        if not isinstance(added, list) or not isinstance(removed, list):
            return JSONResponse({"error": "added and removed must be lists"}, status_code=400)

        now = time.time()
        rejected_count = 0

        # Remove the specified hashes
        if removed:
            # Handle both string hashes and dicts with "hash" key
            removed_hashes = []
            for r in removed:
                if isinstance(r, str):
                    removed_hashes.append(r)
                elif isinstance(r, dict) and "hash" in r:
                    removed_hashes.append(r["hash"])
            if removed_hashes:
                placeholders = ",".join("?" * len(removed_hashes))
                conn.execute(
                    f"DELETE FROM packages WHERE peer_id = ? AND hash IN ({placeholders})",
                    [peer_id] + removed_hashes
                )

        # Add the new hashes
        added_count = 0
        if added:
            # Check if new format (list of dicts) or legacy (list of strings)
            if added and isinstance(added[0], dict):
                # New format with metadata
                valid_packages = []
                for pkg in added:
                    if not isinstance(pkg, dict) or "hash" not in pkg:
                        continue
                    origin_cache = pkg.get("origin")
                    public_key = pkg.get("public_key")

                    # Layer 2 validation: check if origin cache is allowed
                    if origin_cache:
                        allowed = _validate_cache(conn, origin_cache, public_key)
                        if not allowed:
                            rejected_count += 1
                            continue

                    valid_packages.append((
                        pkg["hash"],
                        peer_id,
                        now,
                        origin_cache,
                        public_key,
                        pkg.get("name"),
                    ))

                if valid_packages:
                    conn.executemany(
                        "INSERT OR REPLACE INTO packages (hash, peer_id, last_seen, origin_cache, public_key, package_name) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        valid_packages
                    )
                added_count = len(valid_packages)
            else:
                # Legacy format (list of strings)
                conn.executemany(
                    "INSERT OR REPLACE INTO packages (hash, peer_id, last_seen) VALUES (?, ?, ?)",
                    [(h, peer_id, now) for h in added if isinstance(h, str)]
                )
                added_count = len([h for h in added if isinstance(h, str)])

        conn.commit()

        removed_count = len(removed)
        logger.info(f"Delta sync: peer {peer_id} added {added_count}, removed {removed_count}, rejected {rejected_count}")
        return JSONResponse({"status": "ok", "added": added_count, "removed": removed_count, "rejected": rejected_count})

    # ========== Iroh P2P endpoints ==========

    @app.route("/iroh/announce", methods=["POST"])
    async def iroh_announce(req: Request) -> Response:
        """
        Announce an Iroh peer with its node ID and addresses.

        Optionally includes trusted_caches list for Layer 3 validation.
        """
        body = await req.json()
        node_id = body.get("node_id")
        peer_id = body.get("peer_id")
        relay_url = body.get("relay_url")
        direct_addrs = body.get("direct_addrs", [])
        trusted_caches = body.get("trusted_caches", [])

        if not node_id or not peer_id:
            return JSONResponse({"error": "node_id and peer_id required"}, status_code=400)

        # Capture client IP from headers (handles reverse proxy)
        addr = req.headers.get("X-Real-IP") or req.headers.get("X-Forwarded-For", "").split(",")[0].strip() or req.client.host

        now = time.time()
        # Store direct_addrs as JSON string
        addrs_json = json.dumps(direct_addrs) if direct_addrs else "[]"

        conn.execute(
            "INSERT INTO iroh_peers (node_id, peer_id, relay_url, direct_addrs, addr, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(node_id) DO UPDATE SET peer_id=?, relay_url=?, direct_addrs=?, addr=?, last_seen=?",
            (node_id, peer_id, relay_url, addrs_json, addr, now, peer_id, relay_url, addrs_json, addr, now)
        )

        # Update peer's trusted caches if provided
        if trusted_caches:
            # Clear old entries and insert new ones
            conn.execute("DELETE FROM peer_caches WHERE peer_id = ?", (node_id,))
            for cache in trusted_caches:
                if isinstance(cache, dict) and "url" in cache and "public_key" in cache:
                    conn.execute(
                        "INSERT INTO peer_caches (peer_id, cache_url, public_key) VALUES (?, ?, ?)",
                        (node_id, cache["url"], cache["public_key"])
                    )

        conn.commit()

        cache_count = len(trusted_caches) if trusted_caches else 0
        logger.info(f"Iroh peer announced: {node_id[:16]}... (peer={peer_id}, addr={addr}, relay={relay_url}, caches={cache_count})")
        return JSONResponse({"status": "ok"})

    @app.route("/iroh/peers", methods=["GET"])
    async def iroh_list_peers(req: Request) -> Response:
        """List all active Iroh peers with their addresses."""
        cutoff = time.time() - PEER_TTL
        rows = conn.execute(
            "SELECT node_id, peer_id, relay_url, direct_addrs, addr, last_seen "
            "FROM iroh_peers WHERE last_seen >= ?",
            (cutoff,)
        ).fetchall()

        peers = []
        for row in rows:
            try:
                direct_addrs = json.loads(row[3]) if row[3] else []
            except json.JSONDecodeError:
                direct_addrs = []

            peers.append({
                "node_id": row[0],
                "peer_id": row[1],
                "relay_url": row[2],
                "direct_addrs": direct_addrs,
                "addr": row[4],  # Real client IP from announcement
                "last_seen": row[5],
            })

        return JSONResponse({"peers": peers, "count": len(peers)})

    @app.route("/iroh/peer/{node_id:str}", methods=["GET"])
    async def iroh_get_peer(req: Request) -> Response:
        """Get a specific Iroh peer by node_id."""
        node_id = req.path_params["node_id"]
        row = conn.execute(
            "SELECT node_id, peer_id, relay_url, direct_addrs, last_seen "
            "FROM iroh_peers WHERE node_id = ?",
            (node_id,)
        ).fetchone()

        if row is None:
            return JSONResponse({"error": "peer not found"}, status_code=404)

        try:
            direct_addrs = json.loads(row[3]) if row[3] else []
        except json.JSONDecodeError:
            direct_addrs = []

        return JSONResponse({
            "node_id": row[0],
            "peer_id": row[1],
            "relay_url": row[2],
            "direct_addrs": direct_addrs,
            "last_seen": row[4],
        })

    @app.route("/iroh/peer/{node_id:str}/caches", methods=["GET"])
    async def iroh_get_peer_caches(req: Request) -> Response:
        """Get a peer's trusted caches (for Layer 3 validation)."""
        node_id = req.path_params["node_id"]
        rows = conn.execute(
            "SELECT cache_url, public_key FROM peer_caches WHERE peer_id = ?",
            (node_id,)
        ).fetchall()

        caches = [{"url": row[0], "public_key": row[1]} for row in rows]
        return JSONResponse({"peer_id": node_id, "trusted_caches": caches})

    @app.route("/iroh/peer/{node_id:str}", methods=["DELETE"])
    async def iroh_delete_peer(req: Request) -> Response:
        """
        Deregister an Iroh peer (graceful shutdown).

        This allows peers to immediately notify the tracker they're going
        offline, rather than waiting for TTL expiration.
        """
        node_id = req.path_params["node_id"]

        # Delete from iroh_peers
        cursor = conn.execute(
            "DELETE FROM iroh_peers WHERE node_id = ?",
            (node_id,)
        )
        conn.commit()

        if cursor.rowcount == 0:
            return JSONResponse({"status": "not found"}, status_code=404)

        # Also clean up any packages registered by this peer
        conn.execute(
            "DELETE FROM packages WHERE peer_id = ?",
            (node_id,)
        )
        conn.commit()

        logger.info(f"Iroh peer deregistered: {node_id[:16]}...")
        return JSONResponse({"status": "deregistered"})

    # ========== Admin endpoints for allowed caches ==========

    @app.route("/admin/caches", methods=["GET"])
    async def list_allowed_caches(req: Request) -> Response:
        """List all allowed caches."""
        rows = conn.execute(
            "SELECT cache_url, public_key, enabled FROM allowed_caches"
        ).fetchall()
        caches = [
            {"url": row[0], "public_key": row[1], "enabled": bool(row[2])}
            for row in rows
        ]
        return JSONResponse({"caches": caches, "count": len(caches)})

    @app.route("/admin/caches", methods=["POST"])
    async def add_allowed_cache(req: Request) -> Response:
        """Add an allowed cache."""
        body = await req.json()
        cache_url = body.get("url")
        public_key = body.get("public_key")

        if not cache_url or not public_key:
            return JSONResponse({"error": "url and public_key required"}, status_code=400)

        conn.execute(
            "INSERT INTO allowed_caches (cache_url, public_key, enabled) VALUES (?, ?, 1) "
            "ON CONFLICT(cache_url) DO UPDATE SET public_key=?, enabled=1",
            (cache_url, public_key, public_key)
        )
        conn.commit()

        logger.info(f"Added allowed cache: {cache_url}")
        return JSONResponse({"status": "ok"})

    @app.route("/admin/caches/{cache_url:path}", methods=["DELETE"])
    async def remove_allowed_cache(req: Request) -> Response:
        """Remove an allowed cache."""
        cache_url = req.path_params["cache_url"]
        cursor = conn.execute("DELETE FROM allowed_caches WHERE cache_url = ?", (cache_url,))
        conn.commit()

        if cursor.rowcount == 0:
            return JSONResponse({"status": "not found"}, status_code=404)

        logger.info(f"Removed allowed cache: {cache_url}")
        return JSONResponse({"status": "ok"})

    return app


def _validate_cache(conn: sqlite3.Connection, origin_cache: str, public_key: str = None) -> bool:
    """
    Validate that an origin cache is allowed by the tracker (Layer 2 validation).

    If no allowed_caches are configured, all caches are allowed (permissive mode).
    If allowed_caches exist, only those caches are accepted.
    If public_key is provided, it must match the configured key for that cache.

    Returns:
        True if cache is allowed, False otherwise
    """
    # Check if there are any allowed caches configured
    row = conn.execute("SELECT COUNT(*) FROM allowed_caches WHERE enabled = 1").fetchone()
    if row[0] == 0:
        # No allowed caches configured - permissive mode
        return True

    # Check if this specific cache is allowed
    if public_key:
        row = conn.execute(
            "SELECT public_key FROM allowed_caches WHERE cache_url = ? AND enabled = 1",
            (origin_cache,)
        ).fetchone()
        if row is None:
            return False
        # Validate public key matches
        return row[0] == public_key
    else:
        row = conn.execute(
            "SELECT 1 FROM allowed_caches WHERE cache_url = ? AND enabled = 1",
            (origin_cache,)
        ).fetchone()
        return row is not None


def _update_reputation(conn: sqlite3.Connection, peer_id: str,
                       shared: int = 0, received: int = 0,
                       successful: bool = True):
    conn.execute(
        "INSERT INTO reputation (peer_id, total_shared, total_received, "
        "successful_transfers, failed_transfers) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET "
        "total_shared = total_shared + ?, "
        "total_received = total_received + ?, "
        "successful_transfers = successful_transfers + ?, "
        "failed_transfers = failed_transfers + ?",
        (peer_id, shared, received, 1 if successful else 0, 0 if successful else 1,
         shared, received, 1 if successful else 0, 0 if successful else 1)
    )
