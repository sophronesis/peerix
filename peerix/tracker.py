import json
import math
import time
import sqlite3
import asyncio
import logging

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
            last_seen REAL NOT NULL
        )
    """)
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
    conn.commit()
    return conn


def compute_score(total_shared: int, successful: int, failed: int) -> float:
    if successful + failed == 0:
        return 0.0
    return (successful / (successful + failed + 1)) * math.log(total_shared + 1)


def create_tracker_app(db_path: str) -> Starlette:
    conn = init_db(db_path)
    app = Starlette()

    async def cleanup_stale_peers():
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL)
            cutoff = time.time() - PEER_TTL
            conn.execute("DELETE FROM peers WHERE last_seen < ?", (cutoff,))
            conn.commit()

    @app.on_event("startup")
    async def startup():
        asyncio.create_task(cleanup_stale_peers())

    @app.route("/announce", methods=["POST"])
    async def announce(req: Request) -> Response:
        body = await req.json()
        peer_id = body.get("peer_id")
        port = body.get("port")
        if not peer_id or port is None:
            return JSONResponse({"error": "peer_id and port required"}, status_code=400)

        addr = body.get("addr") or req.client.host
        now = time.time()

        conn.execute(
            "INSERT INTO peers (peer_id, addr, port, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(peer_id) DO UPDATE SET addr=?, port=?, last_seen=?",
            (peer_id, addr, port, now, addr, port, now)
        )
        conn.commit()

        logger.info(f"Peer {peer_id} announced from {addr}:{port}")
        return JSONResponse({"status": "ok"})

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

    return app


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
