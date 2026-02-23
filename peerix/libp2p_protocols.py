"""
LibP2P protocol handlers for peerix.

Defines the wire protocols for narinfo queries and NAR streaming:
- /peerix/narinfo/1.0.0: Query narinfo from a peer
- /peerix/nar/1.0.0: Stream NAR data from a peer
"""
import typing as t
import logging
import struct
import json

from peerix.store import NarInfo, Store


logger = logging.getLogger("peerix.libp2p.protocols")

# Try to import libp2p types
try:
    from libp2p.network.stream.net_stream import NetStream
    from libp2p.custom_types import TProtocol
except ImportError:
    NetStream = t.Any
    TProtocol = str


# Protocol identifiers
PROTOCOL_NARINFO = TProtocol("/peerix/narinfo/1.0.0")
PROTOCOL_NAR = TProtocol("/peerix/nar/1.0.0")

# Message types
MSG_NARINFO_REQUEST = 0x01
MSG_NARINFO_RESPONSE = 0x02
MSG_NARINFO_NOT_FOUND = 0x03
MSG_NAR_REQUEST = 0x04
MSG_NAR_CHUNK = 0x05
MSG_NAR_END = 0x06
MSG_ERROR = 0xFF

# Chunk size for NAR streaming (10MB to match local.py)
NAR_CHUNK_SIZE = 10 * 1024 * 1024


async def read_length_prefixed(stream: NetStream) -> bytes:
    """Read a length-prefixed message from stream."""
    # Read 4-byte big-endian length
    length_bytes = await stream.read(4)
    if len(length_bytes) < 4:
        raise IOError("Failed to read message length")
    length = struct.unpack(">I", length_bytes)[0]

    if length > 100 * 1024 * 1024:  # 100MB max message size
        raise IOError(f"Message too large: {length}")

    # Read the message
    data = b""
    while len(data) < length:
        chunk = await stream.read(min(65536, length - len(data)))
        if not chunk:
            raise IOError("Stream closed while reading message")
        data += chunk

    return data


async def write_length_prefixed(stream: NetStream, data: bytes) -> None:
    """Write a length-prefixed message to stream."""
    length = struct.pack(">I", len(data))
    await stream.write(length + data)


def encode_narinfo_request(hash: str) -> bytes:
    """Encode a narinfo request message."""
    payload = json.dumps({"hash": hash}).encode("utf-8")
    return bytes([MSG_NARINFO_REQUEST]) + payload


def decode_narinfo_request(data: bytes) -> str:
    """Decode a narinfo request message. Returns the hash."""
    if data[0] != MSG_NARINFO_REQUEST:
        raise ValueError(f"Invalid message type: {data[0]}")
    payload = json.loads(data[1:].decode("utf-8"))
    return payload["hash"]


def encode_narinfo_response(narinfo: NarInfo) -> bytes:
    """Encode a narinfo response message."""
    payload = json.dumps({
        "storePath": narinfo.storePath,
        "url": narinfo.url,
        "compression": narinfo.compression,
        "narHash": narinfo.narHash,
        "narSize": narinfo.narSize,
        "references": list(narinfo.references),
        "deriver": narinfo.deriver,
        "signatures": list(narinfo.signatures),
    }).encode("utf-8")
    return bytes([MSG_NARINFO_RESPONSE]) + payload


def decode_narinfo_response(data: bytes) -> t.Optional[NarInfo]:
    """Decode a narinfo response message. Returns NarInfo or None if not found."""
    msg_type = data[0]
    if msg_type == MSG_NARINFO_NOT_FOUND:
        return None
    if msg_type != MSG_NARINFO_RESPONSE:
        raise ValueError(f"Invalid message type: {msg_type}")

    payload = json.loads(data[1:].decode("utf-8"))
    return NarInfo(
        storePath=payload["storePath"],
        url=payload["url"],
        compression=payload["compression"],
        narHash=payload["narHash"],
        narSize=payload["narSize"],
        references=payload["references"],
        deriver=payload.get("deriver"),
        signatures=payload["signatures"],
    )


def encode_narinfo_not_found() -> bytes:
    """Encode a narinfo not found message."""
    return bytes([MSG_NARINFO_NOT_FOUND])


def encode_nar_request(url: str) -> bytes:
    """Encode a NAR request message."""
    payload = json.dumps({"url": url}).encode("utf-8")
    return bytes([MSG_NAR_REQUEST]) + payload


def decode_nar_request(data: bytes) -> str:
    """Decode a NAR request message. Returns the URL."""
    if data[0] != MSG_NAR_REQUEST:
        raise ValueError(f"Invalid message type: {data[0]}")
    payload = json.loads(data[1:].decode("utf-8"))
    return payload["url"]


def encode_nar_chunk(chunk: bytes) -> bytes:
    """Encode a NAR chunk message."""
    return bytes([MSG_NAR_CHUNK]) + chunk


def encode_nar_end() -> bytes:
    """Encode a NAR end message."""
    return bytes([MSG_NAR_END])


def encode_error(message: str) -> bytes:
    """Encode an error message."""
    payload = json.dumps({"error": message}).encode("utf-8")
    return bytes([MSG_ERROR]) + payload


def decode_error(data: bytes) -> str:
    """Decode an error message."""
    if data[0] != MSG_ERROR:
        raise ValueError(f"Invalid message type: {data[0]}")
    payload = json.loads(data[1:].decode("utf-8"))
    return payload["error"]


class NarinfoProtocolHandler:
    """Handler for /peerix/narinfo/1.0.0 protocol."""

    def __init__(self, store: Store):
        self.store = store

    async def handle(self, stream: NetStream) -> None:
        """Handle an incoming narinfo request stream."""
        try:
            # Read the request
            data = await read_length_prefixed(stream)
            hash = decode_narinfo_request(data)

            logger.debug(f"Received narinfo request for: {hash}")

            # Query local store
            narinfo = await self.store.narinfo(hash)

            # Send response
            if narinfo is not None:
                response = encode_narinfo_response(narinfo)
                logger.debug(f"Sending narinfo for {hash}")
            else:
                response = encode_narinfo_not_found()
                logger.debug(f"Narinfo not found: {hash}")

            await write_length_prefixed(stream, response)

        except Exception as e:
            logger.error(f"Error handling narinfo request: {e}")
            try:
                await write_length_prefixed(stream, encode_error(str(e)))
            except Exception:
                pass
        finally:
            await stream.close()


class NarProtocolHandler:
    """Handler for /peerix/nar/1.0.0 protocol."""

    def __init__(self, store: Store):
        self.store = store

    async def handle(self, stream: NetStream) -> None:
        """Handle an incoming NAR request stream."""
        try:
            # Read the request
            data = await read_length_prefixed(stream)
            url = decode_nar_request(data)

            logger.debug(f"Received NAR request for: {url}")

            # Stream NAR data
            try:
                nar_stream = await self.store.nar(url)
                total_bytes = 0

                async for chunk in nar_stream:
                    if chunk:
                        await write_length_prefixed(stream, encode_nar_chunk(chunk))
                        total_bytes += len(chunk)

                # Send end marker
                await write_length_prefixed(stream, encode_nar_end())
                logger.info(f"Streamed NAR {url}: {total_bytes} bytes")

            except FileNotFoundError:
                await write_length_prefixed(stream, encode_error("NAR not found"))
                logger.debug(f"NAR not found: {url}")

        except Exception as e:
            logger.error(f"Error handling NAR request: {e}")
            try:
                await write_length_prefixed(stream, encode_error(str(e)))
            except Exception:
                pass
        finally:
            await stream.close()


async def request_narinfo(stream: NetStream, hash: str) -> t.Optional[NarInfo]:
    """
    Request narinfo from a peer over an open stream.

    Args:
        stream: Open stream to the peer (protocol: /peerix/narinfo/1.0.0)
        hash: The store path hash to query

    Returns:
        NarInfo if found, None otherwise
    """
    try:
        # Send request
        request = encode_narinfo_request(hash)
        await write_length_prefixed(stream, request)

        # Read response
        response = await read_length_prefixed(stream)

        # Check for error
        if response[0] == MSG_ERROR:
            error = decode_error(response)
            logger.debug(f"Peer returned error for {hash}: {error}")
            return None

        return decode_narinfo_response(response)

    except Exception as e:
        logger.debug(f"Failed to request narinfo {hash}: {e}")
        return None
    finally:
        await stream.close()


async def request_nar(stream: NetStream, url: str) -> t.AsyncIterable[bytes]:
    """
    Request NAR data from a peer over an open stream.

    Args:
        stream: Open stream to the peer (protocol: /peerix/nar/1.0.0)
        url: The NAR URL to fetch

    Yields:
        NAR data chunks
    """
    try:
        # Send request
        request = encode_nar_request(url)
        await write_length_prefixed(stream, request)

        # Stream response chunks
        while True:
            response = await read_length_prefixed(stream)
            msg_type = response[0]

            if msg_type == MSG_NAR_CHUNK:
                yield response[1:]  # Strip message type byte

            elif msg_type == MSG_NAR_END:
                break

            elif msg_type == MSG_ERROR:
                error = decode_error(response)
                raise FileNotFoundError(f"Peer returned error: {error}")

            else:
                raise IOError(f"Unexpected message type: {msg_type}")

    except Exception as e:
        logger.debug(f"Failed to request NAR {url}: {e}")
        raise
    finally:
        await stream.close()
