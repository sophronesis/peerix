"""
IPFS compatibility layer for peerix.

Provides interoperability between peerix NAR hashes and IPFS CIDs,
enabling future nix IPFS integration (nix#859, content-addressed fetchers).

Key features:
- Convert NAR hashes to IPFS CIDs
- Announce as IPFS provider (optional)
- Bridge between peerix and IPFS networks
"""
import typing as t
import logging
import hashlib
import base64
import struct

logger = logging.getLogger("peerix.ipfs_compat")


# IPFS/Multihash constants
MULTIHASH_SHA2_256 = 0x12  # SHA2-256 function code
MULTIHASH_SHA2_256_LENGTH = 0x20  # 32 bytes

# CID constants
CID_VERSION_0 = 0
CID_VERSION_1 = 1
MULTICODEC_RAW = 0x55  # Raw binary
MULTICODEC_DAG_PB = 0x70  # DAG-protobuf (for chunked data)

# Base encodings
MULTIBASE_BASE32_LOWER = "b"  # base32 lower-case (RFC 4648)
MULTIBASE_BASE58_BTC = "z"  # base58btc


def decode_nix_hash(nix_hash: str) -> bytes:
    """
    Decode a nix hash string to raw bytes.

    Handles formats:
    - sha256:base32... (nix base32, different from RFC 4648)
    - sha256-base64... (standard base64)
    - sha256:base16... (hex)

    Args:
        nix_hash: The nix hash string

    Returns:
        Raw 32-byte SHA256 hash
    """
    if nix_hash.startswith("sha256:"):
        hash_part = nix_hash[7:]
    elif nix_hash.startswith("sha256-"):
        hash_part = nix_hash[7:]
    else:
        hash_part = nix_hash

    # Try to detect encoding
    if len(hash_part) == 64:
        # Hex encoding
        return bytes.fromhex(hash_part)
    elif len(hash_part) == 52:
        # Nix base32 (uses different alphabet: 0-9a-df-np-sv-z)
        return _decode_nix_base32(hash_part)
    elif "=" in hash_part or len(hash_part) == 44:
        # Standard base64
        # Handle URL-safe base64
        hash_part = hash_part.replace("-", "+").replace("_", "/")
        # Add padding if needed
        padding = 4 - (len(hash_part) % 4)
        if padding != 4:
            hash_part += "=" * padding
        return base64.b64decode(hash_part)
    else:
        raise ValueError(f"Unknown hash format: {nix_hash}")


def _decode_nix_base32(s: str) -> bytes:
    """
    Decode nix-style base32.

    Nix uses a custom base32 alphabet: 0123456789abcdfghijklmnpqrsvwxyz
    (note: no 'e', 'o', 't', 'u')
    """
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
    bits = 0
    value = 0
    result = []

    for char in s:
        idx = alphabet.index(char.lower())
        value = (value << 5) | idx
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((value >> bits) & 0xFF)

    # Nix base32 is big-endian and reversed
    return bytes(reversed(result))


def encode_multihash(hash_bytes: bytes, hash_type: int = MULTIHASH_SHA2_256) -> bytes:
    """
    Encode raw hash bytes as a multihash.

    Args:
        hash_bytes: The raw hash bytes
        hash_type: The hash function code (default: SHA2-256)

    Returns:
        Multihash-encoded bytes
    """
    if hash_type == MULTIHASH_SHA2_256:
        if len(hash_bytes) != 32:
            raise ValueError(f"SHA256 hash must be 32 bytes, got {len(hash_bytes)}")
        return bytes([hash_type, MULTIHASH_SHA2_256_LENGTH]) + hash_bytes
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")


def encode_varint(n: int) -> bytes:
    """Encode an integer as a varint."""
    result = []
    while n > 0x7F:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(result)


def make_cid_v1(codec: int, multihash: bytes) -> bytes:
    """
    Create a CIDv1.

    Format: <version><codec><multihash>
    All components are varints except multihash which is self-describing.

    Args:
        codec: The multicodec (e.g., MULTICODEC_RAW)
        multihash: The multihash bytes

    Returns:
        CIDv1 bytes
    """
    return encode_varint(CID_VERSION_1) + encode_varint(codec) + multihash


def cid_to_base32(cid_bytes: bytes) -> str:
    """
    Encode CID bytes to base32 string with multibase prefix.

    Returns the canonical CIDv1 string representation.
    """
    # Use RFC 4648 base32 lowercase without padding
    encoded = base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")
    return MULTIBASE_BASE32_LOWER + encoded


def nar_hash_to_cid(nar_hash: str) -> str:
    """
    Convert a nix NAR hash to an IPFS CIDv1.

    The resulting CID uses:
    - CIDv1 format
    - raw multicodec (0x55)
    - SHA2-256 multihash

    This allows the NAR to be addressed in IPFS networks.

    Args:
        nar_hash: The NAR hash (e.g., "sha256:base32..." or "sha256-base64...")

    Returns:
        CIDv1 string (e.g., "bafk...")
    """
    try:
        raw_hash = decode_nix_hash(nar_hash)
        multihash = encode_multihash(raw_hash)
        cid_bytes = make_cid_v1(MULTICODEC_RAW, multihash)
        return cid_to_base32(cid_bytes)
    except Exception as e:
        logger.warning(f"Failed to convert NAR hash to CID: {nar_hash}: {e}")
        raise


def cid_to_nar_hash(cid: str) -> str:
    """
    Convert an IPFS CID back to a nix NAR hash format.

    Only works for CIDs created from NAR hashes (raw codec, SHA256).

    Args:
        cid: The CID string (base32 encoded)

    Returns:
        NAR hash in sha256:base32 format

    Raises:
        ValueError if CID is not compatible
    """
    if not cid.startswith(MULTIBASE_BASE32_LOWER):
        raise ValueError(f"CID must be base32 encoded: {cid}")

    # Decode base32
    encoded = cid[1:]  # Remove multibase prefix
    # Add padding if needed
    padding = (8 - len(encoded) % 8) % 8
    encoded = encoded.upper() + "=" * padding
    cid_bytes = base64.b32decode(encoded)

    # Parse CID
    if cid_bytes[0] != CID_VERSION_1:
        raise ValueError(f"Only CIDv1 supported, got version {cid_bytes[0]}")

    # Skip version varint and read codec varint
    pos = 1
    codec = cid_bytes[pos]
    if codec & 0x80:
        raise ValueError("Multi-byte codec varint not supported")
    pos += 1

    if codec != MULTICODEC_RAW:
        raise ValueError(f"Only raw codec supported, got {codec}")

    # Parse multihash
    hash_type = cid_bytes[pos]
    pos += 1
    hash_len = cid_bytes[pos]
    pos += 1

    if hash_type != MULTIHASH_SHA2_256 or hash_len != MULTIHASH_SHA2_256_LENGTH:
        raise ValueError(f"Only SHA256 multihash supported")

    raw_hash = cid_bytes[pos:pos + hash_len]

    # Encode as nix base32
    return "sha256:" + _encode_nix_base32(raw_hash)


def _encode_nix_base32(data: bytes) -> str:
    """
    Encode bytes to nix-style base32.

    Nix base32 is reversed and uses alphabet: 0123456789abcdfghijklmnpqrsvwxyz
    """
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

    # Nix base32 works on reversed bytes
    data = bytes(reversed(data))

    # Convert to base32
    value = int.from_bytes(data, "big")
    result = []

    # Calculate expected length
    length = (len(data) * 8 + 4) // 5

    for _ in range(length):
        result.append(alphabet[value & 0x1F])
        value >>= 5

    return "".join(reversed(result))


class IPFSBridge:
    """
    Bridge between peerix and IPFS networks.

    Provides:
    - NAR hash to CID conversion
    - Optional IPFS provider announcements
    - Future: bitswap protocol support
    """

    def __init__(
        self,
        host: t.Any = None,  # LibP2PHost
        announce_to_ipfs: bool = False,
    ):
        """
        Initialize the IPFS bridge.

        Args:
            host: LibP2P host for DHT announcements
            announce_to_ipfs: Whether to announce NARs to IPFS DHT
        """
        self.host = host
        self.announce_to_ipfs = announce_to_ipfs
        self._announced_cids: t.Set[str] = set()

    def nar_to_cid(self, nar_hash: str) -> str:
        """Convert NAR hash to IPFS CID."""
        return nar_hash_to_cid(nar_hash)

    def cid_to_nar(self, cid: str) -> str:
        """Convert IPFS CID to NAR hash."""
        return cid_to_nar_hash(cid)

    async def announce_nar(self, nar_hash: str) -> t.Optional[str]:
        """
        Announce a NAR to the IPFS DHT.

        Args:
            nar_hash: The NAR hash to announce

        Returns:
            The CID if announcement succeeded, None otherwise
        """
        if not self.announce_to_ipfs or self.host is None:
            return None

        try:
            cid = nar_hash_to_cid(nar_hash)

            if cid in self._announced_cids:
                return cid

            # Announce as IPFS provider
            # Key format for IPFS DHT: /ipfs/{cid}
            ipfs_key = f"/ipfs/{cid}"
            await self.host.provide(ipfs_key)

            self._announced_cids.add(cid)
            logger.debug(f"Announced NAR to IPFS DHT: {cid}")
            return cid

        except Exception as e:
            logger.warning(f"Failed to announce NAR to IPFS: {e}")
            return None

    async def find_nar_from_ipfs(self, nar_hash: str) -> t.List[t.Any]:
        """
        Find IPFS providers for a NAR.

        Args:
            nar_hash: The NAR hash to find

        Returns:
            List of peer infos that have this NAR in IPFS
        """
        if self.host is None:
            return []

        try:
            cid = nar_hash_to_cid(nar_hash)
            ipfs_key = f"/ipfs/{cid}"
            providers = await self.host.find_providers(ipfs_key)
            logger.debug(f"Found {len(providers)} IPFS providers for {cid}")
            return providers

        except Exception as e:
            logger.debug(f"Failed to find IPFS providers: {e}")
            return []
