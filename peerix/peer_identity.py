import typing as t
import hashlib
import base64
import struct
import time
import logging
import os
from dataclasses import dataclass

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


logger = logging.getLogger("peerix.peer_identity")

TIMESTAMP_WINDOW = 300  # 5 minutes


@dataclass
class PeerIdentity:
    peer_id: str
    public_key: bytes  # raw 32-byte ed25519 public key
    signing_key: t.Any  # nacl.signing.SigningKey or None
    public_key_b64: str  # base64-encoded public key for transport


def _read_string(data: bytes, offset: int) -> t.Tuple[bytes, int]:
    """Read an SSH-format length-prefixed string from data at offset."""
    if offset + 4 > len(data):
        raise ValueError("Truncated SSH data")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        raise ValueError("Truncated SSH string")
    return data[offset:offset + length], offset + length


def parse_ssh_ed25519_pubkey(key_data: str) -> bytes:
    """Parse an SSH ed25519 public key and extract the raw 32-byte key.

    Accepts format: ssh-ed25519 AAAA... [comment]
    """
    parts = key_data.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format")
    if parts[0] != "ssh-ed25519":
        raise ValueError(f"Expected ssh-ed25519, got {parts[0]}")

    blob = base64.b64decode(parts[1])

    # SSH wire format: string "ssh-ed25519", string <32-byte key>
    key_type, offset = _read_string(blob, 0)
    if key_type != b"ssh-ed25519":
        raise ValueError(f"Key type mismatch in blob: {key_type}")

    raw_key, _ = _read_string(blob, offset)
    if len(raw_key) != 32:
        raise ValueError(f"Expected 32-byte ed25519 key, got {len(raw_key)}")

    return raw_key


def derive_peer_id(raw_key: bytes) -> str:
    """Derive a stable peer ID from a raw ed25519 public key.

    Returns base64url(SHA256(raw_key)) without padding.
    """
    digest = hashlib.sha256(raw_key).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def get_peer_id_from_ssh_key(path: t.Optional[str] = None) -> t.Optional[str]:
    """Get peer ID from an SSH ed25519 public key file.

    If path is None, tries default locations:
    - /etc/ssh/ssh_host_ed25519_key.pub
    - ~/.ssh/id_ed25519.pub
    """
    paths = []
    if path is not None:
        paths = [path]
    else:
        paths = [
            "/etc/ssh/ssh_host_ed25519_key.pub",
            os.path.expanduser("~/.ssh/id_ed25519.pub"),
        ]

    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    key_data = f.read()
                raw_key = parse_ssh_ed25519_pubkey(key_data)
                peer_id = derive_peer_id(raw_key)
                logger.info(f"Derived peer_id from {p}: {peer_id}")
                return peer_id
            except (ValueError, OSError) as e:
                logger.debug(f"Could not use {p}: {e}")
                continue

    return None


def parse_ssh_ed25519_private_key(key_data: str) -> bytes:
    """Parse an openssh ed25519 private key (unencrypted) and return the 32-byte seed.

    Format: PEM armor -> base64 decode -> openssh-key-v1 format.
    """
    lines = key_data.strip().splitlines()
    if lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----":
        raise ValueError("Not an OpenSSH private key")
    if lines[-1] != "-----END OPENSSH PRIVATE KEY-----":
        raise ValueError("Malformed OpenSSH private key")

    b64_data = "".join(lines[1:-1])
    data = base64.b64decode(b64_data)

    # Check magic
    magic = b"openssh-key-v1\x00"
    if not data.startswith(magic):
        raise ValueError("Not an openssh-key-v1 key")

    offset = len(magic)

    # ciphername
    cipher, offset = _read_string(data, offset)
    if cipher != b"none":
        raise ValueError(f"Encrypted SSH keys not supported (cipher={cipher.decode()})")

    # kdfname
    _, offset = _read_string(data, offset)

    # kdf options
    _, offset = _read_string(data, offset)

    # number of keys
    if offset + 4 > len(data):
        raise ValueError("Truncated key data")
    nkeys = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if nkeys != 1:
        raise ValueError(f"Expected 1 key, got {nkeys}")

    # Skip public key section (length-prefixed blob)
    _, offset = _read_string(data, offset)

    # Private key section (length-prefixed blob)
    priv_blob, _ = _read_string(data, offset)

    # Inside private blob:
    # uint32 checkint1, uint32 checkint2 (must match)
    if len(priv_blob) < 8:
        raise ValueError("Truncated private section")
    check1 = struct.unpack(">I", priv_blob[0:4])[0]
    check2 = struct.unpack(">I", priv_blob[4:8])[0]
    if check1 != check2:
        raise ValueError("Check integers don't match — key may be encrypted")

    poffset = 8

    # string keytype
    key_type, poffset = _read_string(priv_blob, poffset)
    if key_type != b"ssh-ed25519":
        raise ValueError(f"Expected ssh-ed25519, got {key_type}")

    # string public key (32 bytes)
    pub_key, poffset = _read_string(priv_blob, poffset)

    # string private key (64 bytes: 32-byte seed + 32-byte public key)
    priv_key, poffset = _read_string(priv_blob, poffset)
    if len(priv_key) != 64:
        raise ValueError(f"Expected 64-byte ed25519 private key, got {len(priv_key)}")

    seed = priv_key[:32]
    return seed


def load_signing_identity(pub_path: str, priv_path: str) -> PeerIdentity:
    """Load a full signing identity from SSH key files.

    Returns a PeerIdentity with peer_id, public_key, and signing_key.
    """
    if not HAS_NACL:
        raise RuntimeError("pynacl is required for SSH key signing")

    with open(pub_path, "r") as f:
        pub_data = f.read()
    raw_pub = parse_ssh_ed25519_pubkey(pub_data)
    peer_id = derive_peer_id(raw_pub)

    with open(priv_path, "r") as f:
        priv_data = f.read()
    seed = parse_ssh_ed25519_private_key(priv_data)

    signing_key = SigningKey(seed)

    # Verify the public key matches
    if signing_key.verify_key.encode() != raw_pub:
        raise ValueError("Public key does not match private key")

    logger.info(f"Loaded signing identity: peer_id={peer_id}")
    return PeerIdentity(
        peer_id=peer_id,
        public_key=raw_pub,
        signing_key=signing_key,
        public_key_b64=base64.b64encode(raw_pub).decode("ascii"),
    )


def sign_request(identity: PeerIdentity, peer_id: str, timestamp: str) -> str:
    """Sign a request with the identity's private key.

    Signs the message "{peer_id}\n{timestamp}" and returns base64 signature.
    """
    message = f"{peer_id}\n{timestamp}".encode("utf-8")
    signed = identity.signing_key.sign(message)
    return base64.b64encode(signed.signature).decode("ascii")


def verify_request(public_key_bytes: bytes, peer_id: str,
                   timestamp: str, signature_b64: str) -> bool:
    """Verify a signed request.

    Checks:
    1. Signature is valid for the public key
    2. SHA256(public_key) == peer_id
    3. Timestamp is within TIMESTAMP_WINDOW seconds of now
    """
    if not HAS_NACL:
        logger.warning("pynacl not available, cannot verify signatures")
        return False

    # Check timestamp freshness
    try:
        ts = float(timestamp)
    except (ValueError, TypeError):
        logger.debug("Invalid timestamp format")
        return False

    if abs(time.time() - ts) > TIMESTAMP_WINDOW:
        logger.debug(f"Timestamp too old/future: {timestamp}")
        return False

    # Check peer_id matches public key
    expected_peer_id = derive_peer_id(public_key_bytes)
    if expected_peer_id != peer_id:
        logger.debug(f"peer_id mismatch: expected {expected_peer_id}, got {peer_id}")
        return False

    # Verify signature
    try:
        sig = base64.b64decode(signature_b64)
        message = f"{peer_id}\n{timestamp}".encode("utf-8")
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message, sig)
        return True
    except (BadSignatureError, Exception) as e:
        logger.debug(f"Signature verification failed: {e}")
        return False
