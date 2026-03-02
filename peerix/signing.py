"""
Narinfo signing for peerix.

Signs narinfo responses using Ed25519 (via pynacl).
The fingerprint format matches nix's expectations:
  1;storePath;narHash;narSize;ref1,ref2,...

References are full store paths, sorted and comma-separated.
"""

import os
import base64
import logging
import typing as t
from pathlib import Path

from .store import NarInfo

logger = logging.getLogger("peerix.signing")

# Global signer instance
_signer: t.Optional["NarInfoSigner"] = None


class NarInfoSigner:
    """Signs narinfo using Ed25519."""

    def __init__(self, key_name: str, secret_key: bytes):
        """
        Initialize signer with a key name and secret key.

        Args:
            key_name: The key name (used in signature prefix, e.g., "cache.example.org-1")
            secret_key: 64-byte Ed25519 secret key (seed + public key)
        """
        try:
            from nacl.signing import SigningKey
        except ImportError:
            raise ImportError("pynacl is required for signing. Install with: pip install pynacl")

        self.key_name = key_name
        # Ed25519 secret key can be 32 bytes (seed) or 64 bytes (seed + pubkey)
        if len(secret_key) == 32:
            self._signing_key = SigningKey(secret_key)
        elif len(secret_key) == 64:
            self._signing_key = SigningKey(secret_key[:32])
        else:
            raise ValueError(f"Invalid secret key length: {len(secret_key)} (expected 32 or 64)")

        logger.info(f"Initialized signer with key: {key_name}")

    def fingerprint(self, narinfo: NarInfo) -> str:
        """
        Compute the fingerprint for a narinfo.

        Format: 1;storePath;narHash;narSize;ref1,ref2,...
        References are full store paths, sorted and comma-separated.
        """
        # Sort references and join with commas
        refs_str = ",".join(sorted(narinfo.references)) if narinfo.references else ""

        return f"1;{narinfo.storePath};{narinfo.narHash};{narinfo.narSize};{refs_str}"

    def sign(self, narinfo: NarInfo) -> str:
        """
        Sign a narinfo and return the signature string.

        Returns:
            Signature in format "keyname:base64signature"
        """
        fp = self.fingerprint(narinfo)
        signed = self._signing_key.sign(fp.encode("utf-8"))
        sig_b64 = base64.b64encode(signed.signature).decode("ascii")
        return f"{self.key_name}:{sig_b64}"

    def sign_narinfo(self, narinfo: NarInfo) -> NarInfo:
        """
        Sign a narinfo and return a new narinfo with the signature added.

        Args:
            narinfo: The narinfo to sign

        Returns:
            New NarInfo with signature appended to signatures list
        """
        sig = self.sign(narinfo)
        new_sigs = list(narinfo.signatures) + [sig]
        return narinfo._replace(signatures=new_sigs)


def load_signer_from_file(key_path: t.Union[str, Path]) -> t.Optional[NarInfoSigner]:
    """
    Load a signer from a nix secret key file.

    The file format is: keyname:base64secretkey

    Args:
        key_path: Path to the secret key file

    Returns:
        NarInfoSigner if successful, None otherwise
    """
    key_path = Path(key_path)
    if not key_path.exists():
        logger.warning(f"Secret key file not found: {key_path}")
        return None

    try:
        content = key_path.read_text().strip()
        if ":" not in content:
            logger.warning(f"Invalid key file format (no colon): {key_path}")
            return None

        key_name, key_b64 = content.split(":", 1)
        secret_key = base64.b64decode(key_b64)

        return NarInfoSigner(key_name, secret_key)

    except Exception as e:
        logger.warning(f"Failed to load secret key from {key_path}: {e}")
        return None


def init_signer(key_path: t.Optional[t.Union[str, Path]] = None) -> bool:
    """
    Initialize the global signer.

    Checks for key in this order:
    1. Explicit key_path argument
    2. NIX_SECRET_KEY_FILE environment variable

    Args:
        key_path: Optional explicit path to secret key file

    Returns:
        True if signer was initialized, False otherwise
    """
    global _signer

    if key_path is None:
        key_path = os.environ.get("NIX_SECRET_KEY_FILE")

    if key_path is None:
        logger.debug("No secret key configured, signing disabled")
        return False

    _signer = load_signer_from_file(key_path)
    return _signer is not None


def get_signer() -> t.Optional[NarInfoSigner]:
    """Get the global signer instance."""
    return _signer


def sign_narinfo(narinfo: NarInfo) -> NarInfo:
    """
    Sign a narinfo using the global signer.

    If no signer is configured, returns the narinfo unchanged.

    Args:
        narinfo: The narinfo to sign

    Returns:
        Signed NarInfo (or unchanged if no signer)
    """
    if _signer is None:
        return narinfo
    return _signer.sign_narinfo(narinfo)
