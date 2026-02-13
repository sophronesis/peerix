import typing as t
import fnmatch
import logging
import os

from peerix.store import NarInfo, CacheInfo, Store


logger = logging.getLogger("peerix.filtered")


DEFAULT_EXCLUDE_PATTERNS = [
    # System builds
    "*-nixos-system-*",
    "*-etc-*",
    "*-nixos-*-config",
    "*-unit-*.service",
    "*-system-path",
    "*-booted-system",
    "*-toplevel",
    "*-activation-script-*",
    "*-systemd-*",
    # Secrets / sensitive
    "*-sops-nix-*",
    "*-agenix-*",
    "*-secret-*",
    "*-secrets-*",
    "*-password-*",
    "*-private-key-*",
    "*-credentials-*",
    "*.key",
    "*.pem",
    # User-specific
    "*-home-manager-*",
    "*-home-files-*",
]


class FilteredStore(Store):

    def __init__(self, backend: Store, extra_patterns: t.Sequence[str] = (),
                 use_defaults: bool = True):
        self.backend = backend
        self.patterns: t.List[str] = []
        if use_defaults:
            self.patterns.extend(DEFAULT_EXCLUDE_PATTERNS)
        self.patterns.extend(extra_patterns)

    def _is_excluded(self, store_path: str) -> bool:
        basename = os.path.basename(store_path)
        for pattern in self.patterns:
            if fnmatch.fnmatch(basename, pattern):
                logger.debug(f"Filtered out {basename} (matched {pattern})")
                return True
        return False

    async def cache_info(self) -> CacheInfo:
        return await self.backend.cache_info()

    async def narinfo(self, hsh: str) -> t.Optional[NarInfo]:
        info = await self.backend.narinfo(hsh)
        if info is None:
            return None
        if self._is_excluded(info.storePath):
            return None
        return info

    def nar(self, url: str) -> t.Awaitable[t.AsyncIterable[bytes]]:
        return self.backend.nar(url)
