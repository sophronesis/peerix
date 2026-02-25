# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Peerix is a peer-to-peer binary cache for Nix. It supports two discovery modes:
- **IPFS** (default): Uses local IPFS daemon for content-addressed NAR distribution. CID mappings registered with tracker. On startup, all local NarHash→CID mappings are synced to tracker.
- **LAN**: UDP broadcast for zero-config peer discovery on local networks.

## Build & Run

This is a Nix flake project with a Python (3.12) application:

```bash
# Enter dev shell (provides nix-serve, niv, python with deps)
nix develop            # flake-based
nix-shell              # legacy, uses flake-compat

# Build the package
nix build              # produces result/bin/peerix

# Run directly (IPFS mode, default)
nix run . -- --port 12304 --timeout 50 --verbose

# Run with IPFS mode and tracker (requires local IPFS daemon)
nix run . -- --mode ipfs --tracker-url http://tracker:12305 --verbose

# Run with LAN mode
nix run . -- --mode lan --verbose

# Run with signing
NIX_SECRET_KEY_FILE=/path/to/key.pem nix run . -- --verbose

# Run tracker
peerix-tracker --port 12305

# Run from source (inside dev shell)
python -m peerix --port 12304 --verbose
```

There are no tests in this project.

## Architecture

The system has two halves — a **local store** (wraps `nix-serve` for the machine's own `/nix/store`) and a **remote store** (LAN UDP discovery or IPFS-based discovery). Both are exposed through a single Starlette HTTP server (served via Hypercorn/trio).

### Key modules (`peerix/`)

- **`store.py`** — Base `Store` class and data models (`NarInfo`, `CacheInfo` NamedTuples with `parse()`/`dump()` serialization). All stores implement `cache_info()`, `narinfo(hash)`, and `nar(url)`. The `NarInfo.parse()` skips lines without `:` to handle empty lines gracefully.
- **`local.py`** — `LocalStore`: launches `nix-serve` on a Unix socket, proxies narinfo requests to it, and streams NARs via `nix-store --dump`. The `local()` context manager handles the nix-serve subprocess lifecycle. Important: `NIX_SECRET_KEY_FILE` is stripped from nix-serve's env to avoid Perl crashes — signing is handled by peerix itself in `app.py`. Path traversal protection via `os.path.realpath()` + trailing-slash check.
- **`remote.py`** — `DiscoveryProtocol`: a UDP datagram protocol that broadcasts narinfo requests to all private-network broadcast addresses, waits for peer responses (with configurable timeout), then fetches narinfo/NAR data over HTTP from the responding peer. Uses random 4-byte request IDs (anti-spoofing).
- **`tracker.py`** — Standalone tracker server (Starlette + SQLite). Manages peer registry (announce/heartbeat), peer listing, and CID mappings for IPFS mode.
- **`tracker_client.py`** — Client for the tracker. Handles heartbeat announcements, peer listing, CID lookups and registration.
- **`prefix.py`** — `PrefixStore`: decorator that namespaces URL paths so local, remote, and IPFS NAR routes don't collide.
- **`filtered.py`** — `FilteredStore`: heuristic filtering of system-specific/sensitive derivations.
- **`verified.py`** — `VerifiedStore`: verifies store path hashes against upstream cache. Caches expected `narHash` per URL and verifies NAR content on-the-fly during streaming (TOCTOU protection) using SHA256 + Nix base32 encoding.
- **`app.py`** — Starlette routes wiring it together. `setup_stores()` initializes stores based on mode. Narinfo endpoint (`/{hash}.narinfo`) is restricted to localhost (IPv4 and IPv6). Routes: `/local/` for peer-to-peer, `/v2/remote/` for LAN, `/v5/ipfs/` for IPFS.
- **`__main__.py`** — CLI entry point: argparse for `--port`, `--timeout`, `--verbose`, `--private-key`, `--mode`, `--tracker-url`, `--scan-interval`, `--priority`.

### IPFS module (`peerix/`)

- **`ipfs_store.py`** — `IPFSStore`: Store implementation using local IPFS daemon. Adds NARs to IPFS via `/api/v0/add`, retrieves via `/api/v0/cat`. Maintains local CID cache at `/var/lib/peerix/cid_cache.json`. Key methods:
  - `add_to_ipfs()`, `get_from_ipfs()`, `check_ipfs_has()`: IPFS daemon interaction
  - `publish_nar()`: Publish single NAR to IPFS and cache mapping
  - `sync_cid_mappings_to_tracker()`: Register all local CID mappings with tracker (called on startup)
  - `scan_and_publish()`: Scan store paths, filter, and publish to IPFS
  - `run_periodic_scan()`: Background task that periodically scans and publishes (configurable interval, default 1 hour)

### Network protocol

- **LAN**: UDP port 12304 (configurable) — peer discovery via broadcast. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- **IPFS**: Uses local IPFS daemon API (`http://127.0.0.1:5001/api/v0`). NARs are added via `/add` and fetched via `/cat`. CID mappings registered with tracker via `POST /cid` and looked up via `GET /cid/{nar_hash}`. Uses `routing/findprovs` to check content availability. NAR URLs use `ipfs/{cid}` format.
- **HTTP port 12304** (configurable): serves local narinfo/NAR to peers and proxied remote content to the local nix daemon.

### NixOS integration

- **`module.nix`** — NixOS module (`services.peerix.*` options). Configures a hardened systemd service, adds `http://127.0.0.1:{port}/` as a nix substituter, manages trusted public keys, firewall rules. IPFS/Kubo configuration when `services.peerix.ipfs.configureKubo` is enabled. Also includes `services.peerix-tracker.*` for running a tracker.
- **`flake.nix`** — Exposes `packages.peerix`, `nixosModules.peerix`, overlay, and dev shell.

## Known Issues & Gotchas

- **`nix-serve` storeDir bug**: nix-serve may return `StoreDir: Nix::Store::getStoreDir` (literal Perl code). `local.py` handles this by falling back to `/nix/store`.
- **`nix dump-path` deprecated**: Newer Nix requires `--extra-experimental-features nix-command`. We use `nix-store --dump` instead, which is stable.
- **`NIX_SECRET_KEY_FILE` + nix-serve**: Passing this env var to nix-serve causes Perl crashes. Peerix strips it from nix-serve's environment and handles signing itself.
- **Narinfo signing**: Peerix signs narinfo at the HTTP response level using ed25519 (pynacl). The fingerprint format is `1;storePath;narHash;narSize;/nix/store/ref1,/nix/store/ref2,...` with comma-separated sorted full store paths.
- **`/{hash}.narinfo` is restricted to 127.0.0.1**: External peers must use `/local/{hash}.narinfo` instead. This is by design — the main narinfo endpoint is for the local nix daemon only.
- **`nix-build --option require-sigs false`**: Even with `trusted-users`, this may not work in all nix versions. Prefer proper signing with `NIX_SECRET_KEY_FILE` and `trusted-public-keys`.
- **IPFS mode requires daemon**: The local IPFS daemon must be running (`ipfs daemon` or `services.kubo.enable`). API defaults to `http://127.0.0.1:5001/api/v0`.
- **IPFS CID cache**: Stored at `/var/lib/peerix/cid_cache.json`. On startup, all local CID mappings are pre-registered with the tracker via `sync_cid_mappings_to_tracker()`.
- **IPFS NAR URL format**: NARs fetched from IPFS use URL format `ipfs/{cid}`. The `IPFSStore.nar()` method handles both IPFS URLs and local store paths.
- **IPFS findprovs API**: Uses `routing/findprovs` (new API, replacing deprecated `dht/findprovs`). Response is NDJSON; Type=4 indicates provider found.
- **SIGHUP for manual rescan**: Send SIGHUP to trigger manual store rescan in IPFS mode. Use `systemctl reload peerix` on NixOS.

## Dependencies

Python: `trio`, `hypercorn`, `starlette`, `psutil`, `httpx`, `pynacl` (optional, for narinfo signing)
IPFS mode: `httpx`, `trio`, local IPFS daemon (kubo)
System: `nix`, `nix-serve` (both must be on PATH)
