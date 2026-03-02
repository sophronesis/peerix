# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Peerix is a peer-to-peer binary cache for Nix. It supports two discovery modes:
- **Iroh** (default): Uses Iroh P2P for NAT-traversing connectivity. Peers connect via relay servers or directly when possible. Package hashes are synced to tracker using delta updates.
- **LAN**: UDP broadcast for zero-config peer discovery on local networks.

## Build & Run

This is a Nix flake project with a Python (3.12) application:

```bash
# Enter dev shell (provides nix-serve, niv, python with deps)
nix develop            # flake-based
nix-shell              # legacy, uses flake-compat

# Build the package
nix build              # produces result/bin/peerix

# Run with Iroh mode (default)
peerix-iroh --port 12304 --tracker https://sophronesis.dev/peerix --verbose

# Run with LAN mode
nix run . -- --mode lan --verbose

# Run with signing
NIX_SECRET_KEY_FILE=/path/to/key.pem peerix-iroh --verbose

# Run tracker
peerix-tracker --port 12305

# Run from source (inside dev shell)
python -m peerix.iroh_app --port 12304 --verbose
```

There are no tests in this project.

## Architecture

The system has two halves — a **local store** (wraps `nix-serve` for the machine's own `/nix/store`) and a **remote store** (LAN UDP discovery or Iroh P2P). Both are exposed through a single Starlette HTTP server (served via uvicorn/asyncio).

### Key modules (`peerix/`)

- **`store.py`** — Base `Store` class and data models (`NarInfo`, `CacheInfo` NamedTuples with `parse()`/`dump()` serialization). All stores implement `cache_info()`, `narinfo(hash)`, and `nar(url)`.
- **`local.py`** — `LocalStore`: launches `nix-serve` on a Unix socket, proxies narinfo requests to it, and streams NARs via `nix-store --dump`.
- **`local_asyncio.py`** — `LocalStoreAsync`: asyncio version of LocalStore for use with Iroh mode.
- **`remote.py`** — `DiscoveryProtocol`: UDP datagram protocol for LAN mode broadcast discovery.
- **`filtered.py`** — `FilteredStore`, `NixpkgsFilteredStore`: filters packages via patterns or cache.nixos.org HEAD requests.
- **`verified.py`** — `VerifiedStore`: verifies store path hashes against upstream cache with TOCTOU protection.
- **`signing.py`** — Narinfo signing with ed25519 (pynacl). Handles `NIX_SECRET_KEY_FILE` environment variable.
- **`tracker.py`** — Standalone tracker server (Starlette + SQLite). Manages peer registry, package hash registry, Iroh peer announcements.

### Iroh module (`peerix/`)

- **`iroh_app.py`** — Main Iroh-based application. Starlette routes, dashboard, stats tracking, store management.
  - `StoreManager`: Manages store scanning, filtering, delta sync with tracker
  - `_track_request()`, `_track_served()`, `_log_activity()`: Dashboard stats tracking
  - `_load_stats()`, `_save_stats()`: Stats persistence to `/var/lib/peerix/stats.json`
  - Dashboard HTML served at `/dashboard`
  - Signal handler saves stats on SIGTERM/SIGINT
- **`iroh_proto.py`** — Iroh protocol handlers and node management.
  - `IrohNode`: Main P2P node with persistent identity, connection pooling, tracker sync
  - `NarinfoProtocol`: Handles `/peerix/narinfo/1.0.0` requests
  - `NarProtocol`: Handles `/peerix/nar/1.0.0` requests with length-prefixed streaming
  - `fetch_nar_buffered()`: Pre-buffered NAR fetching with retry support
- **`store_scanner.py`** — Scans `/nix/store` for path hashes.

### Network protocol

- **Iroh**: Custom ALPN protocols over QUIC:
  - `/peerix/narinfo/1.0.0`: Bidirectional stream for narinfo queries
  - `/peerix/nar/1.0.0`: Length-prefixed NAR streaming (8-byte size header + data)
  - NAT traversal via Iroh relay servers (euw1-1.relay.iroh.network)
  - Connection pooling per peer/protocol
- **LAN**: UDP port 12304 — peer discovery via broadcast.
- **HTTP port 12304**: Serves local narinfo/NAR to peers and dashboard.
- **Tracker**: HTTP API at `/iroh/announce`, `/iroh/peers`, `/packages/batch`, `/packages/delta`.

### NixOS integration

- **`module.nix`** — NixOS module (`services.peerix.*` options). Configures hardened systemd service, adds substituter, manages firewall rules.
- **`flake.nix`** — Exposes `packages.peerix`, `packages.peerix-iroh`, `nixosModules.peerix`, overlay, and dev shell.

## Known Issues & Gotchas

- **`nix-serve` storeDir bug**: nix-serve may return `StoreDir: Nix::Store::getStoreDir` (literal Perl code). `local.py` handles this by falling back to `/nix/store`.
- **`NIX_SECRET_KEY_FILE` + nix-serve**: Passing this env var to nix-serve causes Perl crashes. Peerix strips it from nix-serve's environment and handles signing itself via `signing.py`.
- **`/{hash}.narinfo` is restricted to 127.0.0.1**: External peers must use `/local/{hash}.narinfo` instead. This is by design.
- **Iroh identity persistence**: Node identity stored at `/var/lib/peerix/iroh_secret.key`. Same node ID across restarts.
- **Stats persistence**: Dashboard stats saved to `/var/lib/peerix/stats.json` every 60 seconds and on shutdown.
- **Filter cache**: Stored at `/var/lib/peerix/filter_cache.json`. Caches which hashes pass/fail cache.nixos.org filter.
- **Delta sync state**: Stored at `/var/lib/peerix/announced_state.json`. Tracks which hashes announced to tracker.
- **NAR URL format**: NARs from peers use URL format `iroh/nar/{peer_id}/{base64_store_path}.nar`.
- **Pre-buffered NAR fetching**: `fetch_nar_buffered()` downloads entire NAR before HTTP response starts, enabling retries on transient Iroh errors.

## Dependencies

Python: `asyncio`, `starlette`, `httpx`, `pynacl` (optional, for signing), `uvicorn`, `iroh`
System: `nix`, `nix-serve` (both must be on PATH)

## Deployment

If `./deploy` script exists in the project root, **always use it** for deploying to servers:

```bash
./deploy do           # Deploy to DO server
./deploy fw16         # Deploy to FW16 (local)
./deploy remote-nixos # Deploy to remote-nixos
./deploy all          # Deploy to all servers
```

The deploy script handles flake updates and uses the correct rebuild commands for each target. Never run nixos-rebuild commands directly on remote servers.
