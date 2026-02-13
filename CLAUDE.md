# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Peerix is a peer-to-peer binary cache for Nix. It lets NixOS machines on the same local network discover and share store paths with each other via UDP broadcast, avoiding redundant downloads from upstream caches.

## Build & Run

This is a Nix flake project with a Python (3.9) application:

```bash
# Enter dev shell (provides nix-serve, niv, python with deps)
nix develop            # flake-based
nix-shell              # legacy, uses flake-compat

# Build the package
nix build              # produces result/bin/peerix

# Run directly
nix run . -- --port 12304 --timeout 50 --verbose

# Run from source (inside dev shell)
python -m peerix --port 12304 --verbose
```

There are no tests in this project.

## Architecture

The system has two halves — a **local store** (wraps `nix-serve` for the machine's own `/nix/store`) and a **remote store** (UDP discovery + HTTP fetch from peers). Both are exposed through a single Starlette HTTP server (served via Hypercorn/uvloop).

### Key modules (`peerix/`)

- **`store.py`** — Base `Store` class and data models (`NarInfo`, `CacheInfo` NamedTuples with `parse()`/`dump()` serialization). All stores implement `cache_info()`, `narinfo(hash)`, and `nar(url)`.
- **`local.py`** — `LocalStore`: launches `nix-serve` on a Unix socket, proxies narinfo requests to it, and streams NARs via `nix dump-path`. The `local()` context manager handles the nix-serve subprocess lifecycle.
- **`remote.py`** — `DiscoveryProtocol`: a UDP datagram protocol that broadcasts narinfo requests to all private-network broadcast addresses, waits for peer responses (with configurable timeout), then fetches narinfo/NAR data over HTTP from the responding peer. Implements the `Store` interface.
- **`prefix.py`** — `PrefixStore`: decorator that namespaces URL paths so local and remote NAR routes don't collide.
- **`app.py`** — Starlette routes wiring it together. `setup_stores()` initializes both stores. Narinfo endpoint (`/{hash}.narinfo`) is restricted to `127.0.0.1` (nix daemon only). Local endpoints serve to peers; `/v2/remote/` endpoints serve peer-fetched content to the local nix daemon.
- **`__main__.py`** — CLI entry point: argparse for `--port`, `--timeout`, `--verbose`, `--private-key`.

### Network protocol

- UDP port 12304 (configurable): peer discovery via broadcast. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- HTTP port 12304: serves both local narinfo/NAR to peers and proxied remote content to the local nix daemon.

### NixOS integration

- **`module.nix`** — NixOS module (`services.peerix.*` options). Configures a hardened systemd service, adds `http://127.0.0.1:12304/` as a nix substituter, and manages trusted public keys and firewall rules.
- **`flake.nix`** — Exposes `packages.peerix`, `nixosModules.peerix`, overlay, and dev shell.

## Dependencies

Python: `aiohttp`, `uvloop`, `hypercorn`, `starlette`, `psutil`
System: `nix`, `nix-serve` (both must be on PATH)
