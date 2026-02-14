# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Peerix is a peer-to-peer binary cache for Nix. It supports two discovery modes:
- **LAN**: UDP broadcast for zero-config peer discovery on local networks.
- **WAN**: Tracker-based discovery for peers across different networks (NAT, VPN, cloud).
- **Both**: LAN and WAN simultaneously.

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

# Run with WAN mode
nix run . -- --mode wan --tracker-url http://tracker:12305 --verbose

# Run with signing
NIX_SECRET_KEY_FILE=/path/to/key.pem nix run . -- --verbose

# Run tracker
nix run . -- --tracker  # or: peerix-tracker --port 12305

# Run from source (inside dev shell)
python -m peerix --port 12304 --verbose
```

There are no tests in this project. Use `test-vm/` for integration testing (see below).

## Architecture

The system has two halves — a **local store** (wraps `nix-serve` for the machine's own `/nix/store`) and a **remote store** (LAN UDP discovery or WAN tracker-based discovery + HTTP fetch from peers). Both are exposed through a single Starlette HTTP server (served via Hypercorn/uvloop).

### Key modules (`peerix/`)

- **`store.py`** — Base `Store` class and data models (`NarInfo`, `CacheInfo` NamedTuples with `parse()`/`dump()` serialization). All stores implement `cache_info()`, `narinfo(hash)`, and `nar(url)`. The `NarInfo.parse()` skips lines without `:` to handle empty lines gracefully.
- **`local.py`** — `LocalStore`: launches `nix-serve` on a Unix socket, proxies narinfo requests to it, and streams NARs via `nix-store --dump`. The `local()` context manager handles the nix-serve subprocess lifecycle. Important: `NIX_SECRET_KEY_FILE` is stripped from nix-serve's env to avoid Perl crashes — signing is handled by peerix itself in `app.py`.
- **`remote.py`** — `DiscoveryProtocol`: a UDP datagram protocol that broadcasts narinfo requests to all private-network broadcast addresses, waits for peer responses (with configurable timeout), then fetches narinfo/NAR data over HTTP from the responding peer. Implements the `Store` interface.
- **`wan.py`** — `TrackerStore`: WAN peer discovery via tracker. Queries tracker for peers, fetches narinfo from peers via HTTP, rewrites NAR URLs to route through the local WAN endpoint. Streams NARs with transfer tracking for reputation.
- **`tracker.py`** — Standalone tracker server (Starlette + SQLite). Manages peer registry (announce/heartbeat), peer listing, transfer initiation, and transfer reporting for reputation.
- **`tracker_client.py`** — Client for the tracker. Handles heartbeat announcements, peer listing, transfer init/reporting. Supports `announce_addr` for NAT scenarios where auto-detected IP is wrong.
- **`prefix.py`** — `PrefixStore`: decorator that namespaces URL paths so local, remote, and WAN NAR routes don't collide.
- **`filtered.py`** — `FilteredStore`: heuristic filtering of system-specific/sensitive derivations for WAN sharing safety.
- **`verified.py`** — `VerifiedStore`: verifies store path hashes against upstream cache before WAN sharing.
- **`app.py`** — Starlette routes wiring it together. `setup_stores()` initializes stores based on mode. Narinfo endpoint (`/{hash}.narinfo`) is restricted to `127.0.0.1` (nix daemon only). Includes ed25519 narinfo signing via `pynacl` when `NIX_SECRET_KEY_FILE` is set. Routes: `/local/` for peer-to-peer, `/v2/remote/` for LAN, `/v3/wan/` for WAN.
- **`__main__.py`** — CLI entry point: argparse for `--port`, `--timeout`, `--verbose`, `--private-key`, `--mode`, `--tracker-url`, `--announce-addr`, `--peer-id`, `--no-verify`, `--no-filter`, etc.

### Network protocol

- **LAN**: UDP port 12304 (configurable) — peer discovery via broadcast. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- **WAN**: Peers announce to tracker via HTTP POST `/announce`. Tracker responds with peer list at GET `/peers`. Transfers are tracked via `/transfer/init` and `/transfer/report`.
- **HTTP port 12304** (configurable): serves local narinfo/NAR to peers and proxied remote/WAN content to the local nix daemon.

### NixOS integration

- **`module.nix`** — NixOS module (`services.peerix.*` options). Configures a hardened systemd service, adds `http://127.0.0.1:{port}/` as a nix substituter, manages trusted public keys, firewall rules, and all WAN/tracker options. Also includes `services.peerix.tracker.*` for running a tracker.
- **`flake.nix`** — Exposes `packages.peerix`, `nixosModules.peerix`, overlay, and dev shell.

## Known Issues & Gotchas

- **`nix-serve` storeDir bug**: nix-serve may return `StoreDir: Nix::Store::getStoreDir` (literal Perl code). `local.py` handles this by falling back to `/nix/store`.
- **`nix dump-path` deprecated**: Newer Nix requires `--extra-experimental-features nix-command`. We use `nix-store --dump` instead, which is stable.
- **`NIX_SECRET_KEY_FILE` + nix-serve**: Passing this env var to nix-serve causes Perl crashes. Peerix strips it from nix-serve's environment and handles signing itself.
- **Narinfo signing**: Peerix signs narinfo at the HTTP response level using ed25519 (pynacl). The fingerprint format is `1;storePath;narHash;narSize;/nix/store/ref1,/nix/store/ref2,...` with comma-separated sorted full store paths.
- **WAN NAR URL format**: The narinfo URL encodes the full WAN routing path: `wan/{addr}/{port}/{peer_id}/{hash}/{nar_url}`. The `nar_url` already includes `local/nar/` — don't prepend it again.
- **Transfer roles**: In `tracker_client.py`, `init_transfer(sender_id)` — the caller is the *receiver* (fetching the NAR), the argument is the *sender* (the peer providing the NAR).
- **`/{hash}.narinfo` is restricted to 127.0.0.1**: External peers must use `/local/{hash}.narinfo` instead. This is by design — the main narinfo endpoint is for the local nix daemon only.
- **`nix-build --option require-sigs false`**: Even with `trusted-users`, this may not work in all nix versions. Prefer proper signing with `NIX_SECRET_KEY_FILE` and `trusted-public-keys`.

## Test VM (`test-vm/`)

A QEMU/KVM VM for integration testing WAN mode:

```bash
cd test-vm

# Build the VM
nix build .#nixosConfigurations.test-vm.config.system.build.vm

# Run with port forwarding (VM peerix on port 12306)
QEMU_NET_OPTS='hostfwd=tcp::12306-:12306' ./result/bin/run-peerix-test-vm-vm
```

The VM uses `port = 12306` to distinguish from the host's `12304`. It talks to the tracker at `10.0.2.2:12305` (QEMU user-net host address). The host should use `--announce-addr 10.0.2.2` so the VM can reach back.

Typical test setup (4 tmux panes):
1. Tracker: `python -m peerix.tracker --port 12305`
2. Host peerix: `NIX_SECRET_KEY_FILE=test-vm/cache-priv-key.pem nix run . -- --mode both --tracker-url http://127.0.0.1:12305 --no-verify --no-filter --announce-addr 10.0.2.2 --verbose`
3. VM (auto-starts peerix via systemd)
4. Host shell for testing

To test: build a derivation on one peer using `test-vm/slow-build.nix` (same pinned nixpkgs on both), then fetch it on the other peer via peerix. Use `base64` encoding to transfer the exact nix file to the VM to ensure derivation hashes match.

## Dependencies

Python: `aiohttp`, `uvloop`, `hypercorn`, `starlette`, `psutil`, `pynacl` (optional, for narinfo signing)
System: `nix`, `nix-serve` (both must be on PATH)
