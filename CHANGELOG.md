# Changelog

## v0.0.4 (2026-03-03)

### New Features

#### Health & Metrics Endpoints
- **`/health`**: Health check endpoint for systemd watchdog integration
  - Reports start time, last successful operation, error count
  - Returns 200 when healthy, 503 when degraded
- **`/metrics`**: Prometheus-compatible metrics endpoint
  - `nars_served_total`, `narinfos_served_total`
  - `bytes_sent_total`, `bytes_received_total`
  - `cache_hits_total`, `cache_misses_total`
  - `peer_requests_total`, `request_duration_seconds`
  - Per-peer bandwidth statistics

#### Peer Reputation System
- Track peer reliability with success/failure counts
- Exponential backoff for failing peers (1s → 2s → 4s → ... → 300s max)
- Peer scoring based on:
  - Success rate (60% weight)
  - Average latency (20% weight)
  - Recency of activity (20% weight)
- Peers sorted by reputation score when querying for packages

#### Unified LAN + Iroh Discovery
- LAN discovery now works alongside Iroh (not as separate mode)
- Enable with `lanDiscovery = true` in NixOS module or `--lan-discovery` CLI flag
- Checks LAN peers via UDP broadcast when Iroh peers don't have package
- Proxy endpoint `/lan/nar/{peer_addr}/{peer_port}/{path}` for LAN NAR fetching

#### Config File Support
- Load configuration from `~/.config/peerix/config.toml`
- CLI arguments override config file values
- TOML sections: `[server]`, `[tracker]`, `[store]`, `[signing]`, `[security]`

#### Test Suite
- Added `peerix/tests/` with pytest-based unit tests
- Tests for: NAR hash computation, path validation, peer reputation, config loading, Kalman ETA, metrics

#### Graceful Shutdown
- Deregister from tracker on shutdown (DELETE `/iroh/peer/{node_id}`)
- Save dashboard stats before exit
- Clean shutdown of LAN discovery, store manager, filters

### Improvements

- **Per-peer bandwidth tracking**: Track bytes sent/received per peer
- **Tracker deregistration**: DELETE endpoint for peer cleanup
- **Better status reporting**: `/status` endpoint shows mode (iroh/lan) and LAN discovery state

### Configuration Changes

New NixOS module options:
- `services.peerix.lanDiscovery` - Enable LAN discovery alongside Iroh (default: false)

New CLI flags:
- `--lan-discovery` - Enable LAN peer discovery via UDP broadcast
- `--config` / `-c` - Path to config file

---

## v0.0.3 (2026-03-03)

### Major Change: IPFS replaced with Iroh P2P

This release replaces IPFS with [Iroh](https://iroh.computer/) for peer-to-peer connectivity. Iroh provides reliable NAT traversal and direct peer connections without requiring a local IPFS daemon.

#### Why the switch?

- **Simpler setup**: No need to run and configure IPFS daemon
- **Better NAT traversal**: Iroh's relay servers work out of the box
- **Direct connections**: Peers connect directly when possible, falling back to relay
- **Lighter footprint**: No IPFS daemon memory/CPU overhead
- **More reliable**: Pre-buffered NAR transfers with automatic retry

#### Migration

If upgrading from v0.0.2:

1. IPFS daemon is no longer required - you can disable `services.kubo`
2. Mode changed from `"ipfs"` to `"iroh"` (now default)
3. CID cache (`/var/lib/peerix/cid_cache.json`) no longer used
4. New state files:
   - `/var/lib/peerix/iroh_secret.key` - persistent node identity
   - `/var/lib/peerix/stats.json` - dashboard stats persistence

### New Features

#### Web Dashboard (`/dashboard`)
- Real-time node status (Iroh node ID, relay URL, direct addresses)
- Connected peers list with country flags and IPs
- Store scan progress with ETA
- Most requested derivations tracking
- Most served derivations with per-peer tracking
- Activity log showing checks, downloads, and serves
- Pause/resume scan controls

#### Stats Persistence
- Dashboard stats survive restarts
- Saved to `/var/lib/peerix/stats.json` every 60 seconds
- Signal handler ensures stats saved on shutdown

#### Peer Tracking
- Track which peers received which packages
- Per-peer serve counts in dashboard
- Activity log shows peer IDs for served packages

### Improvements

- **NixpkgsFilteredStore**: Only serve packages available in cache.nixos.org
- **Hash verification**: TOCTOU-safe verification against upstream cache
- **Connection pooling**: Reuse Iroh connections per peer/protocol
- **Pre-buffered NAR streaming**: Download entire NAR before HTTP response, enabling retries
- **Delta sync**: Only send changed hashes to tracker after initial sync
- **Persistent identity**: Same Iroh node ID across restarts

### Configuration Changes

New options:
- `services.peerix.filterConcurrency` - max concurrent filter requests (default: 10)
- `services.peerix.scanInterval` - seconds between store scans (default: 3600)

Removed options (IPFS-related):
- `services.peerix.ipfs.*` - all IPFS configuration options
- `services.peerix.mode = "ipfs"` - use `"iroh"` instead

### Breaking Changes

- IPFS mode removed - use Iroh mode instead
- LibP2P mode removed
- Hybrid mode removed
- `peerix` binary replaced with `peerix-iroh`

---

## v0.0.2

- Added IPFS mode for content-addressed NAR distribution
- Added package filtering and hash verification
- Added web dashboard for scan progress
- Added tracker for peer discovery

## v0.0.1

- Initial release
- LAN mode with UDP broadcast discovery
- Basic narinfo signing support
