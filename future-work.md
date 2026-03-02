# Iroh Mode: Feature Parity with IPFS Mode

## TODO

### 1. NAR Download from Peers ✅
- [x] Rewrite NAR URLs in narinfo to route through Iroh peer fetch
- [x] Add `/iroh/nar/{peer_id}/{path}` endpoint that fetches via `IrohNode.fetch_nar()`
- [x] Track which peer provided the narinfo to fetch NAR from same peer

### 2. Narinfo Signing ✅
- [x] Integrate `pynacl` signing for narinfo responses
- [x] Support `NIX_SECRET_KEY_FILE` environment variable
- [x] Sign fingerprint format: `1;storePath;narHash;narSize;refs...`
- [x] Add `--private-key` CLI option

### 3. Store Scanning with On-the-fly NAR Generation ✅
- [x] Reuse scan part from `scan_and_publish` in `ipfs_store.py`
- [x] Skip IPFS publish step - generate NAR on-the-fly when requested
- [ ] Add cache for frequently requested NARs (LRU or similar) - deferred, may not be needed
- [x] Track which hashes are available locally for tracker announcement

### 4. Delta Sync ✅
- [x] Announce local package hashes to tracker
- [x] Use delta sync (only send added/removed hashes)
- [x] Persist announced state to `/var/lib/peerix/announced_state.json`
- [x] Periodic re-sync (every 5 minutes like IPFS mode)

### 5. Nixpkgs Filtering ✅
- [x] Integrate `NixpkgsFilteredStore` - only serve packages in cache.nixos.org
- [x] Support `FilteredStore` with custom patterns
- [x] Add `--no-filter` and `--filter-mode` CLI options

### 6. Verified Store ✅
- [x] Integrate `VerifiedStore` wrapper
- [x] Verify NAR hashes against upstream cache (cache.nixos.org)
- [x] Add `--no-verify` and `--upstream-cache` CLI options
- [ ] TOCTOU protection during streaming - deferred (exists in VerifiedStore but not exposed)

### 7. Dashboard ✅
- [x] Port dashboard HTML from `app.py`
- [x] Adapt for Iroh mode (show Iroh peers instead of IPFS swarm)
- [x] Progress tracking with Kalman filter ETA
- [x] Pause/resume controls for scanning
- [ ] Show tracker peers with geo-location - deferred
- [x] `/status` endpoint with full node info
- [x] `/dashboard-stats` JSON endpoint

### 8. NAR Compression
- [ ] Compress NARs on-the-fly (zstd or xz)
- [ ] Add `Compression: zstd` header to narinfo
- [ ] Make compression level configurable
- [ ] Consider caching compressed NARs for frequently requested packages

### 9. Iroh Streaming Reliability
- [ ] Investigate IrohError during NAR streaming (connection drops mid-transfer)
- [ ] Add retry logic for failed NAR fetches
- [ ] Consider chunked transfers with resume capability

## Completed
- [x] Persistent node identity (Ed25519 secret key)
- [x] Tracker integration for Iroh peer discovery
- [x] NAT traversal via Iroh relay
- [x] Narinfo fetch from peers
- [x] Basic HTTP endpoints (/nix-cache-info, /{hash}.narinfo, /nar/, /status, /peers)
- [x] NAR download from Iroh peers (/iroh/nar/{peer_id}/{path})
- [x] Narinfo signing with pynacl
- [x] Store scanning with package hash tracking
- [x] Delta sync for package hashes
- [x] Nixpkgs filtering (NixpkgsFilteredStore)
- [x] Hash verification (VerifiedStore)
- [x] Dashboard with Iroh status and controls
