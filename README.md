Peerix
======

Peer-to-peer binary cache for Nix. Share derivations between machines via IPFS or local network broadcast.

Quick Start
-----------

### IPFS Mode (default)

Uses local IPFS daemon for content-addressed NAR distribution.

Add to `flake.nix` inputs:

```nix
inputs.peerix.url = "github:sophronesis/peerix";
```

Add `peerix.nixosModules.peerix` to your modules, then in `configuration.nix`:

```nix
services.peerix = {
  enable = true;
  # trackerUrl = "http://your-tracker:12305";  # defaults to sophronesis.dev/peerix
};
```

### LAN Mode

Zero-config peer discovery on local networks (no internet required):

```nix
services.peerix = {
  enable = true;
  mode = "lan";
};
```

### Run Your Own Tracker

```nix
# On server
services.peerix-tracker.enable = true;

# On clients
services.peerix.trackerUrl = "http://your-server:12305";
```

How It Works
------------

Peerix implements a Nix binary cache. When Nix queries peerix for a package:

1. **IPFS mode**: Checks tracker for CID mapping, fetches NAR from IPFS
2. **LAN mode**: Broadcasts UDP request, peers respond if they have the package

Store path hashes are verified against `cache.nixos.org` by default.

### IPFS Mode Details

- Periodically scans local store and publishes NARs to IPFS
- CID mappings registered with tracker for peer discovery
- DHT announcement for content discoverability across NAT
- Web dashboard at `http://localhost:12304/` shows scan progress

Configuration
-------------

| Option | Default | Description |
|--------|---------|-------------|
| `enable` | `false` | Enable peerix |
| `mode` | `"ipfs"` | Discovery mode: `"ipfs"` or `"lan"` |
| `port` | `12304` | HTTP server port |
| `trackerUrl` | `null` | Tracker URL (required for IPFS mode) |
| `openFirewall` | `true` | Open firewall ports |
| `privateKeyFile` | `null` | Path to signing key |
| `publicKey` | `null` | Public key for signature verification |

### Tracker Options

| Option | Default | Description |
|--------|---------|-------------|
| `services.peerix-tracker.enable` | `false` | Enable tracker server |
| `services.peerix-tracker.port` | `12305` | Tracker HTTP port |

Signing
-------

Generate a key pair:

```bash
nix-store --generate-binary-cache-key myhost cache-priv-key.pem cache-pub-key.pem
```

Set `privateKeyFile` on the serving node and `publicKey` (or `publicKeyFile`) on consuming nodes so nix can verify signatures.

Alternatively, set `NIX_SECRET_KEY_FILE` environment variable — peerix will sign narinfo responses with ed25519 directly (requires `pynacl`).

Configuration Options
---------------------

### Peerix Service

| Option                           | Description                                                                                  | Default   |
|----------------------------------|----------------------------------------------------------------------------------------------|-----------|
| `services.peerix.enable`         | Enables Peerix.                                                                              | `false`   |
| `services.peerix.openFirewall`   | Open the necessary firewall ports.                                                           | `true`    |
| `services.peerix.port`           | Port for the HTTP server and peer announcements.                                             | `12304`   |
| `services.peerix.mode`           | Discovery mode: `"ipfs"`, `"libp2p"`, `"lan"`, `"wan"`, `"both"`, or `"hybrid"`.             | `"ipfs"`  |
| `services.peerix.user`           | User to run the peerix service under.                                                        | `"nobody"`|
| `services.peerix.group`          | Group to run the peerix service under.                                                       | `"nobody"`|
| `services.peerix.privateKeyFile` | Path to the private key file for signing derivations.                                        | `null`    |
| `services.peerix.publicKeyFile`  | Path to the public key file for verifying signatures.                                        | `null`    |
| `services.peerix.publicKey`      | Public key string for verifying signatures.                                                  | `null`    |
| `services.peerix.globalCacheTTL` | How long (seconds) nix should cache narinfo entries.                                         | `null`    |
| `services.peerix.package`        | The peerix package to use. Use `pkgs.peerix` for a smaller version without libp2p.           | `pkgs.peerix-full` |

### WAN Options

| Option                               | Description                                                                              | Default   |
|---------------------------------------|------------------------------------------------------------------------------------------|-----------|
| `services.peerix.trackerUrl`          | URL of the peerix tracker server. Required for `wan` and `both` modes.                   | `null`    |
| `services.peerix.announceAddr`        | Address to announce to the tracker. Overrides auto-detected IP (useful for NAT/VPN).     | `null`    |
| `services.peerix.peerId`              | Unique peer ID. Auto-generated if not set.                                               | `null`    |
| `services.peerix.upstreamCache`       | Upstream cache URL for hash verification.                                                | `"https://cache.nixos.org"` |
| `services.peerix.noVerify`            | Disable hash verification against upstream cache.                                        | `false`   |
| `services.peerix.noFilter`            | Disable heuristic filtering of system/sensitive derivations.                             | `false`   |
| `services.peerix.noDefaultFilters`    | Keep filtering but skip built-in default patterns.                                       | `false`   |
| `services.peerix.filterPatterns`      | Additional fnmatch patterns to exclude from WAN sharing.                                 | `[]`      |

### LibP2P Options

| Option                               | Description                                                                              | Default   |
|---------------------------------------|------------------------------------------------------------------------------------------|-----------|
| `services.peerix.bootstrapUrl`        | URL to fetch bootstrap peer dynamically. Used when bootstrapPeers is empty.              | `"https://sophronesis.dev/peerix/bootstrap"` |
| `services.peerix.bootstrapPeers`      | Static LibP2P bootstrap peer multiaddrs. If empty, fetched from bootstrapUrl.            | `[]`      |
| `services.peerix.relayServers`        | LibP2P relay server multiaddrs for NAT traversal fallback.                               | `[]`      |
| `services.peerix.networkId`           | Network ID for peer isolation. Peers must share the same ID.                             | `"default"` |
| `services.peerix.listenAddrs`         | LibP2P listen addresses. Note: py-libp2p 0.6.0 only supports TCP.                        | `["/ip4/0.0.0.0/tcp/{port+1000}"]` |

### IPFS Options

| Option | Description | Default |
|--------|-------------|---------|
| `services.peerix.ipfs.enable` | Enable IPFS integration. | `true` |
| `services.peerix.ipfs.configureKubo` | Auto-configure kubo daemon with recommended settings. | `true` |
| `services.peerix.ipfs.lowBandwidth` | **Enable conservative settings for limited networks.** Disables QUIC, sets low connection limits (2/5), rate limits to 3 MiB/s. | `true` |
| `services.peerix.ipfs.routingType` | DHT mode: `"dhtclient"`, `"dht"`, `"dhtserver"`, `"none"`, `"autoclient"`. | `"dhtclient"` |
| `services.peerix.ipfs.enableQUIC` | Enable QUIC/UDP transport. Disable if network gets flooded. | `true` (off in lowBandwidth) |
| `services.peerix.ipfs.acceleratedDHTClient` | Enable accelerated DHT client for faster lookups. | `false` |
| `services.peerix.ipfs.connMgr.lowWater` | Start pruning connections above this. | `600` (5 in lowBandwidth) |
| `services.peerix.ipfs.connMgr.highWater` | Hard connection limit. | `900` (10 in lowBandwidth) |
| `services.peerix.ipfs.resourceMgr.connsInbound` | Max inbound connections. | auto (7 in lowBandwidth) |
| `services.peerix.ipfs.resourceMgr.connsOutbound` | Max outbound connections. | auto (7 in lowBandwidth) |
| `services.peerix.ipfs.rateLimit.enable` | Enable iptables rate limiting for IPFS. | `false` (true in lowBandwidth) |
| `services.peerix.ipfs.rateLimit.totalBandwidth` | Hard cap on total IPFS bandwidth (KiB/s). | `null` (3072 in lowBandwidth) |

### Tracker Service

Run your own tracker for private networks or as a public bootstrap node:

| Option                               | Description                                                                              | Default   |
|---------------------------------------|------------------------------------------------------------------------------------------|-----------|
| `services.peerix-tracker.enable`      | Enable the peerix tracker server.                                                        | `false`   |
| `services.peerix-tracker.port`        | Port for the tracker HTTP server.                                                        | `12305`   |
| `services.peerix-tracker.dbPath`      | Path to the tracker SQLite database.                                                     | `"/var/lib/peerix-tracker/tracker.db"` |
| `services.peerix-tracker.openFirewall`| Open the firewall for the tracker port.                                                  | `true`    |
| `services.peerix-tracker.package`     | The peerix package to use.                                                               | `pkgs.peerix-full` |

Dashboard
---------

Peerix includes a web dashboard for monitoring at `http://localhost:12304/dashboard`:

- **Scan Progress**: Current store scan status with ETA
- **DHT Announce**: DHT announcement progress with pause/resume controls
- **IPFS Swarm Peers**: Connected peers with per-peer bandwidth stats
- **Controls**: Stop IPFS button for emergencies

The dashboard auto-refreshes and reloads when peerix is updated.

Scripts
-------

Utility scripts in `scripts/`:

- `network_watchdog.sh` - Monitor network connectivity and auto-kill IPFS/peerix if unresponsive
- `diagnose_network.sh` - Network diagnostics for troubleshooting
- `monitor_flood.sh` - Monitor for network flooding
- `ipfs_dashboard.sh` - Quick IPFS stats

WAN Mode
--------

WAN mode enables peer-to-peer sharing across different networks using a lightweight tracker server for peer discovery.

### Setup

1. Run a tracker on an accessible host:

```nix
services.peerix-tracker.enable = true;
```

2. Configure peers to use WAN mode:

```nix
services.peerix = {
  enable = true;
  mode = "wan";
  trackerUrl = "http://tracker-host:12305";
};
```

3. For peers behind NAT, use `announceAddr` to specify the reachable address:

```nix
services.peerix = {
  enable = true;
  mode = "wan";
  trackerUrl = "http://tracker-host:12305";
  announceAddr = "my-public-ip-or-hostname";
};
```

### Security

WAN mode includes several safety features:

- **Hash verification**: By default, store path hashes are verified against the upstream cache before sharing.
- **Heuristic filtering**: System-specific and sensitive derivations (passwords, keys, network configs) are excluded from WAN sharing.
- **Narinfo signing**: When `NIX_SECRET_KEY_FILE` or `privateKeyFile` is set, narinfo responses are signed with ed25519, allowing peers to verify authenticity with `require-sigs = true`.
- **Reputation tracking**: The tracker records transfer history for peer reputation.

LibP2P Mode
-----------

LibP2P mode enables true peer-to-peer networking with built-in NAT traversal using the libp2p stack. This includes DHT-based peer discovery, mDNS for local network discovery, and hole punching for connecting peers behind NAT.

### Setup

LibP2P mode works out of the box with default settings - peers connect via a public bootstrap server:

```nix
services.peerix = {
  enable = true;
  mode = "libp2p";
};
```

For private networks, set a custom `networkId` (all peers must match):

```nix
services.peerix = {
  enable = true;
  mode = "libp2p";
  networkId = "my-private-network";
  bootstrapPeers = [
    "/ip4/your-server/tcp/13304/p2p/QmYourPeerID"
  ];
};
```

To find your peer's multiaddr, check the logs:

```bash
journalctl -u peerix | grep "LibP2P listening"
# Output: LibP2P listening on: ['/ip4/1.2.3.4/tcp/13304/p2p/16Uiu2HAm...']
```

### NAT Traversal

LibP2P handles NAT traversal automatically via:

- **mDNS**: Discovers peers on the local network without configuration.
- **DHT**: Kademlia distributed hash table for global peer discovery.
- **Hole Punching**: Establishes direct connections between NAT'd peers.
- **Relay**: Falls back to relay servers when direct connection fails.

For peers behind restrictive NAT, you can configure relay servers:

```nix
services.peerix = {
  enable = true;
  mode = "libp2p";
  networkId = "my-network";
  bootstrapPeers = [ "/ip4/.../p2p/..." ];
  relayServers = [ "/ip4/.../p2p/..." ];  # Optional relay fallback
};
```

### Hybrid Mode

Hybrid mode combines libp2p with the HTTP tracker for maximum compatibility:

```nix
services.peerix = {
  enable = true;
  mode = "hybrid";
  networkId = "my-network";
  bootstrapPeers = [ "/ip4/.../p2p/..." ];
  trackerUrl = "http://tracker-host:12305";  # Also use HTTP tracker
};
```

This allows peers using libp2p to connect with peers using the HTTP tracker.

### Bootstrap API

Peerix exposes a `/bootstrap` endpoint that returns the current peer's multiaddr:

```bash
curl https://your-bootstrap-server:12304/bootstrap
# Returns: {"peer_id": "16Uiu2HAm...", "multiaddrs": ["/ip4/.../p2p/..."], "network_id": "default"}
```

This enables dynamic bootstrap peer discovery - clients fetch the current peer ID at startup instead of using hardcoded values that break when the server restarts.

IPFS Mode
---------

IPFS mode uses the local IPFS daemon for content-addressed NAR distribution. Instead of streaming NARs directly between peers, NARs are added to IPFS and addressed by CID (Content Identifier). This leverages IPFS's content-addressed storage and distribution network.

### How It Works

1. **Periodic Scanning**: Peerix periodically scans the local nix store (default: every hour), filters out sensitive packages, and publishes applicable NARs to IPFS
2. **CID Registry**: NarHash → CID mappings are stored locally and registered with the tracker so other peers can discover available content
3. **Fetching**: When querying narinfo, peerix checks the tracker for CID mappings and fetches from IPFS if available
4. **Startup Sync**: On startup, all local CID mappings are pre-registered with the tracker

### Setup

IPFS mode requires a running IPFS daemon:

```bash
# Start IPFS daemon
ipfs daemon &

# Run peerix in IPFS mode
nix run . -- --mode ipfs --tracker-url http://tracker:12305 --verbose
```

NixOS configuration:

```nix
services.peerix = {
  enable = true;
  mode = "ipfs";
  trackerUrl = "http://tracker-host:12305";
};

# Ensure IPFS daemon is running
services.kubo.enable = true;
```

### Benefits

- **Content-addressed**: NARs are deduplicated across the IPFS network
- **Resilience**: Content persists in IPFS even if the original peer goes offline
- **Interoperability**: Potential future integration with nix IPFS support (nix#859)

### Configuration

| Option | CLI | Default | Description |
|--------|-----|---------|-------------|
| `scanInterval` | `--scan-interval` | `3600` | Seconds between store scans (0 to disable) |

- Scans **all** store paths (no limit), filters sensitive packages, publishes to IPFS
- CID mappings synced to tracker after each scan
- CID cache stored at `/var/lib/peerix/cid_cache.json`
- IPFS API defaults to `http://127.0.0.1:5001/api/v0`
- NAR URLs use `ipfs/{cid}` format when fetched via IPFS
- Filtering uses same patterns as WAN mode (system configs, secrets, etc.)

Network Protocol
----------------

- **LAN**: UDP port 12304 (configurable) for broadcast-based peer discovery. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- **WAN**: Peers announce to the tracker via HTTP. The tracker maintains a peer registry and transfer history in SQLite.
- **LibP2P**: TCP port 13304 (HTTP port + 1000) for libp2p connections. Uses custom protocols `/peerix/narinfo/1.0.0` and `/peerix/nar/1.0.0` for narinfo queries and NAR transfers. DHT keys use `/peerix/v1/network/{network_id_hash}` namespace.
- **IPFS**: Uses local IPFS daemon API (port 5001) to add/fetch NARs. CID mappings are tracked via tracker's `/cid` endpoints. NAR URLs use `ipfs/{cid}` format.
- **HTTP**: Port 12304 (configurable) serves both local narinfo/NAR to peers and proxied remote content to the local nix daemon.

Dependencies
------------

- Python 3.12+: `trio`, `hypercorn`, `starlette`, `httpx`, `pynacl`
- IPFS mode: local IPFS daemon (kubo)
- System: `nix`, `nix-serve`
