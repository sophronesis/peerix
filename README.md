Peerix
======

Peer-to-peer binary cache for Nix. Share derivations between machines via Iroh P2P or local network broadcast.
Basically like torrent tracker, but for your `/nix/store/`

Quick Start
-----------

### Iroh Mode (default)

Uses Iroh for NAT-traversing P2P connectivity with automatic relay fallback.

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

1. **Iroh mode**: Queries peers via Iroh P2P protocol, fetches NAR directly from peer
2. **LAN mode**: Broadcasts UDP request, peers respond if they have the package

Store path hashes are verified against `cache.nixos.org` by default.

### Iroh Mode Details

- NAT traversal via Iroh relay servers (euw1-1.relay.iroh.network)
- Direct peer connections when possible
- Persistent node identity across restarts
- Connection pooling with retry logic
- Pre-buffered NAR streaming for reliability
- Web dashboard at `http://localhost:12304/dashboard`

Configuration
-------------

| Option | Default | Description |
|--------|---------|-------------|
| `enable` | `false` | Enable peerix |
| `mode` | `"iroh"` | Discovery mode: `"iroh"` or `"lan"` |
| `port` | `12304` | HTTP server port |
| `trackerUrl` | `null` | Tracker URL for peer discovery |
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

Dashboard
---------

Peerix includes a web dashboard at `http://localhost:12304/dashboard`:

- **Node Status**: Iroh node ID, relay URL, direct addresses
- **Peers**: Connected peers with country flags and IPs
- **Store**: Available hashes, filter progress, scan status
- **Most Requested**: Top requested derivations
- **Most Served**: Top served derivations with per-peer tracking
- **Activity Log**: Recent checks, downloads, and serves with peer IDs

Stats persist across restarts to `/var/lib/peerix/stats.json`.

Configuration Options
---------------------

### Peerix Service

| Option | Description | Default |
|--------|-------------|---------|
| `services.peerix.enable` | Enables Peerix | `false` |
| `services.peerix.openFirewall` | Open the necessary firewall ports | `true` |
| `services.peerix.port` | Port for the HTTP server | `12304` |
| `services.peerix.mode` | Discovery mode: `"iroh"` or `"lan"` | `"iroh"` |
| `services.peerix.user` | User to run the peerix service under | `"nobody"` |
| `services.peerix.group` | Group to run the peerix service under | `"nobody"` |
| `services.peerix.privateKeyFile` | Path to the private key file for signing | `null` |
| `services.peerix.publicKeyFile` | Path to the public key file for verification | `null` |
| `services.peerix.publicKey` | Public key string for verification | `null` |
| `services.peerix.trackerUrl` | URL of the peerix tracker server | `null` |
| `services.peerix.upstreamCache` | Upstream cache URL for hash verification | `"https://cache.nixos.org"` |
| `services.peerix.noVerify` | Disable hash verification against upstream | `false` |
| `services.peerix.noFilter` | Disable filtering (serve all packages) | `false` |
| `services.peerix.scanInterval` | Seconds between store scans (0 to disable) | `3600` |
| `services.peerix.filterConcurrency` | Max concurrent filter requests | `10` |

### Tracker Service

| Option | Description | Default |
|--------|-------------|---------|
| `services.peerix-tracker.enable` | Enable the peerix tracker server | `false` |
| `services.peerix-tracker.port` | Port for the tracker HTTP server | `12305` |
| `services.peerix-tracker.dbPath` | Path to the tracker SQLite database | `"/var/lib/peerix-tracker/tracker.db"` |
| `services.peerix-tracker.openFirewall` | Open the firewall for the tracker port | `true` |

Security
--------

- **Hash verification**: Store path hashes verified against upstream cache before sharing
- **NixpkgsFilteredStore**: Only serves packages that exist in cache.nixos.org
- **Narinfo signing**: When `NIX_SECRET_KEY_FILE` or `privateKeyFile` is set, narinfo responses are signed with ed25519
- **Localhost restriction**: Main narinfo endpoint restricted to 127.0.0.1

Network Protocol
----------------

- **Iroh**: Custom protocols `/peerix/narinfo/1.0.0` and `/peerix/nar/1.0.0` over QUIC. NAT traversal via relay servers, direct connections when possible.
- **LAN**: UDP port 12304 for broadcast-based peer discovery. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- **HTTP**: Port 12304 serves local narinfo/NAR to peers and proxied remote content to the local nix daemon.
- **Tracker**: HTTP API for peer registration and package hash lookup.

Dependencies
------------

- Python 3.12+: `trio`, `starlette`, `httpx`, `pynacl`, `uvicorn`
- Iroh mode: `iroh` Python bindings
- System: `nix`, `nix-serve`

CLI Usage
---------

```bash
# Run with Iroh mode (default)
peerix-iroh --port 12304 --tracker https://sophronesis.dev/peerix --verbose

# Options
--port          HTTP port (default: 12304)
--tracker       Tracker URL for peer discovery
--peer-id       Human-readable peer ID (default: hostname)
--priority      Cache priority (default: 5)
--timeout       Connection timeout in seconds (default: 10)
--state-dir     Directory for persistent state
--private-key   Path to signing key
--scan-interval Seconds between store scans (default: 3600)
--no-filter     Disable package filtering
--no-verify     Disable hash verification
--filter-concurrency  Max concurrent filter requests (default: 10)
--verbose       Enable verbose logging
```

Version History
---------------

- **v0.0.3**: Iroh P2P integration, dashboard, peer tracking, stats persistence
- **v0.0.2**: IPFS mode, filtering, verification
- **v0.0.1**: Initial release with LAN mode
