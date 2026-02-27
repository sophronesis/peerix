Peerix
======

Peer-to-peer binary cache for Nix. Share derivations between machines via IPFS or local network broadcast.

Quick Start
-----------

### IPFS Mode (default)

Uses local IPFS daemon for content-addressed NAR distribution:

```nix
{
  inputs.peerix.url = "github:sophronesis/peerix";

  outputs = { self, nixpkgs, peerix, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        peerix.nixosModules.peerix
        {
          services.kubo.enable = true;  # IPFS daemon
          services.peerix = {
            enable = true;
            trackerUrl = "http://tracker-host:12305";
          };
        }
      ];
    };
  };
}
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

Set `privateKeyFile` on serving nodes and `publicKey` on consuming nodes.

Dependencies
------------

- Python 3.12+: `trio`, `hypercorn`, `starlette`, `httpx`, `pynacl`
- IPFS mode: local IPFS daemon (kubo)
- System: `nix`, `nix-serve`
