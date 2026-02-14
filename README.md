Peerix
======

Peerix is a peer-to-peer binary cache for nix derivations.
Every participating node can pull derivations from each other instances' respective nix-stores.

How does it work?
-----------------

Peerix implements a nix binary cache. When the nix package manager queries peerix, peerix
will ask the network if any other peerix instances hold the package, and if some other instance
holds the derivation, it will download the derivation from that instance.

Peerix supports two discovery modes:

- **LAN** (default): UDP broadcast on the local network for zero-config peer discovery.
- **WAN**: Tracker-based discovery for peers across different networks (NAT, VPN, cloud, etc).
- **Both**: LAN and WAN simultaneously.

Installation
------------

### Flake

Add peerix as a flake input:

```nix
{
  inputs.peerix.url = "github:sophronesis/peerix";

  outputs = { self, nixpkgs, peerix, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        peerix.nixosModules.peerix
        {
          services.peerix = {
            enable = true;
            # Optional: sign derivations so peers can verify authenticity
            privateKeyFile = "/path/to/cache-priv-key.pem";
            publicKey = "myhost:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
          };
        }
      ];
    };
  };
}
```

### Signing

To sign the peerix cache, generate a key pair:

```bash
nix-store --generate-binary-cache-key myhost /path/to/cache-priv-key.pem /path/to/cache-pub-key.pem
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
| `services.peerix.mode`           | Discovery mode: `"lan"`, `"wan"`, or `"both"`.                                               | `"lan"`   |
| `services.peerix.user`           | User to run the peerix service under.                                                        | `"nobody"`|
| `services.peerix.group`          | Group to run the peerix service under.                                                       | `"nobody"`|
| `services.peerix.privateKeyFile` | Path to the private key file for signing derivations.                                        | `null`    |
| `services.peerix.publicKeyFile`  | Path to the public key file for verifying signatures.                                        | `null`    |
| `services.peerix.publicKey`      | Public key string for verifying signatures.                                                  | `null`    |
| `services.peerix.globalCacheTTL` | How long (seconds) nix should cache narinfo entries.                                         | `null`    |
| `services.peerix.package`        | The peerix package to use.                                                                   | `pkgs.peerix` |

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

### Tracker Service

| Option                               | Description                                                                              | Default   |
|---------------------------------------|------------------------------------------------------------------------------------------|-----------|
| `services.peerix.tracker.enable`      | Enable the peerix tracker server.                                                        | `false`   |
| `services.peerix.tracker.port`        | Port for the tracker server.                                                             | `12305`   |
| `services.peerix.tracker.dbPath`      | Path to the tracker SQLite database.                                                     | `"/var/lib/peerix-tracker/tracker.db"` |
| `services.peerix.tracker.openFirewall`| Open the firewall for the tracker port.                                                  | `true`    |

WAN Mode
--------

WAN mode enables peer-to-peer sharing across different networks using a lightweight tracker server for peer discovery.

### Setup

1. Run a tracker on an accessible host:

```nix
services.peerix.tracker.enable = true;
```

2. Configure peers to use WAN mode:

```nix
services.peerix = {
  enable = true;
  mode = "wan";  # or "both" for LAN + WAN
  trackerUrl = "http://tracker-host:12305";
};
```

3. For peers behind NAT or port forwarding, use `announceAddr` to specify the reachable address:

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

Network Protocol
----------------

- **LAN**: UDP port 12304 (configurable) for broadcast-based peer discovery. Packet byte 0 is message type (0=request, 1=response), bytes 1-4 are request ID.
- **WAN**: Peers announce to the tracker via HTTP. The tracker maintains a peer registry and transfer history in SQLite.
- **HTTP**: Port 12304 (configurable) serves both local narinfo/NAR to peers and proxied remote content to the local nix daemon.

Dependencies
------------

- Python 3.12+: `aiohttp`, `uvloop`, `hypercorn`, `starlette`, `psutil`, `pynacl` (optional, for narinfo signing)
- System: `nix`, `nix-serve`
