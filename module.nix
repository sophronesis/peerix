{ lib, config, pkgs, ... }:
let
  cfg = config.services.peerix;
  tcfg = config.services.peerix-tracker;
in
{
  options = with lib; {
    services.peerix = {
      enable = lib.mkEnableOption "peerix";

      openFirewall = lib.mkOption {
        type = types.bool;
        default = true;
        description = ''
          Defines whether or not firewall ports should be opened for it.
        '';
      };

      privateKeyFile = lib.mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          File containing the private key to sign the derivations with.
        '';
      };

      publicKeyFile = lib.mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          File containing the public key to sign the derivations with.
        '';
      };

      publicKey = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          The public key to sign the derivations with.
        '';
      };

      user = lib.mkOption {
        type = with types; oneOf [ str int ];
        default = "nobody";
        description = ''
          The user the service will use.
        '';
      };

      group = lib.mkOption {
        type = with types; oneOf [ str int ];
        default = "nobody";
        description = ''
          The user the service will use.
        '';
      };

      globalCacheTTL = lib.mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          How long should nix store narinfo files.

          If not defined, the module will not reconfigure the entry.
          If it is defined, this will define how many seconds a cache entry will
          be stored.

          By default not given, as it affects the UX of the nix installation.
        '';
      };

      package = mkOption {
        type = types.package;
        default = pkgs.peerix-full;
        defaultText = literalExpression "pkgs.peerix-full";
        description = ''
          The package to use for peerix.
          Defaults to peerix-full which supports all modes including libp2p.
          Use pkgs.peerix for a smaller package without libp2p support.
        '';
      };

      mode = lib.mkOption {
        type = types.enum [ "lan" "wan" "both" "libp2p" "hybrid" "ipfs" ];
        default = "ipfs";
        description = ''
          Discovery mode:
          - ipfs: IPFS-based P2P (requires services.kubo.enable) [default]
          - libp2p: P2P discovery with NAT traversal (DHT, mDNS, hole punching)
          - lan: UDP broadcast for local network discovery
          - wan: HTTP tracker-based discovery
          - both: lan + wan combined
          - hybrid: libp2p + tracker for maximum compatibility
        '';
      };

      trackerUrl = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          URL of the peerix tracker server. Required for wan, both, and hybrid modes.
        '';
      };

      upstreamCache = lib.mkOption {
        type = types.str;
        default = "https://cache.nixos.org";
        description = ''
          Upstream cache URL for hash verification.
        '';
      };

      filterPatterns = lib.mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Additional fnmatch patterns to exclude from WAN sharing.
        '';
      };

      noFilter = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Disable heuristic filtering of system/sensitive derivations entirely.
        '';
      };

      noDefaultFilters = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Keep filtering enabled but skip built-in default patterns.
        '';
      };

      noVerify = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Disable hash verification against upstream cache.
        '';
      };

      peerId = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Unique peer ID. Auto-generated if null.
        '';
      };

      # LibP2P options
      bootstrapUrl = lib.mkOption {
        type = types.nullOr types.str;
        default = "https://sophronesis.dev/peerix/bootstrap";
        example = "https://my-server.com/peerix/bootstrap";
        description = ''
          URL to fetch bootstrap peer multiaddr dynamically.
          The endpoint should return JSON with "multiaddrs" array.
          Used when bootstrapPeers is empty. Set to null to disable.
        '';
      };

      bootstrapPeers = lib.mkOption {
        type = types.listOf types.str;
        default = [];
        example = [ "/ip4/1.2.3.4/tcp/13304/p2p/QmPeerID" ];
        description = ''
          Static LibP2P bootstrap peer multiaddrs for DHT initialization.
          If empty and bootstrapUrl is set, peers are fetched dynamically.
        '';
      };

      relayServers = lib.mkOption {
        type = types.listOf types.str;
        default = [];
        example = [ "/ip4/1.2.3.4/tcp/13304/p2p/QmRelayID" ];
        description = ''
          LibP2P relay server multiaddrs for NAT traversal fallback.
          Used when direct connections fail due to NAT.
        '';
      };

      networkId = lib.mkOption {
        type = types.str;
        default = "default";
        example = "my-private-network";
        description = ''
          Network identifier for DHT peer discovery.
          Peers with the same network ID will discover each other.
        '';
      };

      listenAddrs = lib.mkOption {
        type = types.listOf types.str;
        default = [];
        example = [ "/ip4/0.0.0.0/tcp/13304" ];
        description = ''
          LibP2P listen multiaddrs. If empty, defaults to TCP on port+1000.
          Note: py-libp2p 0.6.0 only supports TCP, not QUIC.
        '';
      };

      identityFile = lib.mkOption {
        type = types.str;
        default = "/var/lib/peerix/identity.key";
        description = ''
          Path to the persistent identity key file.
          This keeps the peer ID stable across restarts.
          The file contains a 32-byte ed25519 seed.
        '';
      };

      enableIpfsCompat = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable IPFS compatibility layer.
          Announces NARs to IPFS DHT for discoverability by IPFS clients.
        '';
      };

      # IPFS scan options
      scanInterval = lib.mkOption {
        type = types.int;
        default = 3600;
        description = ''
          Interval in seconds for periodic nix store scanning.
          Scans all store paths (after filtering), publishes to IPFS,
          and syncs CID mappings to tracker.
          Set to 0 to disable periodic scanning.
          Default: 3600 (1 hour).
        '';
      };
    };

    # Tracker service (separate top-level for clarity)
    services.peerix-tracker = {
      enable = lib.mkEnableOption "peerix tracker server for P2P peer discovery";

      port = lib.mkOption {
        type = types.int;
        default = 12305;
        description = "Port for the tracker HTTP server.";
      };

      dbPath = lib.mkOption {
        type = types.str;
        default = "/var/lib/peerix-tracker/tracker.db";
        description = "Path to the tracker SQLite database.";
      };

      openFirewall = lib.mkOption {
        type = types.bool;
        default = true;
        description = "Whether to open the firewall for the tracker port.";
      };

      package = lib.mkOption {
        type = types.package;
        default = pkgs.peerix-full;
        defaultText = lib.literalExpression "pkgs.peerix-full";
        description = "The peerix package to use for the tracker.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.enable) {
      systemd.services.peerix = {
        enable = true;
        description = "Local p2p nix caching daemon";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "simple";

          User = cfg.user;
          Group = cfg.group;

          # State directory for persistent identity key
          StateDirectory = "peerix";
          StateDirectoryMode = "0700";

          PrivateMounts = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateIPC = true;
          # PrivateUsers breaks Python wrapper access to nix store

          # SystemCallFilter disabled - trio/asyncio need various syscalls
          # that are hard to enumerate. Other protections still apply.

          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictNamespaces = "";

          NoNewPrivileges = true;
          ReadOnlyPaths = lib.mkMerge [
            ([
              "/nix/var"
              "/nix/store"
            ])

            (lib.mkIf (cfg.privateKeyFile != null) [
              cfg.privateKeyFile
            ])
          ];
          ReadWritePaths = [ "/var/lib/peerix" ];
          ExecPaths = [
            "/nix/store"
          ];
          Environment = lib.mkIf (cfg.privateKeyFile != null) [
            "NIX_SECRET_KEY_FILE=${cfg.privateKeyFile}"
          ];
        };
        script = let
          modeArgs = "--mode ${cfg.mode}";
          trackerArgs = lib.optionalString (cfg.trackerUrl != null) "--tracker-url ${cfg.trackerUrl}";
          verifyArgs = lib.optionalString cfg.noVerify "--no-verify";
          upstreamArgs = lib.optionalString (cfg.upstreamCache != "https://cache.nixos.org")
            "--upstream-cache ${cfg.upstreamCache}";
          filterArgs = lib.optionalString cfg.noFilter "--no-filter";
          defaultFilterArgs = lib.optionalString cfg.noDefaultFilters "--no-default-filters";
          patternArgs = lib.optionalString (cfg.filterPatterns != [])
            "--filter-patterns ${lib.concatStringsSep " " cfg.filterPatterns}";
          peerIdArgs = lib.optionalString (cfg.peerId != null) "--peer-id ${cfg.peerId}";
          # LibP2P args
          bootstrapUrlArgs = lib.optionalString (cfg.bootstrapUrl != null && cfg.bootstrapPeers == [])
            "--bootstrap-url ${cfg.bootstrapUrl}";
          bootstrapArgs = lib.optionalString (cfg.bootstrapPeers != [])
            "--bootstrap-peers ${lib.concatStringsSep " " cfg.bootstrapPeers}";
          relayArgs = lib.optionalString (cfg.relayServers != [])
            "--relay-servers ${lib.concatStringsSep " " cfg.relayServers}";
          networkIdArgs = "--network-id ${cfg.networkId}";
          listenAddrsArgs = lib.optionalString (cfg.listenAddrs != [])
            "--listen-addrs ${lib.concatStringsSep " " cfg.listenAddrs}";
          identityFileArgs = "--identity-file ${cfg.identityFile}";
          ipfsCompatArgs = lib.optionalString cfg.enableIpfsCompat "--enable-ipfs-compat";
          # IPFS scan args
          scanIntervalArgs = "--scan-interval ${toString cfg.scanInterval}";
          # Use Python directly with -m to avoid wrapper script access issues with PrivateUsers
          pythonEnv = pkgs.peerix-python;
          peerixPkg = pkgs.peerix-full-unwrapped;
        in ''
          export PATH="${pkgs.nix}/bin:${pkgs.nix-serve}/bin:$PATH"
          export PYTHONPATH="${peerixPkg}/lib/python3.13/site-packages:$PYTHONPATH"
          exec ${pythonEnv}/bin/python -m peerix \
            ${modeArgs} \
            ${trackerArgs} \
            ${verifyArgs} \
            ${upstreamArgs} \
            ${filterArgs} \
            ${defaultFilterArgs} \
            ${patternArgs} \
            ${peerIdArgs} \
            ${bootstrapUrlArgs} \
            ${bootstrapArgs} \
            ${relayArgs} \
            ${networkIdArgs} \
            ${listenAddrsArgs} \
            ${identityFileArgs} \
            ${ipfsCompatArgs} \
            ${scanIntervalArgs}
        '';
      };

      nix = {
        settings = {
          substituters = [
            "http://127.0.0.1:12304/"
          ];
          trusted-public-keys = [
            (lib.mkIf (cfg.publicKeyFile != null) (builtins.readFile cfg.publicKeyFile))
            (lib.mkIf (cfg.publicKey != null) cfg.publicKey)
          ];
        };
        extraOptions = lib.mkIf (cfg.globalCacheTTL != null) ''
          narinfo-cache-negative-ttl = ${toString cfg.globalCacheTTL}
          narinfo-cache-positive-ttl = ${toString cfg.globalCacheTTL}
        '';
      };

      networking.firewall = lib.mkIf (cfg.openFirewall) {
        # HTTP on 12304, libp2p on 13304 (port + 1000)
        allowedTCPPorts = [ 12304 13304 ];
        allowedUDPPorts = [ 12304 ];
      };
    })

    (lib.mkIf (tcfg.enable) {
      systemd.services.peerix-tracker = {
        enable = true;
        description = "Peerix tracker server for WAN peer discovery";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "simple";
          StateDirectory = "peerix-tracker";

          DynamicUser = true;

          PrivateDevices = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          NoNewPrivileges = true;

          ReadWritePaths = [ (builtins.dirOf tcfg.dbPath) ];
          ExecPaths = [ "/nix/store" ];
        };
        script = let
          pythonEnv = pkgs.peerix-python;
          peerixPkg = pkgs.peerix-full-unwrapped;
        in ''
          export PYTHONPATH="${peerixPkg}/lib/python3.13/site-packages:$PYTHONPATH"
          exec ${pythonEnv}/bin/python -c "
import sys
sys.argv = ['peerix-tracker', '--port', '${toString tcfg.port}', '--db-path', '${tcfg.dbPath}']
from peerix.tracker_main import run
run()
"
        '';
      };

      networking.firewall = lib.mkIf (tcfg.openFirewall) {
        allowedTCPPorts = [ tcfg.port ];
      };
    })
  ];
}
