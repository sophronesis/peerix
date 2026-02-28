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
        default = pkgs.peerix;
        defaultText = literalExpression "pkgs.peerix";
        description = ''
          The package to use for peerix.
        '';
      };

      mode = lib.mkOption {
        type = types.enum [ "lan" "ipfs" ];
        default = "ipfs";
        description = ''
          Discovery mode:
          - ipfs: IPFS-based P2P (requires services.kubo.enable) [default]
          - lan: UDP broadcast for local network discovery
        '';
      };

      trackerUrl = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          URL of the peerix tracker server for CID registry (used in IPFS mode).
        '';
      };

      # IPFS scan options
      scanInterval = lib.mkOption {
        type = types.int;
        default = 3600;
        description = ''
          Interval in seconds for periodic nix store scanning.
          Scans all store paths, publishes to IPFS, and syncs CID mappings to tracker.
          Set to 0 to disable periodic scanning.
          Default: 3600 (1 hour).
        '';
      };

      ipfsConcurrency = lib.mkOption {
        type = types.int;
        default = 10;
        description = ''
          Number of parallel IPFS uploads during store scanning.
          Higher values speed up initial sync but use more resources.
          Default: 10.
        '';
      };

      # Cache options
      priority = lib.mkOption {
        type = types.int;
        default = 5;
        description = ''
          Cache priority for nix substituters.
          Lower number = higher priority.
          Default: 5 (higher priority than cache.nixos.org which is 10).
        '';
      };

      # IPFS module options
      ipfs = {
        enable = lib.mkOption {
          type = types.bool;
          default = true;
          description = ''
            Enable IPFS integration for peerix.
            When enabled, peerix will use IPFS mode by default and
            configure the local IPFS daemon (kubo) with recommended settings.
            Set to false to use peerix without IPFS features.
          '';
        };

        configureKubo = lib.mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether to configure kubo (IPFS daemon) with recommended settings.
            Enables services.kubo and sets experimental features.
            Set to false if you want to manage kubo configuration yourself.
          '';
        };

        routingType = lib.mkOption {
          type = types.enum [ "dhtclient" "dht" "dhtserver" "none" "autoclient" ];
          default = "dhtclient";
          description = ''
            IPFS routing type. Options:
            - "dhtclient": Client-only DHT (default, lightweight, recommended)
            - "dht": Full DHT participation (can cause network timeouts on startup)
            - "dhtserver": DHT server mode (heavy, can cause network timeouts)
            - "autoclient": Automatically switch between client/server
            - "none": No routing (isolated node)
          '';
        };

        acceleratedDHTClient = lib.mkOption {
          type = types.bool;
          default = false;
          description = ''
            Enable accelerated DHT client for faster lookups.
            Uses parallel queries and aggressive caching.
            Can increase bandwidth/connections at startup.
            Only effective when routingType is "dhtclient".
          '';
        };

        rateLimit = {
          enable = lib.mkOption {
            type = types.bool;
            default = false;
            description = ''
              Enable iptables-based rate limiting for IPFS connections.
              This prevents IPFS from overwhelming your network during bursts of activity.
              Applies limits to port 4001 (IPFS swarm port).
            '';
          };

          connectionRate = lib.mkOption {
            type = types.int;
            default = 10;
            description = ''
              Maximum NEW outgoing TCP connections per second.
              Prevents connection flood during startup or heavy activity.
              Default: 10/sec.
            '';
          };

          connectionBurst = lib.mkOption {
            type = types.int;
            default = 20;
            description = ''
              Burst allowance for new connections.
              Allows short bursts above connectionRate.
              Default: 20.
            '';
          };

          packetRate = lib.mkOption {
            type = types.int;
            default = 1400;
            description = ''
              Maximum packets per second for IPFS traffic (both TCP and UDP).
              At 1500 byte MTU, 1400 packets/sec ≈ 2 MiB/s.
              Set to 0 to disable bandwidth limiting (only apply connection limiting).
              Default: 1400 (~2 MiB/s).
            '';
          };

          maxConnections = lib.mkOption {
            type = types.int;
            default = 100;
            description = ''
              Maximum concurrent outgoing connections to IPFS peers (port 4001).
              Uses connlimit to cap total active connections.
              Set to 0 to disable concurrent connection limiting.
              Default: 100.
            '';
          };
        };
      };
    };

    # Tracker service (separate top-level for clarity)
    services.peerix-tracker = {
      enable = lib.mkEnableOption "peerix tracker server for CID registry";

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
        default = pkgs.peerix;
        defaultText = lib.literalExpression "pkgs.peerix";
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

          # State directory for persistent data
          StateDirectory = "peerix";
          StateDirectoryMode = "0700";

          PrivateMounts = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateIPC = true;

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

          # Support reload to trigger manual cache rescan
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        };
        # Enable reload support
        reloadIfChanged = true;
        script = let
          modeArgs = "--mode ${cfg.mode}";
          trackerArgs = lib.optionalString (cfg.trackerUrl != null) "--tracker-url ${cfg.trackerUrl}";
          scanIntervalArgs = "--scan-interval ${toString cfg.scanInterval}";
          concurrencyArgs = "--ipfs-concurrency ${toString cfg.ipfsConcurrency}";
          priorityArgs = "--priority ${toString cfg.priority}";
        in ''
          export PATH="${pkgs.nix}/bin:${pkgs.nix-serve}/bin:$PATH"
          exec ${cfg.package}/bin/peerix \
            ${modeArgs} \
            ${trackerArgs} \
            ${scanIntervalArgs} \
            ${concurrencyArgs} \
            ${priorityArgs}
        '';
      };

      # Path unit to watch for system rebuilds and trigger peerix rescan
      systemd.paths.peerix-rescan = {
        description = "Watch for NixOS rebuild to trigger peerix cache rescan";
        wantedBy = [ "multi-user.target" ];
        pathConfig = {
          PathChanged = "/run/current-system";
          Unit = "peerix-rescan.service";
        };
      };

      systemd.services.peerix-rescan = {
        description = "Trigger peerix cache rescan after NixOS rebuild";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.systemd}/bin/systemctl reload peerix.service";
        };
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
        allowedTCPPorts = [ 12304 ];
        allowedUDPPorts = [ 12304 ];
      };
    })

    # IPFS/Kubo configuration when ipfs.configureKubo is enabled
    (lib.mkIf (cfg.enable && cfg.ipfs.enable && cfg.ipfs.configureKubo) {
      services.kubo = {
        enable = true;
        settings = {
          # Routing type (dhtclient is lightweight, dht/dhtserver can timeout on start)
          Routing.Type = cfg.ipfs.routingType;
          # Accelerated DHT client (parallel queries, more bandwidth on startup)
          Routing.AcceleratedDHTClient = cfg.ipfs.acceleratedDHTClient;
          # Set API to listen on TCP for peerix access
          Addresses.API = "/ip4/127.0.0.1/tcp/5001";
          # CORS headers for API access
          API.HTTPHeaders."Access-Control-Allow-Origin" = [ "*" ];
          # Connection manager - limit connections to prevent network saturation
          # Note: must be <= ResourceMgr limits
          Swarm.ConnMgr = {
            Type = "basic";
            LowWater = 3;    # Start pruning at this many connections
            HighWater = 5;   # Hard limit (must be <= ResourceMgr.ConnsInbound)
            GracePeriod = "30s";
          };
          # Resource Manager - enable it (limits are in separate file for Kubo 0.19+)
          Swarm.ResourceMgr.Enabled = true;
          # Disable QUIC to reduce UDP flood (Telekom handles TCP better)
          Swarm.Transports.Network.QUIC = false;
        };
      };

      # Ensure peerix starts after kubo
      systemd.services.peerix.after = [ "ipfs.service" ];
      systemd.services.peerix.wants = [ "ipfs.service" ];

      # Resource Manager limits file (Kubo 0.19+ uses separate file instead of config)
      # Note: ConnsInbound must be > ConnMgr.HighWater
      environment.etc."ipfs-resource-limits.json" = {
        text = builtins.toJSON {
          System = {
            ConnsInbound = 10;
            ConnsOutbound = 10;
            StreamsInbound = 20;
            StreamsOutbound = 20;
            Memory = 536870912;  # 512MB
          };
        };
        mode = "0644";
      };

      # Copy limits file to IPFS data dir before service starts
      systemd.services.ipfs.preStart = lib.mkAfter ''
        cp /etc/ipfs-resource-limits.json /var/lib/ipfs/libp2p-resource-limit-overrides.json || true
      '';
    })

    # IPFS rate limiting via iptables
    (lib.mkIf (cfg.enable && cfg.ipfs.enable && cfg.ipfs.rateLimit.enable) {
      networking.firewall.extraCommands = let
        connRate = toString cfg.ipfs.rateLimit.connectionRate;
        connBurst = toString cfg.ipfs.rateLimit.connectionBurst;
        pktRate = toString cfg.ipfs.rateLimit.packetRate;
        maxConn = toString cfg.ipfs.rateLimit.maxConnections;
        bandwidthRules = lib.optionalString (cfg.ipfs.rateLimit.packetRate > 0) ''
          # Limit outgoing IPFS bandwidth
          iptables -A OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP
          iptables -A OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP

          # Limit incoming IPFS bandwidth
          iptables -A INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP
          iptables -A INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP
        '';
        cleanupBandwidthRules = lib.optionalString (cfg.ipfs.rateLimit.packetRate > 0) ''
          iptables -D OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP 2>/dev/null || true
          iptables -D INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP 2>/dev/null || true
          iptables -D INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP 2>/dev/null || true
        '';
        connlimitRules = lib.optionalString (cfg.ipfs.rateLimit.maxConnections > 0) ''
          # Limit concurrent outgoing connections
          iptables -A OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP
          iptables -A OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP
        '';
        cleanupConnlimitRules = lib.optionalString (cfg.ipfs.rateLimit.maxConnections > 0) ''
          iptables -D OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
        '';
      in ''
        # Clean up existing IPFS rate limit rules (peerix)
        iptables -D OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport 4001 --syn -j DROP 2>/dev/null || true
        ${cleanupBandwidthRules}
        ${cleanupConnlimitRules}

        # Limit NEW outgoing connections (prevents startup flood)
        # --dport 4001 for outgoing connections TO IPFS peers
        iptables -A OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 4001 --syn -j DROP

        ${bandwidthRules}
        ${connlimitRules}
      '';

      networking.firewall.extraStopCommands = let
        connRate = toString cfg.ipfs.rateLimit.connectionRate;
        connBurst = toString cfg.ipfs.rateLimit.connectionBurst;
        pktRate = toString cfg.ipfs.rateLimit.packetRate;
        maxConn = toString cfg.ipfs.rateLimit.maxConnections;
        bandwidthCleanup = lib.optionalString (cfg.ipfs.rateLimit.packetRate > 0) ''
          iptables -D OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP 2>/dev/null || true
          iptables -D INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP 2>/dev/null || true
          iptables -D INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP 2>/dev/null || true
        '';
        connlimitCleanup = lib.optionalString (cfg.ipfs.rateLimit.maxConnections > 0) ''
          iptables -D OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
        '';
      in ''
        # Clean up IPFS rate limit rules on firewall stop (peerix)
        iptables -D OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport 4001 --syn -j DROP 2>/dev/null || true
        ${bandwidthCleanup}
        ${connlimitCleanup}
      '';
    })

    (lib.mkIf (tcfg.enable) {
      systemd.services.peerix-tracker = {
        enable = true;
        description = "Peerix tracker server for CID registry";
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
        script = ''
          exec ${tcfg.package}/bin/peerix-tracker --port ${toString tcfg.port} --db-path ${tcfg.dbPath}
        '';
      };

      networking.firewall = lib.mkIf (tcfg.openFirewall) {
        allowedTCPPorts = [ tcfg.port ];
      };
    })
  ];
}
