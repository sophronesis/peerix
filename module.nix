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

      filterMode = lib.mkOption {
        type = types.enum [ "nixpkgs" "rules" ];
        default = "nixpkgs";
        description = ''
          Package filter mode:
          - nixpkgs: Only serve packages that exist in cache.nixos.org (default)
          - rules: Use heuristic pattern rules to filter system-specific packages
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

        provideDHTInterval = lib.mkOption {
          type = types.str;
          default = "22h";
          description = ''
            Interval for IPFS to announce pinned content to the DHT.
            Set to "0" to disable automatic DHT providing.
            Default "22h" provides content gradually without flooding.
          '';
        };

        enableQUIC = lib.mkOption {
          type = types.bool;
          default = true;
          description = ''
            Enable QUIC transport (UDP-based).
            Disable if your ISP throttles UDP traffic.
          '';
        };

        connMgr = {
          lowWater = lib.mkOption {
            type = types.int;
            default = 600;
            description = "Start pruning connections when above this number. IPFS default: 600.";
          };
          highWater = lib.mkOption {
            type = types.int;
            default = 900;
            description = "Hard connection limit. IPFS default: 900.";
          };
          gracePeriod = lib.mkOption {
            type = types.str;
            default = "20s";
            description = "Grace period before pruning new connections. IPFS default: 20s.";
          };
        };

        resourceMgr = {
          enabled = lib.mkOption {
            type = types.bool;
            default = true;
            description = "Enable libp2p Resource Manager.";
          };
          connsInbound = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "Max inbound connections. null = auto-scaled. Must be > connMgr.highWater.";
          };
          connsOutbound = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "Max outbound connections. null = auto-scaled.";
          };
          streamsInbound = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "Max inbound streams. null = auto-scaled.";
          };
          streamsOutbound = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "Max outbound streams. null = auto-scaled.";
          };
          memory = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "Max memory in bytes. null = auto-scaled.";
          };
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
            type = types.nullOr types.int;
            default = null;
            description = ''
              Maximum NEW outgoing TCP connections per second.
              null = no rate limiting on new connections.
            '';
          };

          connectionBurst = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = ''
              Burst allowance for new connections.
              Only used when connectionRate is set.
            '';
          };

          packetRate = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = ''
              Maximum packets per second for IPFS traffic (both TCP and UDP).
              At 1500 byte MTU, 1400 packets/sec ≈ 2 MiB/s.
              null = no bandwidth limiting.
            '';
          };

          maxConnections = lib.mkOption {
            type = types.nullOr types.int;
            default = null;
            description = ''
              Maximum concurrent outgoing connections to IPFS peers (port 4001).
              null = no concurrent connection limiting.
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
          filterModeArgs = "--filter-mode ${cfg.filterMode}";
        in ''
          export PATH="${pkgs.nix}/bin:${pkgs.nix-serve}/bin:$PATH"
          exec ${cfg.package}/bin/peerix \
            ${modeArgs} \
            ${trackerArgs} \
            ${scanIntervalArgs} \
            ${concurrencyArgs} \
            ${priorityArgs} \
            ${filterModeArgs}
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
          # Fail fast if peerix is down, fall back to other caches
          connect-timeout = 2;
          fallback = true;
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
          # DHT provide interval (how often IPFS announces pinned content)
          Provide.DHT.Interval = cfg.ipfs.provideDHTInterval;
          # Set API to listen on TCP for peerix access
          Addresses.API = "/ip4/127.0.0.1/tcp/5001";
          # CORS headers for API access
          API.HTTPHeaders."Access-Control-Allow-Origin" = [ "*" ];
          # Connection manager
          Swarm.ConnMgr = {
            Type = "basic";
            LowWater = cfg.ipfs.connMgr.lowWater;
            HighWater = cfg.ipfs.connMgr.highWater;
            GracePeriod = cfg.ipfs.connMgr.gracePeriod;
          };
          # Resource Manager
          Swarm.ResourceMgr.Enabled = cfg.ipfs.resourceMgr.enabled;
          # QUIC transport
          Swarm.Transports.Network.QUIC = cfg.ipfs.enableQUIC;
        };
      };

      # Ensure peerix starts after kubo
      systemd.services.peerix.after = [ "ipfs.service" ];
      systemd.services.peerix.wants = [ "ipfs.service" ];
    })

    # Resource Manager limits file (only if any limit is explicitly set)
    (lib.mkIf (cfg.enable && cfg.ipfs.enable && cfg.ipfs.configureKubo && (
      cfg.ipfs.resourceMgr.connsInbound != null ||
      cfg.ipfs.resourceMgr.connsOutbound != null ||
      cfg.ipfs.resourceMgr.streamsInbound != null ||
      cfg.ipfs.resourceMgr.streamsOutbound != null ||
      cfg.ipfs.resourceMgr.memory != null
    )) {
      environment.etc."ipfs-resource-limits.json" = {
        text = builtins.toJSON {
          System = lib.filterAttrs (n: v: v != null) {
            ConnsInbound = cfg.ipfs.resourceMgr.connsInbound;
            ConnsOutbound = cfg.ipfs.resourceMgr.connsOutbound;
            StreamsInbound = cfg.ipfs.resourceMgr.streamsInbound;
            StreamsOutbound = cfg.ipfs.resourceMgr.streamsOutbound;
            Memory = cfg.ipfs.resourceMgr.memory;
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
        rl = cfg.ipfs.rateLimit;
        connRate = toString rl.connectionRate;
        connBurst = toString (if rl.connectionBurst != null then rl.connectionBurst else rl.connectionRate);
        pktRate = toString rl.packetRate;
        maxConn = toString rl.maxConnections;

        connRateRules = lib.optionalString (rl.connectionRate != null) ''
          # Limit NEW outgoing connections
          iptables -A OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT
          iptables -A OUTPUT -p tcp --dport 4001 --syn -j DROP
        '';
        cleanupConnRateRules = lib.optionalString (rl.connectionRate != null) ''
          iptables -D OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT 2>/dev/null || true
          iptables -D OUTPUT -p tcp --dport 4001 --syn -j DROP 2>/dev/null || true
        '';

        bandwidthRules = lib.optionalString (rl.packetRate != null) ''
          # Limit outgoing IPFS bandwidth
          iptables -A OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP
          iptables -A OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP
          # Limit incoming IPFS bandwidth
          iptables -A INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP
          iptables -A INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP
        '';
        cleanupBandwidthRules = lib.optionalString (rl.packetRate != null) ''
          iptables -D OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP 2>/dev/null || true
          iptables -D INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP 2>/dev/null || true
          iptables -D INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP 2>/dev/null || true
        '';

        connlimitRules = lib.optionalString (rl.maxConnections != null) ''
          # Limit concurrent outgoing connections
          iptables -A OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP
          iptables -A OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP
        '';
        cleanupConnlimitRules = lib.optionalString (rl.maxConnections != null) ''
          iptables -D OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
        '';
      in ''
        # Clean up existing IPFS rate limit rules (peerix)
        ${cleanupConnRateRules}
        ${cleanupBandwidthRules}
        ${cleanupConnlimitRules}

        ${connRateRules}
        ${bandwidthRules}
        ${connlimitRules}
      '';

      networking.firewall.extraStopCommands = let
        rl = cfg.ipfs.rateLimit;
        connRate = toString rl.connectionRate;
        connBurst = toString (if rl.connectionBurst != null then rl.connectionBurst else rl.connectionRate);
        pktRate = toString rl.packetRate;
        maxConn = toString rl.maxConnections;

        connRateCleanup = lib.optionalString (rl.connectionRate != null) ''
          iptables -D OUTPUT -p tcp --dport 4001 --syn -m limit --limit ${connRate}/sec --limit-burst ${connBurst} -j ACCEPT 2>/dev/null || true
          iptables -D OUTPUT -p tcp --dport 4001 --syn -j DROP 2>/dev/null || true
        '';
        bandwidthCleanup = lib.optionalString (rl.packetRate != null) ''
          iptables -D OUTPUT -p tcp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --sport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode srcip --hashlimit-name ipfs_out_udp -j DROP 2>/dev/null || true
          iptables -D INPUT -p tcp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in -j DROP 2>/dev/null || true
          iptables -D INPUT -p udp --dport 4001 -m hashlimit --hashlimit-above ${pktRate}/sec --hashlimit-mode dstip --hashlimit-name ipfs_in_udp -j DROP 2>/dev/null || true
        '';
        connlimitCleanup = lib.optionalString (rl.maxConnections != null) ''
          iptables -D OUTPUT -p tcp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
          iptables -D OUTPUT -p udp --dport 4001 -m connlimit --connlimit-above ${maxConn} -j DROP 2>/dev/null || true
        '';
      in ''
        # Clean up IPFS rate limit rules on firewall stop (peerix)
        ${connRateCleanup}
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
