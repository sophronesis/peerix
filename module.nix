{ lib, config, pkgs, ... }:
let
  cfg = config.services.peerix;
  tcfg = config.services.peerix-tracker;
  # Auto-detect mode based on tracker URL:
  # - trackerUrl set → Iroh mode (P2P with NAT traversal via tracker)
  # - trackerUrl null → LAN mode (UDP broadcast, local network only)
  useIrohMode = cfg.trackerUrl != null;
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

      trackerUrl = lib.mkOption {
        type = types.nullOr types.str;
        default = "https://sophronesis.dev/peerix";
        description = ''
          URL of the peerix tracker server for peer discovery.
          If set: Uses Iroh mode (P2P with NAT traversal via tracker).
          If null: Uses LAN mode (UDP broadcast, local network only).
          Default: "https://sophronesis.dev/peerix" (Iroh mode).
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

      filterConcurrency = lib.mkOption {
        type = types.int;
        default = 10;
        description = ''
          Maximum concurrent HTTP requests when filtering hashes against cache.nixos.org.
          Lower values are gentler on your network but slower.
          Default: 10.
        '';
      };

      allowInsecureHttp = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Allow HTTP (non-TLS) connections to tracker and upstream cache.
          WARNING: This is insecure and should only be used for testing.
          By default, peerix requires HTTPS for all external connections.
        '';
      };

      scanInterval = lib.mkOption {
        type = types.int;
        default = 3600;
        description = ''
          Interval in seconds for periodic nix store scanning.
          Set to 0 to disable periodic scanning.
          Default: 3600 (1 hour).
        '';
      };

      noFilter = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Disable package filtering entirely.
          By default, only packages that exist in cache.nixos.org are served.
        '';
      };

      noVerify = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Disable hash verification against upstream cache.
          WARNING: This reduces security - only use if you trust all peers.
        '';
      };

      upstreamCache = lib.mkOption {
        type = types.str;
        default = "https://cache.nixos.org";
        description = ''
          Upstream cache URL for hash verification and filtering.
          Default: https://cache.nixos.org
        '';
      };

      timeout = lib.mkOption {
        type = types.float;
        default = 10.0;
        description = ''
          Connection timeout in seconds for peer connections.
          Default: 10.0
        '';
      };

      priority = lib.mkOption {
        type = types.int;
        default = 5;
        description = ''
          Cache priority for nix substituters.
          Lower number = higher priority.
          Default: 5 (higher priority than cache.nixos.org which is 10).
        '';
      };

      lanDiscovery = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable LAN peer discovery via UDP broadcast.
          This supplements Iroh mode by also checking local network peers.
          Useful for mixed environments where some peers are on the same LAN.
        '';
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
        description = "Local p2p nix caching daemon (${if useIrohMode then "Iroh" else "LAN"} mode)";
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
        script = if useIrohMode then ''
          # Iroh mode: P2P with NAT traversal via tracker
          export PATH="${pkgs.nix}/bin:${pkgs.nix-serve}/bin:$PATH"
          exec ${cfg.package}/bin/peerix-iroh \
            --port 12304 \
            --tracker ${cfg.trackerUrl} \
            --priority ${toString cfg.priority} \
            --timeout ${toString cfg.timeout} \
            --scan-interval ${toString cfg.scanInterval} \
            --filter-mode ${cfg.filterMode} \
            --filter-concurrency ${toString cfg.filterConcurrency} \
            --upstream-cache ${cfg.upstreamCache} \
            --state-dir /var/lib/peerix \
            ${lib.optionalString cfg.noFilter "--no-filter"} \
            ${lib.optionalString cfg.noVerify "--no-verify"} \
            ${lib.optionalString cfg.allowInsecureHttp "--allow-insecure-http"} \
            ${lib.optionalString cfg.lanDiscovery "--lan-discovery"}
        '' else ''
          # LAN mode: UDP broadcast, local network only
          export PATH="${pkgs.nix}/bin:${pkgs.nix-serve}/bin:$PATH"
          exec ${cfg.package}/bin/peerix \
            --mode lan \
            --port 12304 \
            --priority ${toString cfg.priority} \
            --timeout ${toString (builtins.floor (cfg.timeout * 1000))} \
            --scan-interval ${toString cfg.scanInterval} \
            --filter-mode ${cfg.filterMode}
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
