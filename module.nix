{ lib, config, pkgs, ... }:
let
  cfg = config.services.peerix;
  tcfg = cfg.tracker;
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
        default = (import ./default.nix).default or pkgs.peerix;
        defaultText = literalExpression "pkgs.peerix";
        description = "The package to use for peerix";
      };

      mode = lib.mkOption {
        type = types.enum [ "lan" "wan" "both" ];
        default = "lan";
        description = ''
          Discovery mode: lan (UDP broadcast), wan (tracker-based), or both.
        '';
      };

      trackerUrl = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          URL of the peerix tracker server. Required for wan and both modes.
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

      tracker = {
        enable = lib.mkEnableOption "peerix tracker";

        port = lib.mkOption {
          type = types.int;
          default = 12305;
          description = "Port for the tracker server.";
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

          PrivateMounts = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateIPC = true;
          PrivateUsers = true;

          SystemCallFilters = [
            "@aio"
            "@basic-io"
            "@file-system"
            "@io-event"
            "@process"
            "@network-io"
            "@timer"
            "@signal"
            "@alarm"
          ];
          SystemCallErrorNumber = "EPERM";

          ProtectSystem = "full";
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
        in ''
          exec ${cfg.package}/bin/peerix \
            ${modeArgs} \
            ${trackerArgs} \
            ${verifyArgs} \
            ${upstreamArgs} \
            ${filterArgs} \
            ${defaultFilterArgs} \
            ${patternArgs} \
            ${peerIdArgs}
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
        allowedTCPPorts = [ 12304 ];
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
        script = ''
          exec ${cfg.package}/bin/peerix-tracker \
            --port ${toString tcfg.port} \
            --db-path ${tcfg.dbPath}
        '';
      };

      networking.firewall = lib.mkIf (tcfg.openFirewall) {
        allowedTCPPorts = [ tcfg.port ];
      };
    })
  ];
}
