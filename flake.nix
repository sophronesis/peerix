{
  description = "Peer2Peer Nix-Binary-Cache";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }: {
    nixosModules.peerix = { pkgs, ... }: {
      nixpkgs.overlays = [ (import ./overlay.nix { inherit self; }) ];
      imports = [ ./module.nix ];
    };
    overlay = import ./overlay.nix { inherit self; };
  } // flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python3;

      # Import libp2p packages
      libp2pPkgs = import ./nix/libp2p.nix { inherit pkgs python; };

      # Core packages - required for basic functionality (lan/wan modes)
      corePackages = with python.pkgs; [
        trio
        httpx
        hypercorn
        starlette
        psutil
      ];

      # LibP2P packages - required for libp2p/hybrid modes
      libp2pPackages = [
        libp2pPkgs.libp2p
        libp2pPkgs.multiaddr
      ];

      allPackages = corePackages ++ libp2pPackages;

    in {
      packages = rec {
        # Python environment with all dependencies (for running with -m)
        peerix-python = python.withPackages (ps: allPackages);

        # Basic peerix without libp2p (smaller, fewer deps)
        peerix-unwrapped = python.pkgs.buildPythonApplication {
          pname = "peerix";
          version = builtins.replaceStrings [ " " "\n" ] [ "" "" ] (builtins.readFile ./VERSION);
          src = ./.;
          pyproject = true;

          doCheck = false;

          build-system = [ python.pkgs.setuptools ];

          dependencies = corePackages;

          propagatedBuildInputs = with pkgs; [
            nix
            nix-serve
          ];

          meta = {
            description = "Peer-to-peer Nix binary cache";
            longDescription = ''
              Peerix enables sharing Nix store paths between machines.
              This is the base package supporting lan/wan modes.
              For libp2p support, use peerix-full.
            '';
          };
        };

        # Full peerix with libp2p support
        peerix-full-unwrapped = python.pkgs.buildPythonApplication {
          pname = "peerix";
          version = builtins.replaceStrings [ " " "\n" ] [ "" "" ] (builtins.readFile ./VERSION);
          src = ./.;
          pyproject = true;

          doCheck = false;

          build-system = [ python.pkgs.setuptools ];

          dependencies = allPackages;

          propagatedBuildInputs = with pkgs; [
            nix
            nix-serve
          ];

          meta = {
            description = "Peer-to-peer Nix binary cache with NAT traversal";
            longDescription = ''
              Peerix enables sharing Nix store paths between machines.

              Modes:
              - lan: UDP broadcast for local network
              - wan: HTTP tracker-based discovery
              - libp2p: P2P with NAT traversal (DHT, mDNS, hole punching)
              - hybrid: libp2p + tracker combined
            '';
          };
        };

        peerix = pkgs.symlinkJoin {
          name = "peerix";
          paths = [
            (pkgs.writeShellScriptBin "peerix" ''
              PATH=${pkgs.nix}/bin:${pkgs.nix-serve}:$PATH
              exec ${peerix-unwrapped}/bin/peerix "$@"
            '')
            (pkgs.writeShellScriptBin "peerix-tracker" ''
              exec ${peerix-unwrapped}/bin/peerix-tracker "$@"
            '')
          ];
        };

        peerix-full = pkgs.symlinkJoin {
          name = "peerix-full";
          paths = [
            (pkgs.writeShellScriptBin "peerix" ''
              PATH=${pkgs.nix}/bin:${pkgs.nix-serve}:$PATH
              exec ${peerix-full-unwrapped}/bin/peerix "$@"
            '')
            (pkgs.writeShellScriptBin "peerix-tracker" ''
              exec ${peerix-full-unwrapped}/bin/peerix-tracker "$@"
            '')
          ];
        };
      };

      defaultPackage = self.packages.${system}.peerix-full;

      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          nix-serve
          niv
          (python.withPackages (ps: corePackages ++ libp2pPackages ++ (with ps; [
            # Dev dependencies
            pytest
            pytest-asyncio
            black
            mypy
          ])))
        ];

        shellHook = ''
          echo "Peerix development shell (with libp2p support)"
          echo ""
          echo "Run tests: pytest"
          echo "Run peerix: python -m peerix --mode libp2p"
          echo ""
        '';
      };

      defaultApp = { type = "app"; program = "${self.packages.${system}.peerix-full}/bin/peerix"; };
    });
}
