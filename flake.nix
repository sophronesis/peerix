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

      # Iroh P2P library (binary wheel from PyPI)
      iroh = python.pkgs.buildPythonPackage rec {
        pname = "iroh";
        version = "0.35.0";
        format = "wheel";

        src = pkgs.fetchurl {
          url = "https://files.pythonhosted.org/packages/a6/01/afba5b09b5c7dbde2beee05a4e73656de4e3469f930524c15f17b96590f9/iroh-0.35.0-py3-none-manylinux_2_28_x86_64.whl";
          sha256 = "0im8rilciffg4bznm7pqrnam057a77rnjwfrij2g5bzidih7nrcl";
        };

        # Binary wheel, no build deps needed
        pythonImportsCheck = [ "iroh" ];
      };

      # Core packages for peerix (lan/ipfs modes)
      corePackages = with python.pkgs; [
        trio
        httpx
        hypercorn
        starlette
        psutil
      ];

      # Iroh mode packages
      irohPackages = with python.pkgs; [
        iroh
        uvicorn
      ];

    in {
      packages = rec {
        # Python environment with all dependencies (for running with -m)
        peerix-python = python.withPackages (ps: corePackages);

        peerix-unwrapped = python.pkgs.buildPythonApplication {
          pname = "peerix";
          version = builtins.replaceStrings [ " " "\n" ] [ "" "" ] (builtins.readFile ./VERSION);
          src = ./.;
          pyproject = true;

          doCheck = false;

          build-system = [ python.pkgs.setuptools ];

          dependencies = corePackages ++ irohPackages;

          propagatedBuildInputs = with pkgs; [
            nix
            nix-serve
          ];

          meta = {
            description = "Peer-to-peer Nix binary cache";
            longDescription = ''
              Peerix enables sharing Nix store paths between machines.

              Modes:
              - ipfs: IPFS-based P2P with content-addressed storage (default)
              - lan: UDP broadcast for local network discovery
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
            (pkgs.writeShellScriptBin "peerix-iroh" ''
              PATH=${pkgs.nix}/bin:${pkgs.nix-serve}:$PATH
              exec ${peerix-unwrapped}/bin/peerix-iroh "$@"
            '')
          ];
        };

        default = peerix;
      };

      defaultPackage = self.packages.${system}.peerix;

      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          nix-serve
          niv
          (python.withPackages (ps: corePackages ++ irohPackages ++ (with ps; [
            # Dev dependencies
            pytest
            pytest-asyncio
            black
            mypy
          ])))
        ];

        shellHook = ''
          echo "Peerix development shell"
          echo ""
          echo "Run peerix: python -m peerix --mode ipfs"
          echo "Run iroh mode: python -m peerix.iroh_app --tracker http://sophronesis.dev:12305"
          echo ""
        '';
      };

      defaultApp = { type = "app"; program = "${self.packages.${system}.peerix}/bin/peerix"; };
    });
}
