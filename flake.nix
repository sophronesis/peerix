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

      # Core packages for peerix (lan/ipfs modes)
      corePackages = with python.pkgs; [
        trio
        httpx
        hypercorn
        starlette
        psutil
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

          dependencies = corePackages;

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
          ];
        };

        default = peerix;
      };

      defaultPackage = self.packages.${system}.peerix;

      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          nix-serve
          niv
          uv
          (python.withPackages (ps: corePackages ++ (with ps; [
            # Dev dependencies
            pytest
            pytest-asyncio
            black
            mypy
            pip
          ])))
        ];

        shellHook = ''
          # Create venv if it doesn't exist
          if [ ! -d .venv ]; then
            echo "Creating virtual environment..."
            python -m venv .venv
          fi
          source .venv/bin/activate

          # Install iroh if not present
          if ! python -c "import iroh" 2>/dev/null; then
            echo "Installing iroh..."
            uv pip install iroh
          fi

          echo "Peerix development shell (with iroh)"
          echo ""
          echo "Run peerix: python -m peerix --mode ipfs"
          echo ""
        '';
      };

      defaultApp = { type = "app"; program = "${self.packages.${system}.peerix}/bin/peerix"; };
    });
}
