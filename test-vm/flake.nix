{
  description = "Lightweight NixOS VM for Peerix WAN testing";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    peerix.url = "path:..";
  };

  outputs = { self, nixpkgs, peerix, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.test-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          peerix.nixosModules.peerix
          "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"

          ({ config, pkgs, lib, ... }: {
            # QEMU VM settings
            virtualisation = {
              memorySize = 1024;
              cores = 2;
              graphics = false;
              qemu.options = [ "-enable-kvm" ];
            };

            # Use port 12306 so tracker distinguishes VM from host (both appear as 127.0.0.1)
            services.peerix = {
              enable = true;
              port = 12306;
              mode = "wan";
              trackerUrl = "http://10.0.2.2:12305";
              noVerify = true;
              noFilter = true;
            };

            # Networking
            networking = {
              hostName = "peerix-test-vm";
              firewall.allowedTCPPorts = [ 12306 22 ];
              firewall.allowedUDPPorts = [ 12306 ];
            };

            # SSH for debugging
            services.openssh = {
              enable = true;
              settings.PermitRootLogin = "yes";
            };

            # Auto-login on console
            services.getty.autologinUser = "root";
            users.users.root.initialPassword = "test";

            # Trust peerix signing key
            nix.settings.trusted-public-keys = [
              "peerix-test:/xOCW3cMoMNdceDNDLP0xuBCeIoXirg9piXhi1yrZxg="
            ];

            # Debugging tools
            environment.systemPackages = with pkgs; [ curl htop ];

            system.stateVersion = "24.11";
          })
        ];
      };
    };
}
