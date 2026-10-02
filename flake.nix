{
  description = "nnlan Rust development and Linux network testing environment";

  # Matches rust-toolchain.toml; flake.lock pins the source and content hash.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/8ce4ef6cb6f871616146b9fe26d2a5ae594e94fe";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      toolchain = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain;
    in
    {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.callPackage ./nix/package.nix { }; });
      nixosModules.default = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.nnlan.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      };
      checks = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { boot = pkgs.callPackage ./tests/nixos/boot.nix {
          package = self.packages.${system}.default;
          module = self.nixosModules.default;
        };
        dhcp = pkgs.callPackage ./tests/nixos/dhcp.nix {
          package = self.packages.${system}.default;
          module = self.nixosModules.default;
        }; });
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = assert pkgs.lib.assertMsg
            (builtins.all (p: p.version == toolchain.channel)
              [ pkgs.rustc pkgs.cargo pkgs.rustfmt pkgs.clippy ])
            "Update the nixpkgs pin and rust-toolchain.toml together";
            pkgs.mkShell {
              name = "nnlan-dev";
              packages = with pkgs; [
                rustc cargo rustfmt clippy rust-analyzer
                pkg-config gnumake git
                python3 jq curl
                iproute2 nftables iptables iputils conntrack-tools
                util-linux procps iperf3 tcpdump perf
                wireguard-tools wireguard-go ethtool
              ];
              RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
              RUST_BACKTRACE = "1";
              # Entering the shell never changes routes, firewall rules or privileges.
            };
        });
    };
}
