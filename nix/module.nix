{ config, lib, pkgs, ... }:
let
  cfg = config.services.nnlan;
  unit = name: lib.replaceStrings
    [ "/usr/local/bin/nnlan" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ]
    [ "${cfg.package}/bin/nnlan" (lib.makeBinPath [ pkgs.iproute2 pkgs.nftables ]) ]
    (builtins.readFile (../packaging/systemd + "/${name}.service"));
in {
  options.services.nnlan = {
    enable = lib.mkEnableOption "nnlan with persistent early-boot guards";
    package = lib.mkOption { type = lib.types.package; };
    networkServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "systemd-networkd" ];
      example = [ "NetworkManager" ];
      description = "All physical network configuration services (without .service); each requires successful guard installation.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.networkServices != [ ];
        message = "nnlan early protection requires an explicit network service dependency";
      }
      {
        assertion = !config.systemd.network.enable || lib.elem "systemd-networkd" cfg.networkServices;
        message = "Enabled systemd-networkd must depend on nnlan-guard";
      }
      {
        assertion = !config.networking.networkmanager.enable || lib.elem "NetworkManager" cfg.networkServices;
        message = "Enabled NetworkManager must depend on nnlan-guard";
      }
      {
        assertion = !config.networking.dhcpcd.enable || lib.elem "dhcpcd" cfg.networkServices;
        message = "Enabled dhcpcd must depend on nnlan-guard";
      }
    ];
    environment.systemPackages = [ cfg.package ];
    systemd.units = lib.genAttrs [ "nnlan-guard.service" "nnlan.service" ] (name: {
      text = unit (lib.removeSuffix ".service" name);
      wantedBy = [ "multi-user.target" ];
    });
    systemd.services = lib.genAttrs cfg.networkServices (_: {
      requires = [ "nnlan-guard.service" ];
      after = [ "nnlan-guard.service" ];
    });
    # Identity/configuration must be provisioned BEFORE enabling, never generated
    # in the world-readable Nix store. Missing configuration fails closed.
    systemd.tmpfiles.rules = [ "d /var/lib/nnlan 0700 root root -" ];
  };
}
