{ pkgs, lib, package, module }:
let
  server = pkgs.writeText "boot-receiver.py" ''
    import json, selectors, socket
    sel = selectors.DefaultSelector()
    for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        for kind in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
            s = socket.socket(family, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((address, 8099))
            if kind == socket.SOCK_STREAM:
                s.listen()
            sel.register(s, selectors.EVENT_READ, kind)
    open("/run/receiver-ready", "w").close()
    with open("/run/requests.jsonl", "a", buffering=1) as log:
        while True:
            for key, _ in sel.select():
                if key.data == socket.SOCK_DGRAM:
                    data, peer = key.fileobj.recvfrom(4096)
                else:
                    connection, peer = key.fileobj.accept()
                    connection.close()
                log.write(json.dumps({"source": peer[0], "transport": key.data}) + "\n")
  '';
  probe = pkgs.writeText "boot-probe.py" ''
    import socket, time
    count = 0
    while True:
        for family, address in [(socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "fd10:b007::1")]:
            for kind in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
                with socket.socket(family, kind) as s:
                    s.settimeout(0.05)
                    try:
                        if kind == socket.SOCK_DGRAM:
                            s.sendto(b"boot-probe", (address, 8099))
                        else:
                            s.connect((address, 8099))
                    except OSError:
                        pass
                count += 1
        with open("/run/probe-count", "w") as f:
            f.write(str(count))
        time.sleep(0.05)
  '';
  base = { lib, ... }: {
    networking.useDHCP = false;
    networking.useNetworkd = true;
    networking.firewall.enable = false;
    systemd.network.wait-online.enable = false;
    virtualisation.vlans = [ 1 ];
    virtualisation.memorySize = 768;
    environment.systemPackages = [ pkgs.python3 pkgs.nftables pkgs.iproute2 ];
    # No initrd networking or other physical address configuring service.
    systemd.network.networks."10-test" = {
      matchConfig.Name = "eth1";
      networkConfig.IPv6AcceptRA = false;
      linkConfig.RequiredForOnline = false;
    };
    systemd.network.networks."99-eth0".networkConfig.DHCP = lib.mkForce "no";
  };
in pkgs.testers.runNixOSTest {
  name = "nnlan-early-guard";
  nodes = {
    internet = { ... }: {
      imports = [ base ];
      systemd.network.networks."10-test".address = [ "192.0.2.1/24" "fd10:b007::1/64" ];
      systemd.services.receiver = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${server}";
        serviceConfig.Restart = "on-failure";
      };
    };
    client = { ... }: {
      imports = [ base module ];
      services.nnlan.enable = true;
      services.nnlan.package = package;
      systemd.network.networks."10-test".address = [ "192.0.2.2/24" "fd10:b007::2/64" ];
      systemd.services.fixture = {
        before = [ "nnlan-guard.service" ];
        requiredBy = [ "nnlan-guard.service" ];
        unitConfig.DefaultDependencies = false;
        after = [ "local-fs.target" ];
        serviceConfig.Type = "oneshot";
        path = [ package pkgs.coreutils ];
        script = ''
          if [ ! -f /var/lib/nnlan/nnlan.toml ]; then
            nnlan --config /var/lib/nnlan/nnlan.toml init
            nnlan --config /var/lib/fixture-peer/nnlan.toml init
            peer=$(nnlan --config /var/lib/fixture-peer/nnlan.toml identity)
            printf '[routes]\nexit_node = "%s"\n' "$peer" > /var/lib/nnlan/nnlan.toml
            # A malformed runtime state must not prevent early protection.
            printf 'damaged state' > /var/lib/nnlan/identity.state.json
          fi
        '';
      };
      systemd.services.boot-probe = {
        wantedBy = [ "multi-user.target" ];
        before = [ "nnlan-guard.service" ];
        unitConfig.DefaultDependencies = false;
        after = [ "local-fs.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${probe}";
        serviceConfig.TimeoutStartSec = 15;
        postStart = ''
          until test -s /run/probe-count; do sleep 0.05; done
        '';
      };
      systemd.services.systemd-networkd.preStart = ''
        ${pkgs.nftables}/bin/nft list table inet nnlan > /run/systemd/netif/guard-before-network
      '';
    };
  };
  testScript = ''
    import json, os, time

    internet.start()
    internet.wait_for_file("/run/receiver-ready")
    client.start()
    client.wait_for_unit("nnlan-guard.service")
    client.wait_for_unit("systemd-networkd.service")
    client.wait_until_succeeds("ip -6 addr show dev eth1 | grep -F 'fd10:b007::2/64'")
    client.wait_until_succeeds("journalctl -u nnlan.service --no-pager | grep 'invalid state'")
    client.succeed("systemctl stop nnlan.service")
    client.succeed("test -s /run/systemd/netif/guard-before-network")
    assert client.succeed("cat /var/lib/nnlan/identity.state.json") == "damaged state"
    client.fail("ip link show nnlan0")

    def timestamp(unit, field):
        return int(client.succeed(f"systemctl show {unit} -p {field} --value").strip())

    guard_done = timestamp("nnlan-guard", "ExecMainExitTimestampMonotonic")
    network_started = timestamp("systemd-networkd", "ExecMainStartTimestampMonotonic")
    assert 0 < guard_done < network_started

    def count():
        return int(client.succeed("cat /run/probe-count"))

    def no_leak():
        before = count()
        time.sleep(3)
        assert count() > before + 8
        internet.succeed("test ! -s /run/requests.jsonl")

    no_leak()
    # Independent nft protection, not merely the blackhole routing table.
    client.succeed("ip route flush table 33033; ip -6 route flush table 33033")
    no_leak()
    # Repeated guard is idempotent, does not require working runtime state.
    client.succeed("nnlan --config /var/lib/nnlan/nnlan.toml guard")
    no_leak()
    client.succeed("rm /var/lib/nnlan/identity.state.json")
    # Exercise the shipped daemon sandbox, not only its deliberate failure path.
    client.succeed("systemctl start nnlan.service")
    client.wait_until_succeeds("nnlan --config /var/lib/nnlan/nnlan.toml status")
    client.succeed("ip link show nnlan0")
    client.fail("nnlan --config /var/lib/nnlan/nnlan.toml guard")
    client.succeed("systemctl kill --kill-whom=main --signal=SIGKILL nnlan.service")
    client.wait_until_succeeds("test $(systemctl show nnlan -p NRestarts --value) -ge 1")
    client.wait_until_succeeds("nnlan --config /var/lib/nnlan/nnlan.toml status")
    no_leak()
    client.succeed("systemctl stop nnlan.service")
    client.succeed("nnlan --config /var/lib/nnlan/nnlan.toml exit off --offline")
    internet.wait_until_succeeds("test -s /run/requests.jsonl")
    time.sleep(3)
    positive = [json.loads(line) for line in internet.succeed("cat /run/requests.jsonl").splitlines()]
    assert {p["source"] for p in positive} == {"192.0.2.2", "fd10:b007::2"}
    assert {p["transport"] for p in positive} == {1, 2}

    # Actual reboot: invalid config fails the guard, so networkd must not run.
    client.succeed("echo 'invalid configuration' > /var/lib/nnlan/nnlan.toml")
    client.shutdown()
    internet.succeed("truncate -s 0 /run/requests.jsonl")
    client.start()
    client.wait_until_succeeds("systemctl is-failed nnlan-guard.service")
    client.fail("systemctl is-active systemd-networkd.service")
    client.fail("test -e /run/systemd/netif/guard-before-network")
    client.fail("ip addr show dev eth1 | grep -F '192.0.2.2/24'")
    client.fail("ip -6 addr show dev eth1 | grep -F 'fd10:b007::2/64'")
    no_leak()

    evidence = {
        "result": "passed", "scope": "two real NixOS VMs, static dual-stack networkd",
        "guard_completed_us": guard_done, "network_started_us": network_started,
        "binary_sha256": client.succeed("sha256sum ${package}/bin/nnlan").split()[0],
        "positive_sources": sorted({p["source"] for p in positive}),
        "fixture_sha256": "${builtins.hashFile "sha256" ./boot.nix}",
        "module_sha256": "${builtins.hashFile "sha256" ../../nix/module.nix}",
        "guard_unit_sha256": "${builtins.hashFile "sha256" ../../packaging/systemd/nnlan-guard.service}",
        "daemon_unit_sha256": "${builtins.hashFile "sha256" ../../packaging/systemd/nnlan.service}",
        "checks": ["cold boot before addresses", "daemon failure", "damaged state",
                   "table deletion", "idempotent guard", "daemon sandbox and crash restart",
                   "explicit off positive control",
                   "reboot guard failure blocks networkd"],
    }
    with open(os.path.join(driver.out_dir, "boot.json"), "w") as f:
        json.dump(evidence, f, indent=2)
  '';
}
