{ pkgs, package, module }:
let
  initialServer = pkgs.writeText "dhcp-fixture.conf" ''
    port=0
    interface=eth1
    bind-dynamic
    dhcp-authoritative
    dhcp-range=192.0.2.100,192.0.2.100,255.255.255.0,120s
    dhcp-option=option:router,192.0.2.1
    dhcp-range=fd10:dc::100,fd10:dc::100,64,120s
    enable-ra
    ra-param=eth1,3,30
    dhcp-leasefile=/var/lib/dhcp-fixture.leases
    log-dhcp
  '';
  base = { lib, ... }: {
    networking.useDHCP = false;
    networking.useNetworkd = true;
    networking.firewall.enable = false;
    systemd.network.wait-online.enable = false;
    virtualisation.memorySize = 768;
    systemd.network.networks."99-eth0".networkConfig.DHCP = lib.mkForce "no";
    environment.systemPackages = [ package pkgs.python3 pkgs.iproute2 pkgs.nftables pkgs.tcpdump ];
  };
  node = { ... }: {
    imports = [ base module ];
    services.nnlan.enable = true;
    services.nnlan.package = package;
    systemd.services.fixture = {
      requiredBy = [ "nnlan-guard.service" ];
      before = [ "nnlan-guard.service" ];
      after = [ "local-fs.target" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig.Type = "oneshot";
      path = [ package pkgs.coreutils ];
    };
  };
in pkgs.testers.runNixOSTest {
  name = "nnlan-dhcp-underlay";
  nodes = {
    internet = { ... }: {
      imports = [ base ];
      virtualisation.vlans = [ 2 ];
      systemd.network.networks."10-wan" = {
        matchConfig.Name = "eth1";
        address = [ "198.18.0.100/24" "2001:db8:ffff::100/64" ];
        gateway = [ "198.18.0.1" "2001:db8:ffff::1" ];
      };
      systemd.services.receiver = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        path = [ pkgs.iproute2 pkgs.gnugrep ];
        preStart = ''
          until ip -4 addr show dev eth1 | grep -q '198.18.0.100/24'; do sleep 0.1; done
          until ip -6 addr show dev eth1 | grep -q '2001:db8:ffff::100/64'; do sleep 0.1; done
          while ip -6 addr show dev eth1 tentative | grep -q inet6; do sleep 0.1; done
        '';
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 ${../e2e/exit_servers.py} /run/requests.jsonl 198.18.0.100 2001:db8:ffff::100";
          Restart = "on-failure";
          RestartSec = 1;
        };
      };
    };
    gateway = { ... }: {
      imports = [ node ];
      virtualisation.vlans = [ 1 2 ];
      boot.kernel.sysctl = { "net.ipv4.ip_forward" = 1; "net.ipv6.conf.all.forwarding" = 1; };
      systemd.network.networks."10-lan" = {
        matchConfig.Name = "eth1";
        address = [ "192.0.2.1/24" "192.0.2.254/24" "fd10:dc::1/64" ];
      };
      systemd.network.networks."10-wan" = {
        matchConfig.Name = "eth2";
        address = [ "198.18.0.1/24" "2001:db8:ffff::1/64" ];
      };
      systemd.services.fixture.script = ''
        if [ ! -f /var/lib/nnlan/nnlan.toml ]; then
          nnlan --config /var/lib/nnlan/nnlan.toml init
          printf 'dns_servers = ["198.18.0.100:53"]\n[routes]\nserve_exit = true\n' > /var/lib/nnlan/nnlan.toml
        fi
      '';
      systemd.services.dhcp-fixture = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        preStart = ''
          if [ ! -f /var/lib/dhcp-fixture.conf ]; then
            cp ${initialServer} /var/lib/dhcp-fixture.conf
          fi
        '';
        serviceConfig.ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --no-daemon --conf-file=/var/lib/dhcp-fixture.conf";
      };
      systemd.services.capture = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.tcpdump}/bin/tcpdump -n -U -i eth1 -w /run/dhcp.pcap udp port 67 or udp port 68 or udp port 546 or udp port 547";
      };
    };
    client = { ... }: {
      imports = [ node ];
      virtualisation.vlans = [ 1 ];
      boot.kernel.sysctl = {
        "net.ipv4.conf.all.rp_filter" = 1;
        "net.ipv4.conf.default.rp_filter" = 1;
        "net.ipv4.conf.all.src_valid_mark" = 1;
      };
      systemd.network.networks."10-dhcp" = {
        matchConfig.Name = "eth1";
        networkConfig = { DHCP = "yes"; IPv6AcceptRA = true; };
        dhcpV4Config.UseDNS = false;
        dhcpV6Config = { UseDNS = false; WithoutRA = "solicit"; };
        ipv6AcceptRAConfig.UseDNS = false;
      };
      systemd.services.fixture.script = ''
        if [ ! -f /var/lib/nnlan/nnlan.toml ]; then
          nnlan --config /var/lib/nnlan/nnlan.toml init
          nnlan --config /var/lib/fixture-peer/nnlan.toml init
          peer=$(nnlan --config /var/lib/fixture-peer/nnlan.toml identity)
          uid=$(id -u systemd-network)
          printf 'dhcp_client_uid = %s\n[routes]\nexit_node = "%s"\n' "$uid" "$peer" > /var/lib/nnlan/nnlan.toml
        fi
      '';
    };
  };
  testScript = ''
    import json, os
    from datetime import timedelta

    try:
        deadline = timedelta(seconds=45)
        internet.start()
        gateway.start()
        gateway.wait_for_unit("dhcp-fixture.service")
        gateway.wait_for_unit("nnlan.service")
        internet.wait_until_succeeds("python3 ${../e2e/exit_client.py} http 198.18.0.100", timeout=deadline)
        client.start()
        client.wait_for_unit("nnlan-guard.service")
        client.wait_until_succeeds("ip -4 addr show dev eth1 | grep -F '192.0.2.100/24'", timeout=deadline)
        client.wait_until_succeeds("ip -6 addr show dev eth1 | grep -F 'fd10:dc::100/128'", timeout=deadline)
        client.wait_until_succeeds("ip -4 route show table main default | grep 'via 192.0.2.1 '", timeout=deadline)
        client.wait_until_succeeds("ip -6 route show table main default | grep 'proto ra'", timeout=deadline)

        cli = "nnlan --config /var/lib/nnlan/nnlan.toml"
        peer = gateway.succeed(cli + " identity").strip()
        uid = int(client.succeed("id -u systemd-network"))
        client.succeed("systemctl stop nnlan.service")
        config = f'dhcp_client_uid = {uid}\n[[peers]]\nendpoint = "198.18.0.1:7331"\npublic_key = "{peer}"\n[routes]\nexit_node = "{peer}"\n'
        client.succeed("cat > /var/lib/nnlan/nnlan.toml <<'CONFIG'\n" + config + "CONFIG")
        client.succeed("systemctl start nnlan.service")
        client.wait_until_succeeds(cli + " status", timeout=deadline)
        boot = json.loads(client.succeed(cli + " status"))["boot_id"]
        expected = ["198.18.0.1", "2001:db8:ffff::1"]
        external = ["198.18.0.100", "2001:db8:ffff::100"]

        def app(family):
            host = external[family]
            return json.loads(client.succeed(f"python3 ${../e2e/exit_client.py} http {host}"))["source"]

        for family in [0, 1]:
            client.wait_until_succeeds(f"python3 ${../e2e/exit_client.py} http {external[family]}", timeout=deadline)
            assert app(family) == expected[family]

        for host in external:
            for mode in ["udp", "tcp"]:
                client.succeed(f"python3 ${../e2e/exit_client.py} {mode} {host} dhcp.test")

        def renew():
            previous = {kind: int(gateway.succeed(f"journalctl -u dhcp-fixture --no-pager | grep -c {kind} || true")) for kind in ["DHCPACK", "DHCPREPLY"]}
            # networkctl Renew only triggers DHCPv4 in pinned systemd 261.2.
            # DHCPv6 must reach its real T1 timer for this 120-second lease.
            client.succeed("networkctl renew eth1")
            for kind, count in previous.items():
                gateway.wait_until_succeeds(f"test $(journalctl -u dhcp-fixture --no-pager | grep -c {kind}) -gt {count}", timeout=timedelta(seconds=150))
            client.wait_until_succeeds("ip -j -6 addr show dev eth1 | python3 -c 'import json,sys; assert any(a.get(\"local\") == \"fd10:dc::100\" and a[\"valid_life_time\"] > 100 for link in json.load(sys.stdin) for a in link[\"addr_info\"])'", timeout=deadline)

        renew()
        # A genuine IPv4 unicast renewal, not a new L2 discovery after lease expiry.
        # libpcap's capture buffer can trail the server journal despite -U.
        gateway.wait_until_succeeds("tcpdump -nn -r /run/dhcp.pcap 'src host 192.0.2.100 and dst host 192.0.2.1 and udp src port 68 and udp dst port 67' 2>/dev/null | grep '192.0.2.100.68'", timeout=deadline)
        gateway.wait_until_succeeds("tcpdump -nn -v -r /run/dhcp.pcap 'udp src port 546 and udp dst port 547' 2>/dev/null | grep 'dhcp6 renew'", timeout=deadline)
        assert [app(i) for i in [0, 1]] == expected

        # Server changes both IPv4 lease and default gateway. No nnlan restart.
        gateway.succeed("systemctl stop dhcp-fixture; sed -i 's/192.0.2.100/192.0.2.101/g; s/option:router,192.0.2.1$/option:router,192.0.2.254/' /var/lib/dhcp-fixture.conf; rm -f /var/lib/dhcp-fixture.leases; systemctl start dhcp-fixture")
        client.succeed("networkctl renew eth1")
        # The networkd renew socket binds the leased unicast address; dnsmasq's
        # broadcast NAK can require reaching T2/expiry before a new discovery.
        # Keep real protocol timers (120 s lease), no synthetic interface reset.
        client.wait_until_succeeds("ip -4 addr show dev eth1 | grep -F '192.0.2.101/24'", timeout=timedelta(seconds=150))
        client.wait_until_succeeds("ip -4 route show table main default | grep 'via 192.0.2.254 '", timeout=deadline)
        gateway.succeed("ip addr del 192.0.2.1/24 dev eth1")
        for family in [0, 1]:
            client.wait_until_succeeds(f"python3 ${../e2e/exit_client.py} http {external[family]}", timeout=deadline)
            assert app(family) == expected[family]
        assert json.loads(client.succeed(cli + " status"))["boot_id"] == boot

        # Daemon down, TUN gone, DHCP still renews while applications stay blocked.
        client.succeed("systemctl stop nnlan.service")
        client.fail("ip link show nnlan0")
        internet.succeed("truncate -s 0 /run/requests.jsonl")
        renew()
        for host in external:
            for mode in ["http", "udp", "tcp"]:
                client.fail(f"python3 ${../e2e/exit_client.py} {mode} {host} blocked.test")
        internet.succeed("test ! -s /run/requests.jsonl")
        client.succeed(cli + " exit off --offline")
        assert app(0) == "192.0.2.101"
        assert app(1) == "fd10:dc::100"
        report = {
            "ok": True, "scope": "three real VMs, networkd DHCPv4/DHCPv6 and RA",
            "binary_sha256": client.succeed("sha256sum ${package}/bin/nnlan").split()[0],
            "fixture_sha256": "${builtins.hashFile "sha256" ./dhcp.nix}",
            "helpers_sha256": {
                "exit_servers.py": "${builtins.hashFile "sha256" ../e2e/exit_servers.py}",
                "exit_client.py": "${builtins.hashFile "sha256" ../e2e/exit_client.py}",
            },
            "client_uid": uid, "dhcp_with_guard_before_network": True,
            "unicast_renewal": True, "address_and_gateway_change_without_daemon_restart": True,
            "daemon_down_dhcp_and_fail_closed": True, "explicit_off_positive_control": True,
        }
        with open(os.path.join(driver.out_dir, "dhcp.json"), "w") as f:
            json.dump(report, f, indent=2)
    except Exception:
        for machine in [client, gateway, internet]:
            for command in [
                "nnlan --config /var/lib/nnlan/nnlan.toml status",
                "ip -j address; ip -4 route show table all; ip -6 route show table all; ip -4 rule; ip -6 rule",
                "nft list ruleset",
                "journalctl -u nnlan -u systemd-networkd -u dhcp-fixture --no-pager -n 80",
                "cat /run/requests.jsonl",
                "tcpdump -nn -v -r /run/dhcp.pcap | tail -40",
            ]:
                print(machine.name, command, machine.execute(command))
        raise
  '';
}
