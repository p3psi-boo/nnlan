#!/usr/bin/env python3
"""Exit selection, dual-stack TCP/DNS, fail-closed crash/recovery and marked bootstrap."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import ipaddress
import platform
from pathlib import Path
from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    provenance = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "kernel": platform.release(),
    }
    if args.output:
        # A failed rerun must not leave a prior success looking like its result.
        args.output.unlink(missing_ok=True)
    here = Path(__file__).resolve().parent
    external = ["198.18.0.100", "2001:db8:ffff::100"]
    sources = {n: [f"10.120.{i}.1", str(ipaddress.ip_address(f"fd10:120:{i}::1"))] for i, n in enumerate(["a", "b", "c"])}
    with Network(args.binary, ["a", "r", "b", "c", "internet"]) as net:
        net.init(["a", "r", "b", "c"])
        for i, name in enumerate(["a", "b", "c"]):
            net.link(name, "internet", "wan", f"u{name}", [f"10.120.{i}.1/30", f"10.120.{i}.2/30"], [f"fd10:120:{i}::1/64", f"fd10:120:{i}::2/64"])
            net.ns(name, "ip", "route", "add", "default", "via", f"10.120.{i}.2")
            net.ns(name, "ip", "-6", "route", "add", "default", "via", f"fd10:120:{i}::2")
            if name != "a":
                net.ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        # Strict RPF proves incoming marked DNS/UDP still works with a TUN default.
        net.ns("a", "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=1", "net.ipv4.conf.default.rp_filter=1", "net.ipv4.conf.wan.rp_filter=1", "net.ipv4.conf.lo.rp_filter=1", "net.ipv4.conf.all.src_valid_mark=1", "net.ipv4.conf.default.src_valid_mark=0", "net.ipv4.conf.wan.src_valid_mark=0", "net.ipv4.conf.lo.src_valid_mark=0")
        net.link("a", "r", "ur", "ua", ["10.121.0.1/30", "10.121.0.2/30"])
        net.link("r", "b", "ub", "ur", ["10.121.1.1/30", "10.121.1.2/30"])
        net.link("r", "c", "uc", "ur", ["10.121.2.1/30", "10.121.2.2/30"])
        net.ns("internet", "ip", "addr", "add", external[0] + "/32", "dev", "lo")
        net.ns("internet", "ip", "-6", "addr", "add", external[1] + "/128", "dev", "lo", "nodad")
        traffic_log = net.directory / "traffic.jsonl"
        traffic_log.touch()
        net.spawn("internet", ["python3", str(here / "exit_servers.py"), str(traffic_log)], net.directory / "internet.log")
        for name in net.paths:
            dns = f'\ndns_servers = ["10.120.{["a", "b", "c"].index(name)}.2:5353"]\n' if name != "r" else ""
            peers = []
            if name == "a":
                peers = [("relay.test:7331", "r")]
            elif name == "r":
                peers = [("10.121.1.2:7331", "b"), ("10.121.2.2:7331", "c")]
            text = f'name = "{name}"\nmax_neighbors = {3 if name == "r" else 1}\n' + dns
            for endpoint, peer in peers:
                text += f'\n[[peers]]\nendpoint = "{endpoint}"\npublic_key = "{net.ids[peer]}"\n'
            text += '\n[tun]\nname = "nnlan0"\n'
            net.paths[name].write_text(text)
            net.start(name)

        def traffic():
            return [json.loads(line) for line in traffic_log.read_text().splitlines()]

        def app(mode, host, name="application.test", blocked=False):
            before = len(traffic())
            result = net.ns("a", "python3", str(here / "exit_client.py"), mode, host, name, check=False, timeout=6)
            if blocked:
                assert result.returncode != 0, f"application leaked: {result.stdout}"
                observed = traffic()[before:]
                assert not any(r["kind"] == "http" if mode == "http" else r["kind"] == "dns" and r["name"] == name for r in observed), observed
                return
            if result.returncode:
                raise RuntimeError(result.stderr)
            return json.loads(result.stdout)

        def expect(node):
            for i, host in enumerate(external):
                received = app("http", host)["source"]
                assert received == sources[node][i], (node, host, received, sources[node][i])
            return True

        def dns_expect(node, label):
            before = len(traffic())
            for mode in ["udp", "tcp"]:
                for host in external:
                    app(mode, host, label)
            records = [r for r in traffic()[before:] if r["kind"] == "dns" and r["name"] == label]
            assert len(records) >= 4 and all(r["source"] in sources[node] for r in records), records

        def blocked():
            for host in external:
                for mode in ["http", "udp", "tcp"]:
                    app(mode, host, "blocked.test", blocked=True)

        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 4 for n in net.paths), "membership via DNS hostname")
        expect("a"); dns_expect("a", "baseline.test")
        # Overlay VIP services must be reachable through authenticated TUN, not
        # directly over a physical interface (Linux otherwise uses weak-host input).
        service = "import socket\ns=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);s.bind(('::',8091));s.listen()\nwhile True:\n c,a=s.accept();c.sendall(b'overlay-only');c.close()"
        net.spawn("a", ["python3", "-c", service], net.directory / "vip-service.log")
        probe = "import socket,sys;s=socket.create_connection((sys.argv[1],8091),1.5);assert s.recv(64)==b'overlay-only'"
        address = net.rpc("a", "status")["address"]
        for family, field, gateway in [("-4", "ipv4", "10.120.0.1"), ("-6", "ipv6", "fd10:120::1")]:
            net.wait(lambda: net.ns("b", "python3", "-c", probe, address[field]).returncode == 0, "authenticated VIP service")
            net.ns("internet", "ip", family, "route", "add", address[field], "via", gateway)
            assert net.ns("internet", "python3", "-c", probe, address[field], check=False).returncode != 0

        for node in ["b", "c"]:
            net.rpc(node, "exit", "serve", "on")
        net.wait(lambda: sum(e["serve_exit"] for e in net.rpc("a", "routes")["advertised"]) == 2, "exit advertisements")
        before_config = net.paths["a"].read_bytes()
        net.ns("a", "sysctl", "-qw", "net.ipv4.conf.all.src_valid_mark=0")
        rejected = net.cli("a", "exit", "use", "b", check=False)
        assert rejected.returncode != 0 and "src_valid_mark" in rejected.stderr, rejected.stderr
        assert net.paths["a"].read_bytes() == before_config
        net.ns("a", "sysctl", "-qw", "net.ipv4.conf.all.src_valid_mark=1")
        net.rpc("a", "exit", "use", "b")
        assert net.rpc("a", "status")["kernel_exit_guard_installed"]
        expect("b"); dns_expect("b", "selected-b.test")
        # Early guard never races a live daemon or replaces its current policy.
        locked_guard = net.ns("a", net.binary, "--config", str(net.paths["a"]), "guard", check=False)
        assert locked_guard.returncode != 0 and "another daemon" in locked_guard.stderr
        expect("b")
        # Force real ARP renewal while strict RPF and the exit default are active.
        for name, dev in [("a", "ur"), ("r", "ua")]:
            net.ns(name, "ip", "neigh", "flush", "dev", dev)
        net.wait(lambda: expect("b"), "dynamic ARP renewal with strict RPF")
        # Change the physical source address beneath the still-selected exit.
        # The wildcard UDP socket must migrate after authentication; there is no
        # daemon restart, static neighbor entry or change of the selected exit.
        net.ns("r", "ip", "route", "add", "10.121.0.5/32", "dev", "ua")
        net.ns("a", "ip", "addr", "add", "10.121.0.5/29", "dev", "ur")
        net.ns("a", "ip", "addr", "del", "10.121.0.1/30", "dev", "ur")
        net.wait(lambda: expect("b"), "physical source address renewal with selected exit")
        assert net.rpc("a", "routes")["exit_node"] == net.ids["b"]
        net.spawn("a", ["python3", str(here / "exit_dns_stub.py")], net.directory / "stub.log")
        net.wait(lambda: app("udp", "127.0.0.53", "stub.test")["ok"], "local DNS stub uses selected exit")
        assert all(r["source"] == sources["b"][0] for r in traffic() if r["kind"] == "dns" and r["name"] == "stub.test")
        app("udp", "169.254.169.253", "link-local-resolver.test")
        before_config = net.paths["a"].read_bytes()
        assert net.ns("a", net.binary, "--config", str(net.paths["a"]), "exit", "off", "--offline", check=False).returncode != 0
        assert net.paths["a"].read_bytes() == before_config
        # UDP upstream truncation must retry TCP rather than drop a valid query.
        app("udp", external[0], "large.test")
        assert any(r["kind"] == "dns" and r["name"] == "large.test" and r["tcp"] for r in traffic())
        trace = net.rpc("a", "trace", "b")
        assert trace["complete"] and [h["node"] for h in trace["hops"]] == [net.ids["r"], net.ids["b"]]
        net.crash("b"); blocked()
        app("udp", "127.0.0.53", "stub-blocked.test", blocked=True)
        assert not any(r["kind"] == "dns" and r["name"] == "stub-blocked.test" for r in traffic())
        assert net.rpc("a", "routes")["exit_node"] == net.ids["b"]
        net.rpc("a", "exit", "use", "c")
        expect("c"); dns_expect("c", "selected-c.test")
        net.start("b")
        net.wait(lambda: net.rpc("b", "status")["nodes"] == 4, "old exit recovers")
        assert net.rpc("a", "routes")["exit_node"] == net.ids["c"]
        # Local identity policy must not silently change the selected exit or
        # fall back to the healthy local WAN / other healthy exit.
        net.rpc("a", "members", "deny", net.ids["c"])
        selected = net.rpc("a", "routes")
        assert selected["exit_node"] == net.ids["c"] and selected["exit_state"] == "unreachable"
        blocked()
        net.crash("a"); net.start("a")
        net.wait(lambda: net.rpc("a", "status")["network_running"], "restart with denied exit")
        assert net.ids["c"] in net.rpc("a", "members")["denied"]
        blocked()
        net.rpc("a", "members", "allow", net.ids["c"])
        net.wait(lambda: expect("c"), "explicit exit identity allowance")
        # Losing one family's external path cannot fall back to A's healthy WAN.
        net.ns("c", "ip", "-6", "route", "del", "default")
        app("http", external[1], blocked=True)
        assert app("http", external[0])["source"] == sources["c"][0]
        net.ns("c", "ip", "-6", "route", "add", "default", "via", "fd10:120:2::2")
        net.crash("a"); blocked()
        for family in ["-4", "-6"]:
            net.ns("a", "ip", family, "route", "flush", "table", "33033")
        blocked()  # nft alone, even without the unreachable/blackhole fallback.
        bootstrap_index = len(traffic())
        bootstrap_before = sum(r["kind"] == "dns" and r["name"] == "relay.test" and r["source"] == sources["a"][0] for r in traffic())
        net.start("a"); net.wait(lambda: expect("c"), "marked DNS bootstrap through persistent guard")
        assert sum(r["kind"] == "dns" and r["name"] == "relay.test" and r["source"] == sources["a"][0] for r in traffic()) > bootstrap_before
        assert any(r["kind"] == "dns" and r["name"] == "relay.test" and r["source"] == sources["a"][0] and r["tcp"] for r in traffic()[bootstrap_index:])
        dns_expect("c", "restarted.test")
        # Device removal must preserve protection even if the daemon is still alive.
        net.ns("a", "ip", "link", "del", "nnlan0")
        blocked(); net.crash("a")
        net.start("a"); net.wait(lambda: expect("c"), "TUN removal recovery")
        net.rpc("a", "exit", "off")
        expect("a"); dns_expect("a", "explicit-off.test")
        net.rpc("a", "exit", "use", "c"); expect("c")
        net.crash("a")
        # Simulate fresh kernel policy, then make TUN creation fail. Startup must
        # still install protection before it ever attempts TUN or peer/DNS setup.
        net.ns("a", "nft", "delete", "table", "inet", "nnlan")
        net.ns("a", "nft", "delete", "table", "arp", "nnlan")
        for family in ["-4", "-6"]:
            net.ns("a", "ip", family, "route", "flush", "table", "33033")
            net.ns("a", "ip", family, "rule", "del", "priority", "23333", "not", "fwmark", "0x336733", "lookup", "33033")
        net.ns("a", "ip", "link", "add", "nnlan0", "type", "dummy")
        net.start("a")
        net.wait(lambda: net.daemons["a"].poll() is not None, "expected TUN startup error")
        assert net.daemons["a"].returncode != 0
        blocked()
        net.ns("a", "ip", "link", "del", "nnlan0")
        net.start("a"); net.wait(lambda: expect("c"), "recovery after protected startup failure")
        net.crash("a")
        # Offline off requires this namespace and the identity lock, no live daemon.
        before_config = net.paths["a"].read_bytes()
        assert net.ns("internet", net.binary, "--config", str(net.paths["a"]), "exit", "off", "--offline", check=False).returncode != 0
        assert net.paths["a"].read_bytes() == before_config
        net.ns("a", net.binary, "--config", str(net.paths["a"]), "exit", "off", "--offline")
        expect("a"); dns_expect("a", "offline-off.test")
        assert not any(r["kind"] == "dns" and r["name"] == "blocked.test" for r in traffic())
        report = dict(ok=True, dual_stack=True, encrypted_multihop=True, udp_tcp_dns=True, local_dns_stub=True, link_local_dns=True, dns_tcp_fallback=True, explicit_exit_switch=True, exit_failure_closed=True, ipv6_failure_no_ipv4_fallback=True, client_sigkill_closed=True, nft_without_routes=True, tun_removal_closed=True, marked_hostname_bootstrap=True, marked_dns_tcp_bootstrap=True, protected_startup_failure=True, offline_namespace_and_lock_checked=True, strict_ipv4_rpf=True, dynamic_arp_renewal=True, overlay_vip_plaintext_isolated=True, live_and_offline_disable=True)
        report["provenance"] = {**provenance, "finished_at": datetime.now(timezone.utc).isoformat()}
        report["underlay_source_renewal"] = True
        report["denied_exit_persistent_fail_closed"] = True
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
