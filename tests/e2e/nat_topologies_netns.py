#!/usr/bin/env python3
"""Actual double NAT and shared-public-address hairpin, including relay fallback."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from nat_fixture import RELAY, install
from netns_fixture import Network


def rules(net, node, text):
    path = net.directory / f"{node}-topology.nft"
    path.write_text(text)
    net.ns(node, "nft", "-f", str(path))


def forwarding(net, node):
    net.ns(node, "sysctl", "-qw", "net.ipv4.ip_forward=1")


def double_nat(net, mapping):
    net.link("r", "w", "wan", "relay", [f"{RELAY}/30", "198.18.0.1/30"])
    net.ns("r", "ip", "route", "add", "default", "via", "198.18.0.1")
    forwarding(net, "w")
    for index, node in enumerate(["a", "b"], 1):
        inner, outer = "i" + node, "n" + node
        net.link(node, inner, "wan", "lan", ["192.168.77.2/24", "192.168.77.1/24"])
        net.link(inner, outer, "wan", "lan", ["10.77.0.2/24", "10.77.0.1/24"])
        net.link(outer, "w", "wan", "to_" + node, [f"198.18.{index}.2/30", f"198.18.{index}.1/30"])
        for host, gateway in [(node, "192.168.77.1"), (inner, "10.77.0.1"), (outer, f"198.18.{index}.1")]:
            net.ns(host, "ip", "route", "add", "default", "via", gateway)
        forwarding(net, inner)
        forwarding(net, outer)
        # Inner NAT only returns traffic from endpoints actually contacted.
        # The outer finite model independently controls mapping and filtering.
        rules(net, inner, '''table ip inner_nat {
 chain forward { type filter hook forward priority filter; policy drop;
  iifname "lan" oifname "wan" ip saddr 192.168.77.2 udp sport 7331 counter accept
  iifname "wan" oifname "lan" ct state established ip daddr 192.168.77.2 udp dport 7331 counter accept
 }
 chain srcnat { type nat hook postrouting priority srcnat; policy accept;
  oifname "wan" ip saddr 192.168.77.2 udp sport 7331 counter snat to 10.77.0.2:7331
 }
}
''')
        install(net, outer, f"198.18.{index}.2", mapping, "apdf")
    for prefix in ["192.168.77.0/24", "10.77.0.0/24"]:
        net.ns("w", "ip", "route", "add", "blackhole", prefix)


def hairpin(net, enabled):
    net.link("r", "n", "wan", "wan", [f"{RELAY}/24", "198.18.0.1/24"])
    net.ns("n", "ip", "addr", "add", "198.18.1.2/32", "dev", "lo")
    net.ns("r", "ip", "route", "add", "198.18.1.2/32", "via", "198.18.0.1")
    forwarding(net, "n")
    for index, node in enumerate(["a", "b"], 1):
        net.link(node, "n", "wan", "lan_" + node, [f"10.77.{index}.2/24", f"10.77.{index}.1/24"])
        net.ns(node, "ip", "route", "add", "default", "via", f"10.77.{index}.1")
    hairpin_rules(net, enabled)


def hairpin_rules(net, enabled, replace=False):
    # Distinct LAN interfaces prohibit ordinary private-address shortcuts. Only
    # DNAT traffic may cross them, and then only when hairpin is enabled.
    text = "delete table ip hairpin\n" if replace else ""
    text += '''table ip hairpin {
 set opened { type inet_service; flags dynamic,timeout; timeout 30s; size 16; }
 chain dstnat { type nat hook prerouting priority dstnat; policy accept;
  ip daddr 198.18.1.2 udp dport @opened udp dport 40000 counter dnat to 10.77.1.2:7331
  ip daddr 198.18.1.2 udp dport @opened udp dport 40001 counter dnat to 10.77.2.2:7331
 }
 chain forward { type filter hook forward priority filter; policy drop;
  iifname { "lan_a", "lan_b" } oifname "wan" udp sport 7331 counter accept
  iifname "wan" oifname { "lan_a", "lan_b" } ct state established udp dport 7331 counter accept
  iifname "wan" oifname { "lan_a", "lan_b" } ct status dnat counter accept
'''
    if enabled:
        text += '  iifname { "lan_a", "lan_b" } oifname { "lan_a", "lan_b" } ct status dnat counter accept\n'
    text += '''  counter drop
 }
 chain srcnat { type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.77.1.2 udp sport 7331 counter snat to 198.18.1.2:40000
  ip saddr 10.77.2.2 udp sport 7331 counter snat to 198.18.1.2:40001
 }
 chain remember { type filter hook postrouting priority 110; policy accept;
  ip saddr 198.18.1.2 udp sport { 40000, 40001 } update @opened { udp sport }
 }
}
'''
    rules(net, "n", text)


def probe_hairpin(net, enabled):
    # Use actual application sockets first, independently of overlay status.
    reflector = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.18.0.2',9001))
while True:
 data,peer=s.recvfrom(1024);s.sendto(json.dumps(peer).encode(),peer)
'''
    net.spawn("r", ["python3", "-c", reflector], net.directory / "mapping-probe.log")
    net.wait(lambda: ":9001" in net.ns("r", "ss", "-uln").stdout, "mapping reflector bound")
    server = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.77.2.2',7331));s.settimeout(4)
s.sendto(b'mapping-probe',('198.18.0.2',9001));print(json.dumps({'mapping':json.loads(s.recv(1024))}),flush=True)
try:
 data,peer=s.recvfrom(1024)
 if data==b'hairpin':
  print(json.dumps({'peer':peer}),flush=True);s.sendto(b'hairpin-ok',peer)
except socket.timeout: pass
'''
    log = net.directory / "hairpin-probe.log"
    child = net.spawn("b", ["python3", "-c", server], log)
    net.wait(lambda: '"mapping"' in log.read_text(), "hairpin probe bound")
    client = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.77.1.2',7331));s.settimeout(1)
s.sendto(b'mapping-probe',('198.18.0.2',9001));mapping=json.loads(s.recv(1024))
s.sendto(b'hairpin',('198.18.1.2',40001));result={'mapping':mapping,'hairpin':False}
try:
 data,peer=s.recvfrom(1024);result.update(hairpin=data==b'hairpin-ok',peer=peer)
except socket.timeout: pass
print(json.dumps(result))
'''
    observed = json.loads(net.ns("a", "python3", "-c", client).stdout)
    assert observed["mapping"] == ["198.18.1.2", 40000], observed
    assert observed["hairpin"] == enabled, observed
    assert child.wait(timeout=6) == 0
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert entries[0]["mapping"] == ["198.18.1.2", 40001], entries
    if enabled:
        assert observed["peer"] == ["198.18.1.2", 40001], observed
        assert entries[1]["peer"] == ["198.18.1.2", 40000], entries
    # No probe-created permissions/connections carry into the overlay test.
    hairpin_rules(net, enabled, replace=True)
    for address in ["10.77.1.2", "10.77.2.2"]:
        net.ns("n", "conntrack", "-D", "-p", "udp", "--orig-src", address)
    return dict(a=observed, b=entries)


def exercise(net, expected_direct, endpoints, failed_packets=None):
    net.init(["a", "b", "r"])
    for node in net.paths:
        config = f'name = "{node}"\nmax_neighbors = 2\n'
        if node != "r":
            config += f'[[peers]]\nendpoint = "{RELAY}:7331"\npublic_key = "{net.ids["r"]}"\n'
        net.paths[node].write_text(config)
        net.start(node)
    net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 3 for n in net.paths), "topology membership")
    boots = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}

    def direct():
        return all(any(p["node"] == net.ids[other] for p in net.rpc(node, "status")["neighbors"])
                   for node, other in [("a", "b"), ("b", "a")])

    def advertised():
        records = net.rpc("a", "peers")
        return all(any(r["record"]["descriptor"]["node"] == net.ids[n] and endpoint in r["record"]["descriptor"]["endpoints"]
                       for r in records) for n, endpoint in endpoints.items())

    net.wait(advertised, "outer/public candidates discovered")
    assert not direct(), "discovery created unsolicited full mesh"
    initial = net.rpc("a", "trace", "b")
    assert initial["complete"] and [h["node"] for h in initial["hops"]] == [net.ids["r"], net.ids["b"]], initial
    start = time.monotonic()
    # A single user request must drive the second candidate; do not accidentally
    # hide a scheduler that only advances while the application keeps polling.
    echo = net.rpc("a", "ping", "b", "--size", "2048")
    assert echo["hop_encrypted"] and echo["bytes"] == 2048
    quiet_before = None
    while time.monotonic() - start < (35 if expected_direct else 22):
        if direct():
            break
        if failed_packets and quiet_before is None and time.monotonic() - start >= 20:
            quiet_before = failed_packets()
        time.sleep(0.3)
    assert direct() == expected_direct, net.rpc("a", "status")
    elapsed = time.monotonic() - start
    if expected_direct:
        assert elapsed < 3, ("dead first candidate stalled direct upgrade", elapsed)
    quiet_after = failed_packets() if failed_packets else None
    if failed_packets:
        assert quiet_before == quiet_after and quiet_after > 0, (quiet_before, quiet_after)
    traces, actual_endpoints = {}, {}
    for node, other in [("a", "b"), ("b", "a")]:
        trace = net.rpc(node, "trace", other)
        expected = [net.ids[other]] if expected_direct else [net.ids["r"], net.ids[other]]
        assert trace["complete"] and [h["node"] for h in trace["hops"]] == expected, trace
        traces[node] = trace
        assert net.rpc(node, "ping", other, "--size", "8192")["hop_encrypted"]
        address = net.rpc(other, "status")["address"]
        for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
            net.ns(node, "ping", family, "-n", "-c", "3", "-i", "0.2", "-W", "2", address[field])
        if expected_direct:
            peer = next(p for p in net.rpc(node, "status")["neighbors"] if p["node"] == net.ids[other])
            assert peer["endpoint"] == endpoints[other], peer
            actual_endpoints[node] = peer["endpoint"]
    assert all(len(net.rpc(n, "status")["neighbors"]) <= 2 for n in net.paths)
    assert all(net.rpc(n, "status")["boot_id"] == boots[n] for n in net.paths)
    return dict(direct=direct(), expected_direct=expected_direct, observed_seconds=elapsed,
                encrypted_echoes=1, single_request_trigger=True,
                stopped_failed_probes=quiet_after, bidirectional_dual_stack=True, traces=traces,
                actual_endpoints=actual_endpoints, no_daemon_restart=True, neighbor_limit=2)


def scenario(binary, name):
    layered = name.startswith("double-")
    names = ["a", "b", "r", "ia", "ib", "na", "nb", "w"] if layered else ["a", "b", "r", "n"]
    with Network(binary, names) as net:
        if layered:
            mapping = name.removeprefix("double-")
            double_nat(net, mapping)
            endpoints = {n: f"198.18.{i}.2:40000" for i, n in enumerate(["a", "b"], 1)}
            result = exercise(net, mapping == "eim", endpoints)
            connections = {n: net.ns(n, "conntrack", "-L", "-p", "udp").stdout for n in ["ia", "ib", "na", "nb"]}
            # Prove the daemon's relay session actually crossed both SNATs.
            for index, node in enumerate(["a", "b"], 1):
                assert any(f"src=192.168.77.2 dst={RELAY} sport=7331 dport=7331" in line and
                           f"src={RELAY} dst=10.77.0.2 sport=7331 dport=7331" in line
                           for line in connections["i" + node].splitlines()), connections
                assert any(f"src=10.77.0.2 dst={RELAY} sport=7331 dport=7331" in line and
                           f"src={RELAY} dst=198.18.{index}.2 sport=7331 dport=40000" in line
                           for line in connections["n" + node].splitlines()), connections
            result["two_snat_layers"] = connections
        else:
            enabled = name == "hairpin-on"
            hairpin(net, enabled)
            measured = probe_hairpin(net, enabled)
            def failed_packets():
                entries = json.loads(net.ns("n", "nft", "-j", "list", "chain", "ip", "hairpin", "forward").stdout)
                return sum(expr["counter"]["packets"] for item in entries["nftables"] if "rule" in item
                           and any("drop" in expr for expr in item["rule"]["expr"])
                           for expr in item["rule"]["expr"] if "counter" in expr)
            result = exercise(net, enabled, {"a": "198.18.1.2:40000", "b": "198.18.1.2:40001"},
                              failed_packets=None if enabled else failed_packets)
            result["independent_hairpin_probe"] = measured
            result["router_rules"] = json.loads(net.ns("n", "nft", "-j", "list", "table", "ip", "hairpin").stdout)
            result["conntrack"] = net.ns("n", "conntrack", "-L", "-p", "udp").stdout
        result.update(case=name, ok=True)
        print(json.dumps(result), flush=True)
        return result


def main():
    cases = ["double-eim", "double-apdm", "hairpin-on", "hairpin-off"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--case", choices=["all", *cases], default="all")
    parser.add_argument("--output", type=Path, default=Path("target/e2e-nat-topologies.json"))
    args = parser.parse_args()
    selected = cases if args.case == "all" else [args.case]
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                      binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                      fixture_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                      for name in ["nat_topologies_netns.py", "nat_fixture.py", "netns_fixture.py"]})
    report = dict(ok=False, requested_cases=selected, scenarios=[], provenance=provenance)

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pending = args.output.with_suffix(".tmp")
        pending.write_text(json.dumps(report, indent=2) + "\n")
        pending.replace(args.output)

    save()
    for case in selected:
        report["scenarios"].append(scenario(args.binary, case))
        save()
    report["ok"] = True
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    save()


if __name__ == "__main__":
    main()
