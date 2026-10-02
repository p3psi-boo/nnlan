#!/usr/bin/env python3
"""One-shot IPv6 candidate discovery with a dropped or delayed first IPv4 path."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from netns_fixture import Network


def exercise(binary, ipv4_mode):
    with Network(binary, ["a", "b", "r", "w"]) as net:
        ips = {node: f"2001:db8:88:{index}::2" for index, node in enumerate(["r", "a", "b"])}
        for index, node in enumerate(["r", "a", "b"]):
            net.link(node, "w", "wan", "to_" + node,
                     [f"10.88.{index}.2/24", f"10.88.{index}.1/24"],
                     [ips[node] + "/64", f"2001:db8:88:{index}::1/64"])
            net.ns(node, "ip", "route", "add", "default", "via", f"10.88.{index}.1")
            net.ns(node, "ip", "-6", "route", "add", "default", "via", f"2001:db8:88:{index}::1")
        for family in ["ipv4.ip_forward", "ipv6.conf.all.forwarding"]:
            net.ns("w", "sysctl", "-qw", f"net.{family}=1")
        blocked_v4 = net.directory / "ipv4-block.nft"
        blocked_v4.write_text('''table inet dead_v4 {
 chain forward { type filter hook forward priority -10; policy accept;
  meta nfproto ipv4 counter drop
 }
}
'''.replace("counter drop", "counter accept" if ipv4_mode == "delay" else "counter drop"))
        net.ns("w", "nft", "-f", str(blocked_v4))
        if ipv4_mode == "delay":
            for node in ["a", "b"]:
                net.ns(node, "tc", "qdisc", "add", "dev", "wan", "root", "handle", "1:", "prio")
                net.ns(node, "tc", "qdisc", "add", "dev", "wan", "parent", "1:3", "handle", "30:",
                       "netem", "delay", "1500ms", "limit", "64")
                net.ns(node, "tc", "filter", "add", "dev", "wan", "parent", "1:", "protocol", "ip",
                       "prio", "1", "u32", "match", "ip", "protocol", "17", "0xff", "flowid", "1:3")
        # Incoming UDP has no permanent public-port exception. Both nodes must
        # initiate toward the discovered IPv6 endpoint to open their own filter.
        stateful = net.directory / "stateful.nft"
        stateful.write_text('''table inet stateful {
 chain input { type filter hook input priority filter; policy accept;
  iifname "wan" meta nfproto ipv4 udp dport 7331 ct state established counter accept
  iifname "wan" meta l4proto udp udp dport 7331 ct state established counter accept
  iifname "wan" meta l4proto udp udp dport 7331 counter drop
 }
}
''')
        for node in ["a", "b"]:
            net.ns(node, "nft", "-f", str(stateful))
        net.init(["a", "b", "r"])
        for node in net.paths:
            config = f'name = "{node}"\nlisten = "[::]:7331"\nmax_neighbors = 2\n'
            if node != "r":
                config += f'[[peers]]\nendpoint = "[{ips["r"]}]:7331"\npublic_key = "{net.ids["r"]}"\n'
            net.paths[node].write_text(config)
            net.start(node)
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 3 for n in net.paths), "IPv6-only bootstrap")
        boots = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}

        def direct():
            return all(any(p["node"] == net.ids[other] and p["endpoint"] == f"[{ips[other]}]:7331"
                           for p in net.rpc(node, "status")["neighbors"])
                       for node, other in [("a", "b"), ("b", "a")])

        def trace(node, other, expected):
            actual = net.rpc(node, "trace", other)
            assert actual["complete"] and [h["node"] for h in actual["hops"]] == [net.ids[n] for n in expected], actual
            return actual

        def traffic():
            for node, other in [("a", "b"), ("b", "a")]:
                echo = net.rpc(node, "ping", other, "--size", "8192")
                assert echo["hop_encrypted"] and echo["bytes"] == 8192
                address = net.rpc(other, "status")["address"]
                for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
                    net.ns(node, "ping", family, "-n", "-c", "3", "-i", "0.2", "-W", "2", address[field])

        assert not direct(), "discovery created a full mesh"
        initial_trace = trace("a", "b", ["r", "b"])
        # Confirm both candidate families exist, with the dead IPv4 candidate
        # first. Configured peers contain R only; no hand-written A/B candidate.
        records = net.rpc("a", "peers")
        for index, node in enumerate(["a", "b"], 1):
            endpoints = next(r["record"]["descriptor"]["endpoints"] for r in records
                             if r["record"]["descriptor"]["node"] == net.ids[node])
            assert endpoints.index(f"10.88.{index}.2:7331") < endpoints.index(f"[{ips[node]}]:7331"), endpoints
        start = time.monotonic()
        assert net.rpc("a", "ping", "b", "--size", "2048")["hop_encrypted"]
        net.wait(direct, "single-request family fallback", timeout=3)
        upgrade_seconds = time.monotonic() - start
        assert upgrade_seconds < 3
        traces = [trace("a", "b", ["b"]), trace("b", "a", ["a"])]
        traffic()
        v4_rules = json.loads(net.ns("w", "nft", "-j", "list", "table", "inet", "dead_v4").stdout)
        dropped = sum(expr["counter"]["packets"] for item in v4_rules["nftables"] if "rule" in item
                      for expr in item["rule"]["expr"] if "counter" in expr)
        assert dropped > 0, "first-family candidate was never actually attempted"
        delayed_stats = {}
        delayed_connections = {}
        if ipv4_mode == "delay":
            # IPv4 is usable but slower than the second candidate. Its valid
            # delayed responses must not revive the cancelled outgoing flights.
            # Keep both paths available through multiple 3 s round trips.
            settled = time.monotonic()
            while time.monotonic() - settled < 8:
                assert direct(), "late losing candidate replaced the IPv6 winner"
                time.sleep(0.2)
            for node in ["a", "b"]:
                stats = json.loads(net.ns(node, "tc", "-j", "-s", "qdisc", "show", "dev", "wan").stdout)
                delayed = next(q for q in stats if q["kind"] == "netem")
                assert delayed["packets"] > 0 and delayed["drops"] == 0, delayed
                delayed_stats[node] = stats
                connections = net.ns(node, "conntrack", "-L", "-f", "ipv4", "-p", "udp", "--dport", "7331").stdout
                assert "[ASSURED]" in connections, connections
                delayed_connections[node] = connections
                filters = json.loads(net.ns(node, "nft", "-j", "list", "chain", "inet", "stateful", "input").stdout)
                first = next(item["rule"] for item in filters["nftables"] if "rule" in item)
                assert sum(e["counter"]["packets"] for e in first["expr"] if "counter" in e) > 0, first
            # Isolate the following relay-fallback phase from the viable IPv4
            # alternative. This is a separate fault, not a delayed-path claim.
            net.ns("w", "nft", "flush", "chain", "inet", "dead_v4", "forward")
            net.ns("w", "nft", "add", "rule", "inet", "dead_v4", "forward",
                   "meta", "nfproto", "ipv4", "counter", "drop")

        blocked = net.directory / "ipv6-direct-block.nft"
        blocked.write_text(f'''table inet direct_block {{
 chain forward {{ type filter hook forward priority -20; policy accept;
  ip6 saddr {{ {ips["a"]}, {ips["b"]} }} ip6 daddr {{ {ips["a"]}, {ips["b"]} }} counter drop
 }}
}}
''')
        net.ns("w", "nft", "-f", str(blocked))
        net.wait(lambda: all(all(p["node"] != net.ids[other] for p in net.rpc(node, "status")["neighbors"])
                            for node, other in [("a", "b"), ("b", "a")]), "IPv6 direct path expires")
        fallback = [trace("a", "b", ["r", "b"]), trace("b", "a", ["r", "a"])]
        traffic()
        net.ns("w", "nft", "delete", "table", "inet", "direct_block")
        assert net.rpc("a", "ping", "b", "--size", "2048")["hop_encrypted"]
        net.wait(direct, "IPv6 direct recovery", timeout=12)

        net.crash("r")
        net.wait(lambda: all(all(p["node"] != net.ids["r"] for p in net.rpc(n, "status")["neighbors"])
                            for n in ["a", "b"]), "IPv6 bootstrap disappeared")
        idle = time.monotonic()
        while time.monotonic() - idle < 65:
            # Status RPC is not overlay user traffic. The only remaining edge
            # must survive demand expiry, record expiry and the idle threshold.
            assert direct()
            time.sleep(0.5)
        idle_seconds = time.monotonic() - idle
        traffic()
        independent = [trace("a", "b", ["b"]), trace("b", "a", ["a"])]
        assert all(net.rpc(n, "status")["boot_id"] == boots[n] for n in ["a", "b"])
        assert all(len(net.rpc(n, "status")["neighbors"]) <= 2 for n in ["a", "b"])
        return dict(ok=True, initial_trace=initial_trace, direct_traces=traces, fallback_traces=fallback,
                    independent_traces=independent, upgrade_seconds=upgrade_seconds,
                    single_request_trigger=True, ipv4_mode=ipv4_mode,
                    ipv4_candidate_packets=dropped, delayed_ipv4_stats=delayed_stats,
                    delayed_ipv4_connections=delayed_connections,
                    dead_ipv4_packets=dropped if ipv4_mode == "drop" else None,
                    bootstrap_offline_idle_seconds=idle_seconds, bidirectional_dual_stack=True,
                    no_endpoint_restart=True, ipv4_block=v4_rules,
                    stateful_filters={n:json.loads(net.ns(n, "nft", "-j", "list", "table", "inet", "stateful").stdout)
                                      for n in ["a", "b"]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--ipv4-mode", choices=["drop", "delay"], default="drop")
    parser.add_argument("--output", type=Path, default=Path("target/e2e-ipv6-discovery.json"))
    args = parser.parse_args()
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                      binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                      fixture_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                      for name in ["ipv6_discovery_netns.py", "netns_fixture.py"]})
    report = dict(ok=False, provenance=provenance)

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pending = args.output.with_suffix(".tmp")
        pending.write_text(json.dumps(report, indent=2) + "\n")
        pending.replace(args.output)

    save()
    report.update(exercise(args.binary, args.ipv4_mode))
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
