#!/usr/bin/env python3
"""Real UDP NAT mapping/filtering matrix and authenticated overlay fallback."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from netns_fixture import Network
from nat_fixture import RELAY, filtering_probe, install, mapping_probe, probe_servers, topology

CASES = {f"{mapping}-{filtering}": (mapping, filtering) for mapping in ["eim", "adm", "apdm"] for filtering in ["eif", "adf", "apdf"]}


PAIRS = {f"{left}+{right}": (left, right) for left in CASES for right in CASES}


def permits_direct(left, right):
    # Fixture-specific reachability, not a claim about every NAT with this label.
    # An EIF binding accepts an initiation at its advertised port; conntrack
    # returns replies from that same port. EIM+ADF also admits a peer's changed
    # source port after outbound contact. Two EIM mappings permit simultaneous
    # opening even when both filters require the exact remote endpoint.
    a, b = CASES[left], CASES[right]
    return (a[0] == b[0] == "eim" or any(
        filtering == "eif" or (mapping == "eim" and filtering == "adf")
        for mapping, filtering in [a, b]))


def scenario(binary, name):
    left, right = PAIRS.get(name, (name, name))
    policies = {"a": CASES[left], "b": CASES[right]}
    expected_direct = permits_direct(left, right)
    with Network(binary, ["a", "b", "r", "na", "nb", "w"]) as net:
        topology(net)
        for index, node in enumerate(["a", "b"], 1):
            install(net, "n" + node, f"198.18.{index}.2", *policies[node])
        probe_servers(net)
        measured, filters = {}, {}
        for node in ["a", "b"]:
            mapping, filtering = policies[node]
            measured[node] = mapping_probe(net, node)
            ports = [p[1] for p in measured[node]]
            expected = {"eim": [40000, 40000, 40000], "adm": [40000, 40000, 40001], "apdm": [40000, 40002, 40001]}[mapping]
            assert ports == expected, (mapping, measured[node], expected)
            filters[node] = filtering_probe(net, node)
            allowed = {"eif": ["original", "other-ip", "other-port"], "adf": ["original", "other-port"], "apdf": ["original"]}[filtering]
            assert filters[node] == allowed, (filtering, filters[node], allowed)
        # Do not let the independent measurement probes open application filters.
        for index, node in enumerate(["a", "b"], 1):
            install(net, "n" + node, f"198.18.{index}.2", *policies[node])
            net.ns("n" + node, "conntrack", "-D", "-p", "udp", "--orig-src", "10.77.0.2")
        net.init(["a", "b", "r"])
        for node in net.paths:
            # No explicit public candidates: learn them from the authenticated relay.
            config = f'name = "{node}"\nmax_neighbors = 2\n'
            if node != "r":
                config += f'\n[[peers]]\nendpoint = "{RELAY}:7331"\npublic_key = "{net.ids["r"]}"\n'
            config += '\n[tun]\nname = "nnlan0"\n'
            net.paths[node].write_text(config)
            net.start(node)
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 3 for n in net.paths), "NAT membership")

        initial_boot = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}

        def direct():
            return all(any(p["node"] == net.ids[other] for p in net.rpc(node, "status")["neighbors"]) for node, other in [("a", "b"), ("b", "a")])

        def public_candidates():
            records = net.rpc("a", "peers")
            return all(any(r["record"]["descriptor"]["node"] == net.ids[node] and f"198.18.{index}.2:40000" in r["record"]["descriptor"]["endpoints"] for r in records) for index, node in enumerate(["a", "b"], 1))

        net.wait(public_candidates, "observed NAT candidates")
        assert not direct(), "discovery opened a full mesh before user traffic"
        initial = net.rpc("a", "trace", "b")
        assert initial["complete"] and [h["node"] for h in initial["hops"]] == [net.ids["r"], net.ids["b"]], initial
        started = time.monotonic()
        echoes = 0
        while time.monotonic() - started < (35 if expected_direct else 22):
            echo = net.rpc("a", "ping", "b", "--size", "2048")
            assert echo["hop_encrypted"] and echo["bytes"] == 2048
            echoes += 1
            if direct():
                break
            time.sleep(0.3)
        if direct() != expected_direct:
            evidence = dict(case=name, expected_direct=expected_direct, measured_mapping=measured,
                measured_filtering=filters, status={n: net.rpc(n, "status") for n in net.paths},
                routers={n: dict(rules=net.ns(n, "nft", "-j", "list", "table", "ip", "nat_fixture").stdout,
                    conntrack=net.ns(n, "conntrack", "-L", "-p", "udp").stdout) for n in ["na", "nb"]})
            Path("target/nat-matrix-failure.json").write_text(json.dumps(evidence, indent=2)+"\n")
            raise AssertionError(f"{name}: expected direct={expected_direct}; see target/nat-matrix-failure.json")
        established_ms = round((time.monotonic() - started) * 1000, 1)
        if expected_direct:
            # Generous local-fixture bound, still below the 9 s dead-candidate
            # retry window. Regressing to a self-dial must fail this test.
            assert established_ms < 8000, ("self candidate delayed direct upgrade", name, established_ms)
        trace = net.rpc("a", "trace", "b")
        hops = [net.ids["b"]] if expected_direct else [net.ids["r"], net.ids["b"]]
        assert trace["complete"] and [h["node"] for h in trace["hops"]] == hops, trace
        reverse_trace = net.rpc("b", "trace", "a")
        reverse_hops = [net.ids["a"]] if expected_direct else [net.ids["r"], net.ids["a"]]
        assert reverse_trace["complete"] and [h["node"] for h in reverse_trace["hops"]] == reverse_hops, reverse_trace
        assert net.rpc("b", "ping", "a", "--size", "2048")["hop_encrypted"]
        addresses = net.rpc("b", "status")["address"]
        for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
            net.ns("a", "ping", family, "-n", "-c", "3", "-W", "2", addresses[field])
        for node in net.paths:
            assert len(net.rpc(node, "status")["neighbors"]) <= 2
        result = dict(case=name, models={"a": left, "b": right}, expected_direct=expected_direct, ok=True, measured_mapping=measured, measured_filtering=filters, direct=direct(), trace_hops=len(hops), reverse_trace_hops=len(reverse_hops), dual_stack_tun=True, encrypted_echoes=echoes, observed_ms=established_ms, neighbor_limit=2)
        if left == right == "eim-apdf":
            def ping_direct():
                reply = net.rpc("a", "ping", "b", "--size", "2048")
                return reply["hop_encrypted"] and direct()

            block = net.directory / "direct-block.nft"
            block.write_text("""table inet direct_block {
 chain forward { type filter hook forward priority -10; policy accept;
  ip saddr { 198.18.1.2, 198.18.2.2 } ip daddr { 198.18.1.2, 198.18.2.2 } counter drop
 }
}
""")
            net.ns("w", "nft", "-f", str(block))
            net.wait(lambda: all(all(p["node"] != net.ids[other] for p in net.rpc(node, "status")["neighbors"]) for node, other in [("a", "b"), ("b", "a")]), "failed direct adjacency expires")
            fallback = net.rpc("a", "trace", "b")
            assert fallback["complete"] and [h["node"] for h in fallback["hops"]] == [net.ids["r"], net.ids["b"]], fallback
            assert net.rpc("a", "ping", "b", "--size", "8192")["hop_encrypted"]
            net.ns("w", "nft", "delete", "table", "inet", "direct_block")
            net.wait(ping_direct, "direct path restored after firewall removal", timeout=40)
            result["direct_loss_relay_fallback_and_recovery"] = True

            # Actual kernel conntrack deletion plus a different translated port,
            # not merely changing a descriptor or injecting an observed address.
            install(net, "na", "198.18.1.2", *policies["a"], port_base=41000)
            net.ns("na", "conntrack", "-D", "-p", "udp", "--orig-src", "10.77.0.2")
            net.wait(lambda: any(p["node"] == net.ids["a"] and p["endpoint"] == "198.18.1.2:41000" for p in net.rpc("r", "status")["neighbors"]), "relay observes authenticated NAT rebinding", timeout=40)
            net.wait(lambda: ping_direct() and any(p["node"] == net.ids["a"] and p["endpoint"] == "198.18.1.2:41000" for p in net.rpc("b", "status")["neighbors"]), "restricted NAT direct path recovers after rebinding", timeout=70)
            assert any(p["node"] == net.ids["a"] and p["endpoint"] == "198.18.1.2:41000" for p in net.rpc("b", "status")["neighbors"])
            result["nat_port_rebinding"] = True
            net.crash("r")
            net.wait(lambda: all(all(p["node"] != net.ids["r"] for p in net.rpc(n, "status")["neighbors"]) for n in ["a", "b"]), "bootstrap relay disconnected")
            assert ping_direct()
            independent = net.rpc("a", "trace", "b")
            assert independent["complete"] and [h["node"] for h in independent["hops"]] == [net.ids["b"]]
            for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
                net.ns("a", "ping", family, "-n", "-c", "3", "-W", "2", addresses[field])
            result["bootstrap_relay_offline_dual_stack"] = True
        if (left, right) in [("adm-eif", "apdm-apdf"), ("apdm-apdf", "adm-eif")]:
            # EIF admits a request at the relay-observed port even though its
            # own outgoing mapping is endpoint-dependent. Replies must refresh
            # the actual conntrack binding, not the hypothetical new-flow port.
            net.crash("r")
            # Failed configured-peer retries must not refresh the relay-created
            # binding as a side effect. Drop before NAT classification/learning.
            blocked = net.directory / "bootstrap-block.nft"
            blocked.write_text(f"""table inet bootstrap_block {{
 chain early {{ type filter hook prerouting priority -130; policy accept;
  iifname "lan" ip daddr {RELAY} udp dport 7331 counter drop
 }}
}}
""")
            for router in ["na", "nb"]:
                net.ns(router, "nft", "-f", str(blocked))
            net.wait(lambda: all(all(p["node"] != net.ids["r"] for p in net.rpc(n, "status")["neighbors"]) for n in ["a", "b"]), "heterogeneous bootstrap disconnected")
            start = time.monotonic()
            count = 0
            while time.monotonic() - start < 65: # Exceeds filter (30 s) and record (60 s) TTLs.
                assert direct()
                assert net.rpc("a", "ping", "b", "--size", "2048")["hop_encrypted"]
                assert net.rpc("b", "ping", "a", "--size", "2048")["hop_encrypted"]
                count += 1
                time.sleep(0.5)
            result["bootstrap_offline_seconds"] = time.monotonic() - start
            result["bootstrap_offline_bidirectional_echoes"] = count
            result["bootstrap_retries_blocked_before_nat"] = {n: json.loads(net.ns(n, "nft", "-j", "list", "table", "inet", "bootstrap_block").stdout) for n in ["na", "nb"]}
            result["bindings_after_expiry"] = {n: json.loads(net.ns(n, "nft", "-j", "list", "set", "ip", "nat_fixture", "opened").stdout) for n in ["na", "nb"]}
            for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
                net.ns("a", "ping", family, "-n", "-c", "3", "-W", "2", addresses[field])
            result["heterogeneous_bootstrap_offline_dual_stack"] = True
        assert all(net.rpc(n, "status")["boot_id"] == initial_boot[n] for n in ["a", "b"])
        result["no_endpoint_restart"] = True
        result["final_endpoints"] = {n: net.rpc(n, "status")["neighbors"] for n in ["a", "b"]}
        print(json.dumps(result), flush=True)
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--case", choices=["all", "matrix", *CASES, *PAIRS], default="all", metavar="CASE", help="all: nine homogeneous cases; matrix: 81 ordered pairs; or MODEL+MODEL")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), kernel=platform.release())
    provenance["fixture_sha256"] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ["nat_netns.py", "nat_fixture.py", "netns_fixture.py"]}
    selected = list(PAIRS) if args.case == "matrix" else list(CASES) if args.case == "all" else [args.case]
    report = dict(ok=False, scenarios=[], provenance=provenance, requested_cases=selected)
    def save():
        if args.output:
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
