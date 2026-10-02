#!/usr/bin/env python3
"""Interface refresh and >16 successive real NAT bindings without daemon restart."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from netns_fixture import Network
from nat_fixture import RELAY, install, topology


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        args.output.unlink(missing_ok=True)
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(), binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest())
    provenance["fixture_sha256"] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ["candidates_netns.py", "nat_fixture.py", "netns_fixture.py"]}
    with Network(args.binary, ["a", "b", "r", "na", "nb", "w"]) as net:
        topology(net)
        for index, router in enumerate(["na", "nb"], 1):
            install(net, router, f"198.18.{index}.2", "eim", "apdf")
        block = net.directory / "churn-block.nft"
        block.write_text('table inet churn_block {\n chain forward { type filter hook forward priority -10; policy accept;\n ip saddr { 198.18.1.2, 198.18.2.2 } ip daddr { 198.18.1.2, 198.18.2.2 } drop\n }\n}\n')
        net.ns("w", "nft", "-f", str(block))
        net.init(["a", "b", "r"])
        for node in net.paths:
            # Keep A/B relayed during churn. A public observation therefore has
            # only R as provenance; B receives A's signed candidate record via R.
            config = f'name = "{node}"\nmax_neighbors = 2\n'
            if node != "r":
                config += f'\n[[peers]]\nendpoint = "{RELAY}:7331"\npublic_key = "{net.ids["r"]}"\n'
            net.paths[node].write_text(config)
            net.start(node)
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 3 for n in net.paths), "churn membership")
        initial_boot = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}

        def descriptor(observer, node):
            return next(p["record"]["descriptor"] for p in net.rpc(observer, "peers") if p["record"]["descriptor"]["node"] == net.ids[node])

        def current_binding(port):
            address = f"198.18.1.2:{port}"
            for observer in ["a", "b"]:
                endpoints = descriptor(observer, "a")["endpoints"]
                if address not in endpoints:
                    return False
                stale = [e for e in endpoints if e.startswith("198.18.1.2:") and e != address]
                assert not stale, (observer, port, endpoints)
                assert len(endpoints) <= 16
            return any(p["node"] == net.ids["a"] and p["endpoint"] == address for p in net.rpc("r", "status")["neighbors"])

        net.wait(lambda: current_binding(40000), "initial public observation")
        updates = []
        for port in range(41000, 41020):
            started = time.monotonic()
            install(net, "na", "198.18.1.2", "eim", "apdf", port_base=port)
            net.ns("na", "conntrack", "-D", "-p", "udp", "--orig-src", "10.77.0.2")
            net.wait(lambda: current_binding(port), f"NAT candidate replacement {port}", timeout=30)
            # Real overlay traffic still works after each mapping replacement.
            echo = net.rpc("a", "ping", "b", "--size", "2048")
            assert echo["hop_encrypted"]
            updates.append(dict(port=port, elapsed_ms=round((time.monotonic()-started)*1000, 1)))
            print(json.dumps(updates[-1]), flush=True)
            # This local, lossless fixture must not need the 6 s dead-peer timer
            # to free old key generations every fourth rebinding.
            assert updates[-1]["elapsed_ms"] < 6000, updates[-1]

        # Address appearance, removal and interface down/up on the relay itself;
        # no observation from a peer can manufacture these host candidates.
        net.ns("r", "ip", "link", "add", "extra0", "type", "dummy")
        net.ns("r", "ip", "addr", "add", "192.0.2.11/32", "dev", "extra0")
        net.ns("r", "ip", "link", "set", "dev", "extra0", "up")
        net.wait(lambda: "192.0.2.11:7331" in descriptor("a", "r")["endpoints"], "new interface host candidate", timeout=12)
        net.ns("r", "ip", "addr", "del", "192.0.2.11/32", "dev", "extra0")
        net.ns("r", "ip", "addr", "add", "192.0.2.12/32", "dev", "extra0")
        def replaced_host():
            endpoints = descriptor("b", "r")["endpoints"]
            return "192.0.2.11:7331" not in endpoints and "192.0.2.12:7331" in endpoints
        net.wait(replaced_host, "removed address withdrawn", timeout=12)
        net.ns("r", "ip", "link", "set", "dev", "extra0", "down")
        net.wait(lambda: "192.0.2.12:7331" not in descriptor("a", "r")["endpoints"], "down interface withdrawn", timeout=12)
        net.ns("r", "ip", "link", "set", "dev", "extra0", "up")
        net.wait(lambda: "192.0.2.12:7331" in descriptor("a", "r")["endpoints"], "up interface reintroduced", timeout=12)
        assert all(net.rpc(n, "status")["boot_id"] == initial_boot[n] for n in net.paths)
        assert len(descriptor("b", "a")["endpoints"]) <= 16
        trace = net.rpc("a", "trace", "b")
        assert trace["complete"] and [h["node"] for h in trace["hops"]] == [net.ids["r"], net.ids["b"]]
        address = net.rpc("b", "status")["address"]
        for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
            net.ns("a", "ping", family, "-c", "3", "-W", "2", address[field])
        net.ns("w", "nft", "delete", "table", "inet", "churn_block")
        def direct_after_churn():
            net.rpc("a", "ping", "b", "--size", "2048")
            return all(any(p["node"] == net.ids[other] for p in net.rpc(node, "status")["neighbors"]) for node, other in [("a", "b"), ("b", "a")])
        net.wait(direct_after_churn, "direct upgrade uses the newest discovered mapping", timeout=35)
        assert any(p["node"] == net.ids["a"] and p["endpoint"] == "198.18.1.2:41019" for p in net.rpc("b", "status")["neighbors"])
        direct_trace = net.rpc("a", "trace", "b")
        assert direct_trace["complete"] and [h["node"] for h in direct_trace["hops"]] == [net.ids["b"]]
        for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
            net.ns("a", "ping", family, "-c", "3", "-W", "2", address[field])
        assert all(net.rpc(n, "status")["boot_id"] == initial_boot[n] for n in net.paths)
        report = dict(direct_upgrade_after_twenty_rebindings=True, ok=True, nat_rebindings=updates, no_daemon_restart=True, signed_remote_candidates_updated=True, candidate_limit=16, interface_add_replace_down_up=True, dual_stack_multihop=True, provenance={**provenance, "finished_at":datetime.now(timezone.utc).isoformat()})
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
