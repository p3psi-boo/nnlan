#!/usr/bin/env python3
"""Real routed MTU changes, ICMP black holes, asymmetric limits and IPv6 underlay."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from netns_fixture import Network


def counters(net, node):
    lines = net.ns(node, "cat", "/proc/net/snmp").stdout.splitlines()
    names = next(i for i, line in enumerate(lines) if line.startswith("Ip:"))
    values = dict(zip(lines[names].split()[1:], map(int, lines[names+1].split()[1:])))
    result = {key: values[key] for key in ["FragCreates", "ReasmReqds"]}
    ipv6 = dict(line.split() for line in net.ns(node, "cat", "/proc/net/snmp6").stdout.splitlines())
    result.update({key: int(ipv6[key]) for key in ["Ip6FragCreates", "Ip6ReasmReqds"]})
    return result


def icmp_unreachable(net):
    lines = net.ns("r", "cat", "/proc/net/snmp").stdout.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("Icmp:"))
    return dict(zip(lines[index].split()[1:], map(int, lines[index+1].split()[1:])))["OutDestUnreachs"]


def exercise(binary, family):
    with Network(binary, ["a", "b", "r"]) as net:
        v6a = ["2001:db8:1::1/64", "2001:db8:1::fe/64"] if family == 6 else None
        v6b = ["2001:db8:2::fe/64", "2001:db8:2::1/64"] if family == 6 else None
        net.link("a", "r", "eth0", "left", ["192.0.2.1/24", "192.0.2.254/24"], v6a)
        net.link("r", "b", "right", "eth0", ["198.51.100.254/24", "198.51.100.1/24"], v6b)
        net.ns("r", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        for node, gateway in [("a", "192.0.2.254"), ("b", "198.51.100.254")]:
            net.ns(node, "ip", "route", "add", "default", "via", gateway)
        if family == 6:
            net.ns("r", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
            for node, gateway in [("a", "2001:db8:1::fe"), ("b", "2001:db8:2::fe")]:
                net.ns(node, "ip", "-6", "route", "add", "default", "via", gateway)
        net.init(["a", "b"])
        target = "[2001:db8:2::1]:7331" if family == 6 else "198.51.100.1:7331"
        net.paths["a"].write_text(f'name = "a"\nlisten = "[::]:7331"\nmax_neighbors = 1\n[[peers]]\nendpoint = "{target}"\npublic_key = "{net.ids["b"]}"\n')
        net.paths["b"].write_text('name = "b"\nlisten = "[::]:7331"\nmax_neighbors = 1\n')
        baseline = {n: counters(net, n) for n in net.names}
        net.start("b")
        net.start("a")
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 2 for n in net.paths), "PMTU membership")
        boots = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}
        stages = []

        def pmtu(node):
            peers = net.rpc(node, "status")["neighbors"]
            return peers[0]["pmtu"] if peers else {}

        def verify(name, a_limit, b_limit, timeout=40):
            start = time.monotonic()
            def limits():
                return all(pmtu(n).get("confirmed") and high-16 <= pmtu(n)["udp_payload"] <= high for n, high in [("a", a_limit), ("b", b_limit)])
            net.wait(limits, name + " PMTU convergence", timeout=timeout)
            echo = net.rpc("a", "ping", "b", "--size", "16384")
            assert echo["bytes"] == 16384 and echo["hop_encrypted"]
            for left, right in [("a", "b"), ("b", "a")]:
                address = net.rpc(right, "status")["address"]
                for version, key, size in [("-4", "ipv4", "1252"), ("-6", "ipv6", "1232")]:
                    net.ns(left, "ping", version, "-M", "do", "-s", size, "-c", "3", "-i", "0.2", "-W", "2", str(address[key]))
            assert {n: net.rpc(n, "status")["boot_id"] for n in net.paths} == boots
            assert {n: counters(net, n) for n in net.names} == baseline, "IP fragmentation detected"
            result = dict(stage=name, elapsed_ms=round((time.monotonic()-start)*1000, 1), a=pmtu("a"), b=pmtu("b"), encrypted_echo_bytes=echo["bytes"], full_tun_mtu_dual_stack=True, no_ip_fragmentation=True)
            stages.append(result)
            print(json.dumps(result), flush=True)

        verify("initial", 1452, 1452)
        if family == 4:
            # A gets real router-generated ICMP PTB; B gets local EMSGSIZE.
            icmp_before = icmp_unreachable(net)
            net.ns("r", "ip", "link", "set", "right", "mtu", "900")
            net.ns("b", "ip", "link", "set", "eth0", "mtu", "900")
            verify("icmp_and_local_emsgsize", 872, 872)
            assert icmp_unreachable(net) > icmp_before, "router did not generate ICMP PTB"
            assert net.rpc("b", "status")["udp_socket_dropped"] > 0
            stages[-1]["router_generated_icmp"] = True
            stages[-1]["local_send_error_survived"] = True
            # Different one-way ceiling, with NO ICMP error for dropped UDP.
            rules = net.directory / "pmtu.nft"
            rules.write_text('table inet pmtu_test { chain forward { type filter hook forward priority -10; policy accept; ip saddr 198.51.100.1 meta l4proto udp meta length > 700 counter drop; }\n chain output { type filter hook output priority -10; policy accept; ip protocol icmp icmp type destination-unreachable icmp code frag-needed counter drop; }\n}\n')
            net.ns("r", "nft", "-f", str(rules))
            verify("asymmetric_silent_blackhole", 872, 672)
            net.ns("r", "ip", "link", "set", "right", "mtu", "576")
            net.ns("b", "ip", "link", "set", "eth0", "mtu", "576")
            verify("ipv4_minimum_mtu_icmp_filtered", 548, 548)
            drop_counters = net.ns("r", "nft", "list", "table", "inet", "pmtu_test").stdout
            assert "counter packets 0 bytes 0 drop" not in drop_counters, drop_counters
            net.ns("r", "nft", "delete", "table", "inet", "pmtu_test")
            net.ns("r", "ip", "link", "set", "right", "mtu", "1500")
            net.ns("b", "ip", "link", "set", "eth0", "mtu", "1500")
            verify("mtu_growth_without_restart", 1452, 1452, timeout=80)
        else:
            net.ns("r", "ip", "link", "set", "right", "mtu", "1280")
            net.ns("b", "ip", "link", "set", "eth0", "mtu", "1280")
            verify("ipv6_minimum_mtu", 1232, 1232)
        return dict(underlay_family=family, stages=stages, no_restart=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        args.output.unlink(missing_ok=True)
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(), binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), fixture_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ["pmtu_netns.py", "netns_fixture.py"]})
    cases = [exercise(args.binary, family) for family in [4, 6]]
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    report = dict(ok=True, cases=cases, provenance=provenance)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
