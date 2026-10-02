#!/usr/bin/env python3
"""Persistent identity policy on a real dual-path, four-daemon TUN overlay."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time
from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                      binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                      fixture_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), Path(__file__).with_name("netns_fixture.py")]})
    with Network(args.binary, ["a", "c", "d", "b"]) as net:
        net.init(["a", "c", "d", "b"])
        peers = {n: [] for n in net.paths}
        for i, (left, right) in enumerate([("a", "c"), ("a", "d"), ("c", "b"), ("d", "b")]):
            net.link(left, right, f"u{i}", f"u{i}", [f"10.140.{i}.1/30", f"10.140.{i}.2/30"])
            peers[left].append(f'[[peers]]\nendpoint = "10.140.{i}.2:7331"\npublic_key = "{net.ids[right]}"\n')
        for name in net.paths:
            net.paths[name].write_text(f'name = "{name}"\nmax_neighbors = 2\n' + "".join(peers[name]))
            net.start(name)
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 4 for n in net.paths), "signed membership")
        addresses = {n: net.rpc(n, "status")["address"] for n in net.paths}
        boot = net.rpc("a", "status")["boot_id"]

        def connected():
            for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
                net.ns("a", "ping", family, "-n", "-c", "1", "-W", "2", addresses["b"][field])
            return True

        connected()
        net.rpc("a", "members", "deny", net.ids["c"])
        net.wait(lambda: net.rpc("a", "trace", "b")["complete"], "alternate return path convergence")
        trace = net.rpc("a", "trace", "b")
        assert trace["complete"] and [h["node"] for h in trace["hops"]] == [net.ids["d"], net.ids["b"]], trace
        connected()
        # Real applications on B send to A; receiver evidence distinguishes
        # discarded requests from merely dropped responses.
        received = net.directory / "received"
        listener = "import socket,sys; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); s.bind(('::',39001)); f=open(sys.argv[1],'a',buffering=1)\nwhile True:\n p,a=s.recvfrom(2048); f.write(a[0]+'\\n')"
        net.spawn("a", ["python3", "-c", listener, str(received)], net.directory / "receiver.log")
        net.wait(received.exists, "application listener")
        sender = "import socket,sys; h=sys.argv[1]; s=socket.socket(socket.AF_INET6 if ':' in h else socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'identity-policy',(h,39001))"

        def application(success):
            for field in ["ipv4", "ipv6"]:
                before = received.read_text()
                net.ns("b", "python3", "-c", sender, addresses["a"][field])
                if success:
                    net.wait(lambda: received.read_text() != before, "allowed application")
                else:
                    time.sleep(0.5)
                    assert received.read_text() == before, "denied identity reached application"

        application(True)
        net.rpc("a", "members", "deny", net.ids["b"])
        for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
            assert not net.ns("a", "ip", family, "route", "show", "exact", addresses["b"][field], "dev", "nnlan0").stdout.strip()
            assert net.ns("a", "ping", family, "-n", "-c", "1", "-W", "1", addresses["b"][field], check=False).returncode != 0
        application(False)
        assert net.ids["b"] in net.rpc("d", "members")["trusted"], "other issuer remains a real alternate endorsement"
        # Force denied C to request a fresh direct connection after the old
        # neighbor has timed out. Configured slots do not bypass identity policy.
        time.sleep(7)
        invalid = net.rpc("a", "status")["invalid_udp"]
        for _ in range(2):
            assert net.cli("c", "ping", net.ids["a"], check=False).returncode != 0
            assert all(p["node"] != net.ids["c"] for p in net.rpc("a", "status")["neighbors"])
        assert net.rpc("a", "status")["invalid_udp"] > invalid, "fresh denied handshake was not exercised"
        application(False)
        assert net.rpc("a", "status")["boot_id"] == boot
        net.crash("a")
        net.start("a")
        net.wait(lambda: net.rpc("a", "status")["nodes"] == 2, "persistent denial on restart")
        assert set(net.rpc("a", "members")["denied"]) == {net.ids["b"], net.ids["c"]}
        net.spawn("a", ["python3", "-c", listener, str(received)], net.directory / "receiver-restarted.log")
        net.rpc("a", "members", "allow", net.ids["b"])
        net.wait(connected, "explicit allowance restores dual-stack route")
        application(True)
        assert net.ids["c"] in net.rpc("a", "members")["denied"]
        # All local anchors disappear: the stale signed A/C/D/B cycle must not
        # keep remote members trusted merely because the records are still live.
        net.rpc("a", "members", "deny", net.ids["d"])
        assert net.rpc("a", "status")["nodes"] == 1
        assert net.rpc("a", "members")["trusted"] == [net.ids["a"]]
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    report = dict(ok=True, alternate_path=True, dual_stack_identity_filter=True, vip_routes_removed=True,
                  persistent_denial=True, explicit_allowance=True, disconnected_cycle_rejected=True, provenance=provenance)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
