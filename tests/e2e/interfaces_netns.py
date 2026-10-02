#!/usr/bin/env python3
"""Real rtnetlink churn, snapshot failure/timeout, and periodic reconciliation."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time

from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path, default=Path("target/e2e-interfaces.json"))
    args = parser.parse_args()
    report = dict(ok=False, started_at=datetime.now(timezone.utc).isoformat(),
                  kernel=platform.release(), binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  fixture_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                  for name in ["interfaces_netns.py", "netns_fixture.py"]})

    def checkpoint():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(args.output)

    checkpoint()
    with Network(args.binary, ["a", "b"]) as net:
        net.link("a", "b", "wan0", "wan0", ["198.18.44.1/24", "198.18.44.2/24"],
                 ["2001:db8:44::1/64", "2001:db8:44::2/64"])
        net.init(["a", "b"])
        net.paths["b"].write_text('name = "b"\nlisten = "[::]:7331"\n')
        net.paths["a"].write_text('name = "a"\nlisten = "[::]:7331"\n'
                                  'endpoints = ["192.0.2.250:7331"]\n\n[[peers]]\n'
                                  f'endpoint = "198.18.44.2:7331"\npublic_key = "{net.ids["b"]}"\n')
        # Instrument only A's snapshot command, not netns setup or other nodes.
        # All successful snapshots still come from the actual kernel ip command.
        shim = net.directory / "bin"
        shim.mkdir()
        mode = net.directory / "snapshot-mode"
        mode.write_text("slow")
        queries = net.directory / "snapshot-queries.jsonl"
        wrapper = shim / "ip"
        wrapper.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys, time
if sys.argv[1:] == ["-j", "address", "show", "up"]:
    mode = pathlib.Path({str(mode)!r}).read_text()
    with open({str(queries)!r}, "a") as log:
        log.write(json.dumps(dict(at=time.monotonic(), mode=mode, pid=os.getpid())) + "\\n")
    if mode == "fail": sys.exit(1)
    if mode == "slow": time.sleep(60)
os.execv({shutil.which('ip')!r}, [{shutil.which('ip')!r}, *sys.argv[1:]])
''')
        wrapper.chmod(0o755)
        net.start("b")
        net.daemons["a"] = net.spawn("a", ["env", f"PATH={shim}:{os.environ['PATH']}", net.binary,
                                               "--config", str(net.paths["a"]), "run"],
                                    net.paths["a"].with_suffix(".log"))
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 2 for n in net.paths), "membership while initial snapshot is blocked", timeout=1.5)
        boots = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}

        def endpoints():
            peers = net.rpc("b", "peers")
            addresses = next(p["record"]["descriptor"]["endpoints"] for p in peers
                             if p["record"]["descriptor"]["node"] == net.ids["a"])
            assert len(addresses) <= 16 and "192.0.2.250:7331" in addresses, addresses
            return set(addresses)

        def query_log():
            return [json.loads(line) for line in queries.read_text().splitlines()]

        def echo():
            start = time.monotonic()
            assert net.rpc("a", "ping", "b", "--size", "2048")["hop_encrypted"]
            return time.monotonic() - start

        # A blocked initial discovery query is not a prerequisite for the
        # configured bootstrap or its admin socket. The same monitor recovers.
        net.wait(queries.exists, "initial snapshot started", timeout=2)
        initial_query = query_log()[0]
        assert initial_query["mode"] == "slow", initial_query
        assert Path(f"/proc/{initial_query['pid']}").exists(), "initial query must still be blocked"
        report["blocked_startup_echo_seconds"] = echo()
        assert report["blocked_startup_echo_seconds"] < 1
        mode.write_text("ok")
        net.wait(lambda: not Path(f"/proc/{initial_query['pid']}").exists(),
                 "initial timed-out snapshot reaped", timeout=4)
        net.ns("a", "ip", "link", "set", "wan0", "mtu", "1490")
        net.wait(lambda: "198.18.44.1:7331" in endpoints(), "initial discovery recovery", timeout=3)
        report["blocked_startup_recovered_without_restart"] = True
        checkpoint()

        changes = []

        def change(label, commands, present=(), absent=()):
            start = time.monotonic()
            for command in commands:
                net.ns("a", "ip", *command)
            net.wait(lambda: set(present) <= endpoints() and not set(absent) & endpoints(), label, timeout=2)
            elapsed = time.monotonic() - start
            changes.append(dict(change=label, elapsed_seconds=elapsed))
            report["changes"] = changes
            checkpoint()
            assert elapsed < 2, changes[-1]

        change("interface-add", [["link", "add", "extra0", "type", "dummy"],
                                  ["addr", "add", "192.0.2.11/32", "dev", "extra0"],
                                  ["link", "set", "extra0", "up"]], ["192.0.2.11:7331"])
        for index in range(12, 22):
            change(f"replace-{index}", [["addr", "del", f"192.0.2.{index-1}/32", "dev", "extra0"],
                                        ["addr", "add", f"192.0.2.{index}/32", "dev", "extra0"]],
                   [f"192.0.2.{index}:7331"], [f"192.0.2.{index-1}:7331"])
        change("interface-down", [["link", "set", "extra0", "down"]], absent=["192.0.2.21:7331"])
        change("interface-up", [["link", "set", "extra0", "up"]], present=["192.0.2.21:7331"])
        v6 = "[2001:db8:45::1]:7331"
        change("ipv6-add", [["-6", "addr", "add", "2001:db8:45::1/128", "dev", "extra0", "nodad"]], [v6])
        change("ipv6-deprecate", [["-6", "addr", "change", "2001:db8:45::1/128", "dev", "extra0", "preferred_lft", "0"]], absent=[v6])
        change("ipv6-preferred", [["-6", "addr", "change", "2001:db8:45::1/128", "dev", "extra0", "preferred_lft", "forever"]], [v6])
        change("interface-delete", [["link", "del", "extra0"]], absent=[v6, "192.0.2.21:7331"])
        # Observe the real notification subscription, not just quick polling.
        netlink = net.ns("a", "cat", "/proc/net/netlink").stdout
        assert any(row.split()[1] == "0" and int(row.split()[3], 16) & 0x111 == 0x111
                   for row in netlink.splitlines()[1:]), netlink
        report["netlink_subscription"] = netlink

        net.ns("a", "ip", "link", "add", "churn0", "type", "dummy")
        net.ns("a", "ip", "link", "set", "churn0", "up")
        batch = net.directory / "churn.batch"
        batch.write_text("".join(f"addr add 192.0.2.{i}/32 dev churn0\naddr del 192.0.2.{i}/32 dev churn0\n" for i in range(1, 201))
                         + "addr add 192.0.2.88/32 dev churn0\n")
        time.sleep(0.3)
        before = len(query_log())
        start = time.monotonic()
        net.ns("a", "ip", "-batch", str(batch))
        net.wait(lambda: "192.0.2.88:7331" in endpoints(), "burst final state", timeout=2)
        time.sleep(0.3)
        burst_queries = len(query_log()) - before
        assert 1 <= burst_queries <= 12, burst_queries
        report["burst"] = dict(events=401, snapshots=burst_queries, elapsed_seconds=time.monotonic()-start)
        report["burst_echo_seconds"] = echo()
        assert not any(a.startswith("192.0.2.") and a not in {"192.0.2.88:7331", "192.0.2.250:7331"} for a in endpoints())

        # A stuck worker must time out, terminate its child, and leave UDP/TUN live.
        mode.write_text("slow")
        net.ns("a", "ip", "link", "set", "churn0", "mtu", "1400")
        net.wait(lambda: query_log()[-1]["mode"] == "slow", "blocked snapshot started", timeout=2)
        slow_pid = query_log()[-1]["pid"]
        report["during_blocked_snapshot_echo_seconds"] = echo()
        assert report["during_blocked_snapshot_echo_seconds"] < 1
        mode.write_text("ok")
        net.wait(lambda: not Path(f"/proc/{slow_pid}").exists(), "timed-out snapshot child reaped", timeout=4)
        report["timed_out_child_reaped"] = True

        # Snapshot failures expire only dynamic addresses; configured candidates
        # and encrypted traffic remain. Recovery has no notification trigger.
        mode.write_text("fail")
        net.ns("a", "ip", "link", "set", "churn0", "mtu", "1450")
        net.wait(lambda: query_log()[-1]["mode"] == "fail", "snapshot failure started", timeout=3)
        net.wait(lambda: "192.0.2.88:7331" not in endpoints(), "failed dynamic source TTL", timeout=40)
        report["snapshot_failures"] = sum(q["mode"] == "fail" for q in query_log())
        report["during_failed_snapshot_echo_seconds"] = echo()
        mode.write_text("ok")
        start = time.monotonic()
        net.wait(lambda: "192.0.2.88:7331" in endpoints(), "periodic recovery without an event", timeout=18)
        report["periodic_recovery_seconds"] = time.monotonic() - start
        time.sleep(0.5)
        before = len(query_log())
        time.sleep(16)
        quiet_queries = len(query_log()) - before
        assert 1 <= quiet_queries <= 2, quiet_queries
        report["quiet_16_second_snapshots"] = quiet_queries
        for left, right in [("a", "b"), ("b", "a")]:
            address = net.rpc(right, "status")["address"]
            for family, field in [("-4", "ipv4"), ("-6", "ipv6")]:
                net.ns(left, "ping", family, "-c", "3", "-W", "2", address[field])
            trace = net.rpc(left, "trace", right)
            assert trace["complete"] and [h["node"] for h in trace["hops"]] == [net.ids[right]]
        assert all(net.rpc(n, "status")["boot_id"] == boots[n] for n in net.paths)
        report.update(ok=True, no_restart=True, dual_stack_tun=True, snapshot_queries=query_log(),
                      finished_at=datetime.now(timezone.utc).isoformat())
        checkpoint()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
