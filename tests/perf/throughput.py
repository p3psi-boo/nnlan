#!/usr/bin/env python3
"""Real TUN goodput, per-daemon CPU, loaded ICMP RTT and optional scoped perf."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "e2e"))
from netns_fixture import Network

CASES = ["physical_ipv4", "overlay_ipv4", "overlay_ipv6", "overlay_ipv4_reverse"]


def ticks(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, report):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def latency(text):
    # ping's '<' samples are upper bounds, not exact values; preserve raw output.
    samples = sorted(float(v) for v in re.findall(r"time[=<]([0-9.]+) ms", text))
    return dict(samples=len(samples), rtt_ms={f"p{p:g}": samples[max(0, math.ceil(len(samples)*p/100)-1)] if samples else None for p in [50, 99, 99.9]}, raw=text)


def measure(net, pids, args, case, host, repeat):
    command = ["iperf3", "-c", host, "-J", "--get-server-output"]
    if case.endswith("_reverse"):
        command.append("-R")
    warm = None
    if args.warmup:
        warm = json.loads(net.ns("a", *command, "-t", str(args.warmup), timeout=args.warmup+20).stdout)
        assert "error" not in warm, warm
    profile = None
    profile_path = args.output.with_suffix(f".{repeat}.{case}.perf.data").resolve()
    if args.perf:
        profile = net.spawn("a", [str(args.perf.resolve()), "record", "-e", "cpu-clock", "-F", "199", "--call-graph", "dwarf,4096", "-p", ",".join(str(p) for p in pids.values()), "-o", str(profile_path), "--", "sleep", str(args.seconds+2)], net.directory / f"perf-{repeat}-{case}.log")
        time.sleep(0.2)
        assert profile.poll() is None, "perf did not start; inspect fixture logs"
    ping_log = net.directory / f"ping-{repeat}-{case}.log"
    ping = net.spawn("a", ["ping", "-6" if ":" in host else "-4", "-n", "-i", "0.02", "-c", str(args.seconds*50), "-W", "2", host], ping_log)
    qdisc_before = ({n: json.loads(net.ns(n, "tc", "-s", "-j", "qdisc", "show", "dev", "wan").stdout) for n in pids}
                    if getattr(args, "underlay_mbps", None) else None)
    before = {n: net.rpc(n, "status") for n in pids}
    cpu = {n: ticks(pid) for n, pid in pids.items()}
    start = time.monotonic()
    trial = json.loads(net.ns("a", *command, "-t", str(args.seconds), timeout=args.seconds+20).stdout)
    elapsed = time.monotonic() - start
    end_cpu = {n: ticks(pid) for n, pid in pids.items()}
    assert "error" not in trial, trial
    after = {n: net.rpc(n, "status") for n in pids}
    qdisc_after = ({n: json.loads(net.ns(n, "tc", "-s", "-j", "qdisc", "show", "dev", "wan").stdout) for n in pids}
                   if getattr(args, "underlay_mbps", None) else None)
    assert all(before[n]["boot_id"] == after[n]["boot_id"] for n in pids)
    ping.wait(timeout=5)
    assert ping.returncode in [0, 1], ping_log.read_text()
    if profile:
        profile.wait(timeout=5)
        assert profile.returncode == 0, "perf capture failed"
    return dict(case=case, repeat=repeat, seconds=elapsed,
                receiver_mbps=trial["end"]["sum_received"]["bits_per_second"] / 1e6,
                daemon_cpu_percent={n: (end_cpu[n]-cpu[n]) / os.sysconf("SC_CLK_TCK") / elapsed * 100 for n in pids},
                loaded_icmp=latency(ping_log.read_text()), profile=str(profile_path) if profile else None,
                before=before, after=after, qdisc_before=qdisc_before, qdisc_after=qdisc_after,
                warmup_iperf=warm, iperf=trial)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=15)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--case", choices=["all", *CASES], default="all")
    parser.add_argument("--underlay-mbps", type=int, help="shape both fixture WAN egresses with TBF; not a physical NIC measurement")
    parser.add_argument("--perf", type=Path, help="optional perf executable; samples only fixture daemon PIDs")
    parser.add_argument("--output", type=Path, default=Path("target/perf-throughput.json"))
    args = parser.parse_args()
    assert 3 <= args.seconds <= 300 and 0 <= args.warmup <= 300 and 1 <= args.repeats <= 20
    assert args.underlay_mbps is None or 1 <= args.underlay_mbps <= 100_000
    args.output.parent.mkdir(parents=True, exist_ok=True)
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                      binary_sha256=digest(args.binary), fixture_sha256=digest(__file__),
                      helper_sha256=digest(Path(__file__).resolve().parents[1] / "e2e/netns_fixture.py"),
                      cpu_model=next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
                      logical_cpus=os.cpu_count(), loadavg=os.getloadavg(), arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()})
    report = dict(complete=False, scope="same-host veth/TUN, no CPU pinning, default FEC+RTX, one TCP stream and 50 ICMP/s; warmup excluded from measurement; not an acceptance gate", provenance=provenance, results=[])
    save(args.output, report)
    with Network(args.binary, ["a", "b"]) as net:
        net.init(["a", "b"])
        net.link("a", "b", "wan", "wan", ["10.141.0.1/30", "10.141.0.2/30"], ["fd10:141::1/64", "fd10:141::2/64"])
        if args.underlay_mbps is not None:
            # Only fixture-owned veths. Budget 5 ms of bytes for token-bucket bursts;
            # keep the byte queue bounded to another 20 ms of configured capacity.
            rate = args.underlay_mbps * 1_000_000
            burst = max(65_536, rate // 8 // 200)
            for n in ["a", "b"]:
                net.ns(n, "tc", "qdisc", "add", "dev", "wan", "root", "tbf",
                       "rate", f"{args.underlay_mbps}mbit", "burst", str(burst), "latency", "20ms")
            report["underlay_shaping"] = dict(rate_mbps=args.underlay_mbps, burst_bytes=burst,
                                                latency_ms=20, directions="both", qdisc={
                n: json.loads(net.ns(n, "tc", "-s", "-j", "qdisc", "show", "dev", "wan").stdout)
                for n in ["a", "b"]})
            save(args.output, report)
        net.paths["a"].write_text(f'name = "a"\nmax_neighbors = 1\n[[peers]]\nendpoint = "10.141.0.2:7331"\npublic_key = "{net.ids["b"]}"\n')
        net.paths["b"].write_text('name = "b"\nmax_neighbors = 1\n')
        for n in net.paths:
            net.start(n)
        net.wait(lambda: all(net.rpc(n, "status")["nodes"] == 2 for n in net.paths), "overlay membership")
        pids = {n: next(int(pid) for pid in net.ip("netns", "pids", net.names[n]).stdout.split() if Path(f"/proc/{pid}/comm").read_text().strip().startswith("nnlan")) for n in net.paths}
        net.spawn("b", ["iperf3", "-s"], net.directory / "iperf-server.log")
        net.wait(lambda: "5201" in net.ns("b", "ss", "-ln", "-t").stdout, "iperf server")
        addresses = net.rpc("b", "status")["address"]
        hosts = dict(physical_ipv4="10.141.0.2", overlay_ipv4=addresses["ipv4"], overlay_ipv6=addresses["ipv6"], overlay_ipv4_reverse=addresses["ipv4"])
        cases = CASES if args.case == "all" else [args.case]
        for repeat in range(args.repeats):
            offset = repeat % len(cases)
            for case in cases[offset:] + cases[:offset]:
                result = measure(net, pids, args, case, hosts[case], repeat)
                report["results"].append(result)
                save(args.output, report)
                print(json.dumps({k: result[k] for k in ["case", "repeat", "receiver_mbps", "daemon_cpu_percent"]} | {"rtt_ms": result["loaded_icmp"]["rtt_ms"]}), flush=True)
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["complete"] = True
    save(args.output, report)


if __name__ == "__main__":
    main()
