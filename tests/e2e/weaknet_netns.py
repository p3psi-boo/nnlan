#!/usr/bin/env python3
"""Four outgoing repair policies over real dual-stack TUN and kernel netem."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

from netns_fixture import Network

HERE = Path(__file__).resolve().parent
# Faults affect encrypted underlay datagrams, not selected plaintext frame types.
PROFILES = {
    "clean": ([], []),
    "random_loss": (["loss", "random", "5%"], []),
    "burst_loss": (["loss", "gemodel", "3%", "40%", "90%", "0.1%"], []),
    "reordering": (["delay", "30ms", "reorder", "25%", "50%"], []),
    "duplication": (["duplicate", "15%"], []),
    "reverse_loss": ([], ["loss", "random", "60%"]),
    "rate_limit": (["delay", "20ms", "rate", "1mbit"], []),
    "mixed": (["delay", "20ms", "8ms", "distribution", "normal", "loss", "4%", "reorder", "20%", "duplicate", "3%", "rate", "3mbit"], []),
}
MODES = {"both": (True, True), "fec_only": (True, False), "rtx_only": (False, True), "neither": (False, False)}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def trial(net, policy, profile, args, pids):
    before = {n: net.rpc(n, "status") for n in net.paths}
    for n, fault in zip(["a", "b"], PROFILES[profile]):
        net.ns(n, "tc", "qdisc", "replace", "dev", "wan", "root", "netem", "limit", "128", *(fault or ["delay", "0ms"]), "seed", str(args.seed))
    result_path = net.directory / f"{profile}-receive.json"
    tag = os.urandom(8).hex()
    address = before["b"]["address"]
    common = ["--ipv4", address["ipv4"], "--ipv6", address["ipv6"], "--tag", tag, "--count", str(args.count)]
    receiver = net.spawn("b", [sys.executable, str(HERE / "weaknet_traffic.py"), "receive", *common, "--output", str(result_path)], net.directory / f"{profile}-receive.log")
    net.wait(lambda: result_path.with_suffix(".ready").exists(), "UDP receivers ready")
    sent_path = net.directory / f"{profile}-send.json"
    sender = net.spawn("a", [sys.executable, str(HERE / "weaknet_traffic.py"), "send", *common, "--output", str(sent_path)], net.directory / f"{profile}-send.log")
    peaks = {n: dict(in_flight=0, queued_bytes=0, rss_kib=0) for n in net.paths}
    deadline = time.monotonic() + args.count * 0.01 + 12
    while receiver.poll() is None:
        assert time.monotonic() < deadline, "traffic receiver deadline"
        for n in net.paths:
            status = net.rpc(n, "status")
            assert status["boot_id"] == before[n]["boot_id"]
            assert len(status["neighbors"]) == 1, "adjacency lost in bounded weak-link trial"
            link = status["neighbors"][0]["link"]
            assert link["repair"] == policy
            assert link["in_flight"] <= 2048 and link["queued_bytes"] <= (2048+128)*1280
            for metric in ["in_flight", "queued_bytes"]:
                peaks[n][metric] = max(peaks[n][metric], link[metric])
            rss = next(line.split()[1] for line in Path(f"/proc/{pids[n]}/status").read_text().splitlines() if line.startswith("VmRSS:"))
            peaks[n]["rss_kib"] = max(peaks[n]["rss_kib"], int(rss))
        time.sleep(0.25)
    assert receiver.returncode == 0, "UDP receiver rejected payload"
    sender.wait(timeout=3)
    assert sender.returncode == 0
    traffic = json.loads(result_path.read_text())
    after = {n: net.rpc(n, "status") for n in net.paths}
    qdiscs = {n: json.loads(net.ns(n, "tc", "-s", "-j", "qdisc", "show", "dev", "wan").stdout) for n in net.paths}
    counters = {}
    for n in net.paths:
        old, new = (s[n]["neighbors"][0]["link"] for s in [before, after])
        counters[n] = {key: new[key]-old[key] for key in ["original_sent", "fec_sent", "fec_recovered", "retransmitted", "queue_dropped", "expired_sources", "tx_wire_bytes", "rx_wire_bytes"]}
        assert all(v >= 0 for v in counters[n].values()), "link epoch changed"
        if not policy["fec"]:
            assert counters[n]["fec_sent"] == 0
        if not policy["rtx"]:
            assert counters[n]["retransmitted"] == 0
    for family, stream in traffic.items():
        assert stream["received"] > 0 and stream["duplicates"] == 0
        assert all(s["source"] == before["a"]["address"]["ipv"+family] for s in stream["samples"].values())
        if profile == "clean":
            assert stream["received"] == args.count
        if profile in ["reordering", "duplication", "reverse_loss"]:
            assert stream["received"] >= args.count * 0.95, "no forward loss: controller failed to sustain this offered load"
        if profile in ["random_loss", "burst_loss"]:
            assert stream["received"] >= args.count * 0.8, "delivery far below injected loss level"
    if profile == "reordering":
        assert sum(t["reordered"] for t in traffic.values()) > 0, "reordering did not reach the application"
    if profile == "duplication":
        assert after["b"]["invalid_udp"] > before["b"]["invalid_udp"], "no duplicate ciphertext rejected"
    if profile in ["random_loss", "burst_loss", "reverse_loss"]:
        assert sum(q.get("drops", 0) for queues in qdiscs.values() for q in queues) > 0, "fault did not drop datagrams"
    for n in net.paths:
        net.ns(n, "tc", "qdisc", "del", "dev", "wan", "root")
    # Fault removal must restore actual application traffic without a restart.
    net.wait(lambda: net.rpc("a", "ping", "b", "--size", "2048")["hop_encrypted"], "post-fault encrypted echo")
    for family in [4, 6]:
        net.ns("a", "ping", f"-{family}", "-n", "-c", "2", "-W", "3", address[f"ipv{family}"])
    return dict(profile=profile, policy=policy, traffic=traffic, sent=json.loads(sent_path.read_text()),
                counters=counters, peaks=peaks, qdiscs=qdiscs, before=before, after=after,
                restored_dual_stack=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--mode", choices=["all", *MODES], default="all")
    parser.add_argument("--profile", choices=["all", *PROFILES], default="all")
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--seed", type=int, default=31415)
    parser.add_argument("--output", type=Path, default=Path("target/e2e-weaknet.json"))
    args = parser.parse_args()
    assert 100 <= args.count <= 1000
    args.output.parent.mkdir(parents=True, exist_ok=True)
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
        binary_sha256=sha(args.binary), fixture_sha256={p: sha(HERE/p) for p in ["weaknet_netns.py", "weaknet_traffic.py", "netns_fixture.py"]}, count_per_family=args.count, seed=args.seed)
    report = dict(ok=False, scope="two real daemons/TUN/netns; same-kernel one-way timestamps; kernel netem; both IP families; not a throughput acceptance gate", provenance=provenance, scenarios=[])
    save(args.output, report)
    for mode in MODES if args.mode == "all" else [args.mode]:
        fec, rtx = MODES[mode]
        policy = dict(fec=fec, rtx=rtx)
        with Network(args.binary, ["a", "b"]) as net:
            net.init(["a", "b"])
            net.link("a", "b", "wan", "wan", ["10.151.0.1/30", "10.151.0.2/30"])
            for n in net.paths:
                peer = f'[[peers]]\nendpoint = "10.151.0.2:7331"\npublic_key = "{net.ids["b"]}"\n' if n == "a" else ''
                net.paths[n].write_text(f'name = "{n}"\nmax_neighbors = 1\n{peer}\n[repair]\nfec = {str(fec).lower()}\nrtx = {str(rtx).lower()}\n')
                net.start(n)
            net.wait(lambda: all(net.rpc(n,"status")["nodes"] == 2 for n in net.paths), "membership")
            net.wait(lambda: all((p := net.rpc(n,"status")["neighbors"][0]["pmtu"])["udp_payload"] == p.get("maximum_udp_payload", 1232) for n in net.paths), "initial PMTU")
            net.rpc("a", "ping", "b", "--size", "2048")
            pids = {n: next(int(p) for p in net.ip("netns", "pids", net.names[n]).stdout.split() if Path(f"/proc/{p}/comm").read_text().strip() == args.binary.name[:15]) for n in net.paths}
            for profile in PROFILES if args.profile == "all" else [args.profile]:
                time.sleep(1.1) # Retire earlier sources before counter subtraction.
                result = trial(net, policy, profile, args, pids)
                report["scenarios"].append(result)
                save(args.output, report)
                print(json.dumps(dict(mode=mode, profile=profile, received={f: t["received"] for f,t in result["traffic"].items()}, counters=result["counters"])), flush=True)
    if args.profile == "all":
        for mode in MODES if args.mode == "all" else [args.mode]:
            fec, rtx = MODES[mode]
            rows = [r for r in report["scenarios"] if r["policy"] == dict(fec=fec, rtx=rtx)]
            if fec:
                assert sum(r["counters"]["b"]["fec_recovered"] for r in rows) > 0
            if rtx:
                assert sum(r["counters"]["a"]["retransmitted"] for r in rows) > 0
    report["ok"] = True
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    save(args.output, report)


if __name__ == "__main__":
    main()
