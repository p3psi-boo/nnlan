#!/usr/bin/env python3
"""Four real Linux TUN daemons in isolated namespaces; never change host routes.
Run: nix develop --command python3 tests/e2e/overlay_netns.py --binary target/release/nnlan
Requires passwordless sudo (or run as root), iproute2 and Linux TUN support.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import platform
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--collision", action="store_true", help="use public colliding test identities for A and B")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    provenance = {"started_at": datetime.now(timezone.utc).isoformat(),
                  "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "kernel": platform.release()}
    root = [] if os.geteuid() == 0 else ["sudo", "-n"]
    token = "gb" + uuid.uuid4().hex[:7]
    names = [f"{token}-{name}" for name in ["a", "c", "d", "b"]]
    created = []
    interfaces = []
    processes = []
    logs = []

    def command(argv, *, check=True, timeout=15):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "LC_ALL": "C"})
        if check and result.returncode:
            raise RuntimeError(f"{' '.join(argv)}\n{result.stdout}\n{result.stderr}")
        return result

    def ip(*argv, **kwargs):
        return command(root + ["ip", *argv], **kwargs)

    def ns(index, *argv, **kwargs):
        return ip("netns", "exec", names[index], *argv, **kwargs)

    with tempfile.TemporaryDirectory(prefix="nnlan-netns-") as temporary:
        paths = [Path(temporary) / name / "nnlan.toml" for name in ["a", "c", "d", "b"]]

        def cli(index, *argv, **kwargs):
            return command(root + [binary, "--config", str(paths[index]), *argv], **kwargs)

        def rpc(index, *argv):
            return json.loads(cli(index, *argv).stdout)

        try:
            for index, name in enumerate(names):
                ip("netns", "add", name)
                created.append(name)
                ip("-n", name, "link", "set", "lo", "up")
                command([binary, "--config", str(paths[index]), "init"])
            if args.collision:
                fixture = json.loads((Path(__file__).parent.parent / "fixtures/ipv4-collision.json").read_text())
                for index, field in [(0, "seed_a"), (3, "seed_b")]:
                    paths[index].with_name("identity.key").write_bytes(b"GGBKEY1\n" + bytes.fromhex(fixture[field]))
            ids = [cli(i, "identity").stdout.strip() for i in range(4)]
            endpoints = [[] for _ in names]
            for edge in range(3):
                left, right = f"{token}{edge}l", f"{token}{edge}r"
                ip("link", "add", left, "type", "veth", "peer", "name", right)
                interfaces.extend([left, right])
                for index, dev, host in [(edge, left, 1), (edge + 1, right, 2)]:
                    ip("link", "set", dev, "netns", names[index])
                    ip("-n", names[index], "link", "set", dev, "name", f"u{edge}")
                    address = f"10.101.{edge}.{host}"
                    ip("-n", names[index], "address", "add", f"{address}/30", "dev", f"u{edge}")
                    ip("-n", names[index], "link", "set", f"u{edge}", "up")
                    endpoints[index].append(f"{address}:7331")
            for index, path in enumerate(paths):
                peer = ""
                if index < 3:
                    peer = f'\n[[peers]]\nendpoint = "10.101.{index}.2:7331"\npublic_key = "{ids[index + 1]}"\n'
                path.write_text(
                    f'name = "{["a", "c", "d", "b"][index]}"\nlisten = "0.0.0.0:7331"\n'
                    f'max_neighbors = {[1, 2, 2, 1][index]}\nendpoints = {json.dumps(endpoints[index])}\n'
                    + peer + '\n[tun]\nname = "nnlan0"\nenabled = true\nmtu = 1280\n'
                )
                logfile = path.with_suffix(".log")
                logs.append(logfile)
                with logfile.open("w") as output:
                    processes.append(subprocess.Popen(root + ["ip", "netns", "exec", names[index], binary, "--config", str(path), "run"], stdout=output, stderr=output))
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("daemon exited during startup")
                try:
                    status = [rpc(i, "status") for i in range(4)]
                    if all(s["nodes"] == 4 and s["addresses_claimed"] for s in status):
                        break
                except (RuntimeError, json.JSONDecodeError):
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("four-node topology did not converge")
            if args.collision:
                assert status[0]["address"]["ipv4"] != status[3]["address"]["ipv4"], status
                assert max(status[i]["address"]["probe"] for i in [0, 3]) > 0, status
                for index in [0, 3]:
                    addresses = json.loads(ns(index, "ip", "-j", "address", "show", "dev", "nnlan0").stdout)[0]["addr_info"]
                    assert any(a["local"] == status[index]["address"]["ipv4"] for a in addresses), addresses
            target = status[3]["address"]
            trace = rpc(0, "trace", "b")
            assert trace["complete"] and [h["node"] for h in trace["hops"]] == ids[1:], trace
            ipv4 = ns(0, "ping", "-n", "-c", "3", "-W", "3", target["ipv4"]).stdout
            ipv6 = ns(0, "ping", "-6", "-n", "-c", "3", "-W", "3", target["ipv6"]).stdout
            assert re.search(r"\b0% packet loss", ipv4) and re.search(r"\b0% packet loss", ipv6), (ipv4, ipv6)
            echo = rpc(0, "ping", "b", "--size", "16384")
            assert echo["hop_encrypted"], echo
            baseline = sum(peer["link"]["fec_recovered"] for peer in rpc(1, "status")["neighbors"])
            ns(0, "tc", "qdisc", "add", "dev", "u0", "root", "netem", "loss", "8%")
            recovered = 0
            for iteration in range(32):
                result = rpc(0, "ping", "b", "--size", "8192")
                assert result["hop_encrypted"], result
                repaired = rpc(1, "status")
                recovered = sum(peer["link"]["fec_recovered"] for peer in repaired["neighbors"]) - baseline
                if iteration >= 7 and recovered > 0:
                    break
            assert recovered > 0, repaired
            ns(0, "tc", "qdisc", "del", "dev", "u0", "root")
            report = {"ok": True, "collision_test": args.collision, "addresses": [s["address"] for s in status], "trace": trace, "ipv4_ping": ipv4, "ipv6_ping": ipv6, "encrypted_echo": echo, "netem_loss": "8%", "fec_recovered_at_c": recovered}
            provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
            report["provenance"] = provenance
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        except Exception:
            for path in logs:
                print(f"--- {path.name} ({path.parent.name}) ---\n{path.read_text()}", flush=True)
            raise
        finally:
            # Only PIDs currently attached to namespaces created by this invocation.
            for name in created:
                pids = ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    command(root + ["kill", "-TERM", *pids], check=False)
            for process in processes:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            for name in reversed(created):
                pids = ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    command(root + ["kill", "-KILL", *pids], check=False)
                ip("netns", "del", name, check=False)
            for process in processes:
                process.wait(timeout=3)
            for dev in interfaces:
                if ip("link", "show", "dev", dev, check=False).returncode == 0:
                    ip("link", "del", "dev", dev, check=False)


if __name__ == "__main__":
    main()
