#!/usr/bin/env python3
"""Real duplicate IPv4/IPv6 LANs, manual publisher choice and crash fail-closed.
Only changes namespaces created here; all application traffic uses actual TUN.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import platform
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    provenance = {"started_at": datetime.now(timezone.utc).isoformat(),
                  "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "kernel": platform.release()}
    root = [] if os.geteuid() == 0 else ["sudo", "-n"]
    token = "gs" + uuid.uuid4().hex[:7]
    names = {name: f"{token}-{name}" for name in ["a", "b", "c", "la", "lb", "lc"]}
    created, interfaces, processes, logs = [], [], [], []
    prefixes = ["192.168.77.0/24", "fd77::/64"]
    hosts = ["192.168.77.10", "fd77::10"]
    specifics = ["192.168.77.10/32", "fd77::10/128"]

    def command(argv, *, check=True, timeout=15):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "LC_ALL": "C"})
        if check and result.returncode:
            raise RuntimeError(f"{' '.join(argv)}\n{result.stdout}\n{result.stderr}")
        return result

    def ip(*argv, **kwargs):
        return command(root + ["ip", *argv], **kwargs)

    def ns(name, *argv, **kwargs):
        return ip("netns", "exec", names[name], *argv, **kwargs)

    def wait_for(check, description, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (RuntimeError, json.JSONDecodeError):
                pass
            time.sleep(0.15)
        raise AssertionError(f"timed out: {description}")

    with tempfile.TemporaryDirectory(prefix="nnlan-subnet-") as temporary:
        paths = {name: Path(temporary) / name / "nnlan.toml" for name in ["a", "b", "c"]}
        daemons = {}

        def cli(name, *argv, **kwargs):
            return command(root + [binary, "--config", str(paths[name]), *argv], **kwargs)

        def rpc(name, *argv):
            return json.loads(cli(name, *argv).stdout)

        def spawn(name, argv, logpath):
            logs.append(logpath)
            with logpath.open("a") as output:
                child = subprocess.Popen(root + ["ip", "netns", "exec", names[name], *argv], stdout=output, stderr=output)
            processes.append(child)
            return child

        def start(name):
            daemons[name] = spawn(name, [binary, "--config", str(paths[name]), "run"], paths[name].with_suffix(".log"))

        def crash(name):
            pids = ip("netns", "pids", names[name]).stdout.split()
            assert pids, f"missing daemon {name}"
            command(root + ["kill", "-KILL", *pids])
            daemons[name].wait(timeout=5)
            wait_for(lambda: ns(name, "ip", "link", "show", "nnlan0", check=False).returncode != 0, "TUN removal")

        def link(left, right, leftdev, rightdev, v4, v6=None):
            index = len(interfaces) // 2
            a, b = f"{token}{index}l", f"{token}{index}r"
            ip("link", "add", a, "type", "veth", "peer", "name", b)
            interfaces.extend([a, b])
            for pos, (name, original, dev) in enumerate([(left, a, leftdev), (right, b, rightdev)]):
                ip("link", "set", original, "netns", names[name])
                ip("-n", names[name], "link", "set", original, "name", dev)
                ip("-n", names[name], "address", "add", v4[pos], "dev", dev)
                if v6:
                    ip("-n", names[name], "-6", "address", "add", v6[pos], "dev", dev, "nodad")
                ip("-n", names[name], "link", "set", dev, "up")

        request = '''import socket,sys,json
s=socket.create_connection((sys.argv[1],8080),1.5)
s.settimeout(1.5)
s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
data=b""
while True:
 b=s.recv(4096)
 if not b: break
 data+=b
print(data.split(b"\\r\\n\\r\\n",1)[1].decode())
'''
        server = '''import socket,sys,json,threading
name=sys.argv[1]
def serve(family,host):
 s=socket.socket(family,socket.SOCK_STREAM)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,8080));s.listen(20)
 while True:
  c,a=s.accept()
  try:
   c.settimeout(2);c.recv(4096)
   body=json.dumps(dict(lan=name,source=a[0],payload="subnet-test-"*4096)).encode()
   c.sendall(b"HTTP/1.0 200 OK\\r\\nContent-Length: "+str(len(body)).encode()+b"\\r\\n\\r\\n"+body)
  except OSError: pass
  finally: c.close()
threading.Thread(target=serve,args=(socket.AF_INET,"0.0.0.0"),daemon=True).start()
serve(socket.AF_INET6,"::")
'''

        def application(host, *, blocked=False):
            result = ns("a", "python3", "-c", request, host, check=False, timeout=5)
            if blocked:
                assert result.returncode != 0, f"traffic leaked: {result.stdout}"
                return True
            if result.returncode:
                raise RuntimeError(result.stderr)
            body = json.loads(result.stdout)
            assert body.pop("payload") == "subnet-test-" * 4096
            return body

        def expect(lan):
            for host in hosts:
                result = application(host)
                assert result["lan"] == lan, result
                assert result["source"] == ("192.168.77.1" if ":" not in host else "fd77::1"), result
            return True

        def accepted(via, *, replace=False):
            for prefix in prefixes:
                rpc("a", "routes", "accept", prefix, "--via", via, *(["--replace"] if replace else []))

        try:
            for name in names:
                ip("netns", "add", names[name]); created.append(names[name])
                ip("-n", names[name], "link", "set", "lo", "up")
            for name, path in paths.items():
                command([binary, "--config", str(path), "init"])
            ids = {name: cli(name, "identity").stdout.strip() for name in paths}
            link("a", "b", "ub", "ua", ["10.112.0.1/30", "10.112.0.2/30"])
            link("b", "c", "uc", "ua", ["10.112.1.1/30", "10.112.1.2/30"])
            for name in paths:
                link(name, "l" + name, "lan", "eth0", ["192.168.77.1/24", "192.168.77.10/24"], ["fd77::1/64", "fd77::10/64"])
                spawn("l" + name, ["python3", "-u", "-c", server, name], Path(temporary) / f"lan-{name}.log")
            for name, path in paths.items():
                peers = ""
                if name in ["a", "b"]:
                    index, target = (0, "b") if name == "a" else (1, "c")
                    peers += f'\n[[peers]]\nendpoint = "10.112.{index}.2:7331"\npublic_key = "{ids[target]}"\n'
                if name in ["b", "c"]:
                    ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
                path.write_text(f'name = "{name}"\nmax_neighbors = {2 if name == "b" else 1}\n' + peers + '\n[tun]\nname = "nnlan0"\n')
                start(name)
            wait_for(lambda: all(rpc(n, "status")["nodes"] == 3 for n in paths), "membership")
            for name in ["b", "c"]:
                for prefix in prefixes:
                    rpc(name, "routes", "advertise", prefix)
            def advertised():
                entries = rpc("a", "routes")["advertised"]
                return all(any(e["via"] == ids[n] and all(p in e["prefixes"] for p in prefixes) for e in entries) for n in ["b", "c"])
            wait_for(advertised, "both LAN publishers")
            expect("a")  # Advertisement alone changes no local routing.
            accepted("b"); expect("b")
            for prefix in prefixes:
                assert cli("a", "routes", "accept", prefix, "--via", "c", check=False).returncode != 0
            expect("b")
            def specific_advertised(prefix, present=True):
                return any(e["via"] == ids["c"] and (prefix in e["prefixes"]) == present for e in rpc("a", "routes")["advertised"])
            for prefix in specifics:
                rpc("c", "routes", "advertise", prefix)
                wait_for(lambda: specific_advertised(prefix), "specific prefix advertisement")
                rpc("a", "routes", "accept", prefix, "--via", "c")
            expect("c")
            rpc("c", "routes", "withdraw", specifics[0])
            wait_for(lambda: specific_advertised(specifics[0], False), "specific withdrawal")
            application(hosts[0], blocked=True)  # Never fall through to healthy broader B.
            assert application(hosts[1])["lan"] == "c"
            for prefix in specifics:
                rpc("a", "routes", "reject", prefix)
            expect("b")
            rpc("b", "routes", "withdraw", prefixes[0])
            wait_for(lambda: not any(e["via"] == ids["b"] and prefixes[0] in e["prefixes"] for e in rpc("a", "routes")["advertised"]), "withdrawal")
            assert next(r for r in rpc("a", "routes")["selected"] if r["prefix"] == prefixes[0])["state"] == "blocked"
            application(hosts[0], blocked=True)
            assert application(hosts[1])["lan"] == "b"
            rpc("b", "routes", "advertise", prefixes[0]); wait_for(advertised, "re-advertisement")
            expect("b")
            accepted("c", replace=True); expect("c")
            rpc("a", "members", "deny", ids["c"])
            assert all(r["via"] == ids["c"] and r["state"] == "blocked" for r in rpc("a", "routes")["selected"])
            for host in hosts:
                application(host, blocked=True)
            assert all(r["via"] == ids["c"] for r in rpc("a", "routes")["accepted"])
            rpc("a", "members", "allow", ids["c"])
            wait_for(lambda: expect("c"), "explicit subnet publisher allowance")
            trace = rpc("a", "trace", "c")
            assert trace["complete"] and [h["node"] for h in trace["hops"]] == [ids["b"], ids["c"]], trace
            crash("c")
            for host in hosts:
                application(host, blocked=True)
            start("c"); wait_for(lambda: expect("c"), "selected router restart", timeout=30)
            # Exercise restart parsing of iproute2's host-route JSON representation.
            for prefix in specifics:
                rpc("c", "routes", "advertise", prefix)
                wait_for(lambda: specific_advertised(prefix), "specific re-advertisement")
                rpc("a", "routes", "accept", prefix, "--via", "c")
            crash("a")
            for host in hosts:
                application(host, blocked=True)
            # Unrelated physical LAN traffic still works: only selected prefixes blocked.
            ns("a", "ping", "-n", "-c", "1", "-W", "1", "10.112.0.2")
            start("a"); wait_for(lambda: expect("c"), "client restart and persistent choice", timeout=30)
            assert all(r["via"] == ids["c"] for r in rpc("a", "routes")["accepted"])
            crash("a")
            # Prove nft protection independently, not merely the blackhole route.
            for family in ["-4", "-6"]:
                ns("a", "ip", family, "route", "flush", "table", "33033")
            for host in hosts:
                application(host, blocked=True)
            start("a"); wait_for(lambda: expect("c"), "restart after route removal", timeout=30)
            for prefix in prefixes + specifics:
                rpc("a", "routes", "reject", prefix)
            expect("a")
            report = {"ok": True, "dual_stack": True, "same_prefix_publishers": [ids["b"], ids["c"]], "advertisements_require_acceptance": True, "explicit_replace": True, "withdrawal_blocks_without_fallback": True, "router_restart": True, "client_sigkill_guard": True, "nft_guard_without_routes": True, "selection_persisted": True, "explicit_reject_restores_local_lan": True, "masquerade_verified": True, "subnet_multihop": True, "longest_prefix_fail_closed": True, "tcp_payload_bytes": 11 * 4096}
            provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
            report["denied_publisher_fail_closed"] = True
            report["provenance"] = provenance
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        except Exception:
            for path in dict.fromkeys(logs):
                print(f"--- {path} ---\n{path.read_text()}", flush=True)
            raise
        finally:
            for name in created:
                pids = ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    command(root + ["kill", "-TERM", *pids], check=False)
            for child in processes:
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            for name in reversed(created):
                pids = ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    command(root + ["kill", "-KILL", *pids], check=False)
                ip("netns", "del", name, check=False)
            for child in processes:
                child.wait(timeout=3)
            for dev in interfaces:
                if ip("link", "show", "dev", dev, check=False).returncode == 0:
                    ip("link", "del", "dev", dev, check=False)


if __name__ == "__main__":
    main()
