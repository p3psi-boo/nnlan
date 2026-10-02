"""Owned namespace/process fixture shared by Linux integration scenarios."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


class Network:
    def __init__(self, binary, names):
        self.binary = str(Path(binary).resolve())
        self.root = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.token = "ge" + uuid.uuid4().hex[:7]
        self.names = {name: f"{self.token}-{name}" for name in names}
        self.created, self.interfaces, self.processes, self.logs = [], [], [], []
        self.temporary = tempfile.TemporaryDirectory(prefix="nnlan-e2e-")
        self.directory = Path(self.temporary.name)
        self.paths, self.ids, self.daemons = {}, {}, {}

    @staticmethod
    def command(argv, *, check=True, timeout=15):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "LC_ALL": "C"})
        if check and result.returncode:
            raise RuntimeError(f"{' '.join(argv)}\n{result.stdout}\n{result.stderr}")
        return result

    def ip(self, *args, **kwargs):
        return self.command(self.root + ["ip", *args], **kwargs)

    def ns(self, name, *args, **kwargs):
        return self.ip("netns", "exec", self.names[name], *args, **kwargs)

    def cli(self, name, *args, **kwargs):
        return self.command(self.root + [self.binary, "--config", str(self.paths[name]), *args], **kwargs)

    def rpc(self, name, *args):
        return json.loads(self.cli(name, *args).stdout)

    @staticmethod
    def wait(check, description, timeout=30):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (RuntimeError, json.JSONDecodeError) as error:
                last = error
            time.sleep(0.15)
        raise AssertionError(f"timed out: {description}\n{last}")

    def __enter__(self):
        try:
            for name in self.names.values():
                self.ip("netns", "add", name)
                self.created.append(name)
                self.ip("-n", name, "link", "set", "lo", "up")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def init(self, names):
        for name in names:
            path = self.directory / name / "nnlan.toml"
            self.command([self.binary, "--config", str(path), "init"])
            self.paths[name] = path
            self.ids[name] = self.cli(name, "identity").stdout.strip()

    def link(self, left, right, leftdev, rightdev, ipv4, ipv6=None):
        index = len(self.interfaces) // 2
        a, b = f"{self.token}{index}l", f"{self.token}{index}r"
        self.ip("link", "add", a, "type", "veth", "peer", "name", b)
        self.interfaces.extend([a, b])
        for pos, (name, original, dev) in enumerate([(left, a, leftdev), (right, b, rightdev)]):
            self.ip("link", "set", original, "netns", self.names[name])
            self.ip("-n", self.names[name], "link", "set", "dev", original, "name", dev)
            self.ip("-n", self.names[name], "address", "add", ipv4[pos], "dev", dev)
            if ipv6:
                self.ip("-n", self.names[name], "-6", "address", "add", ipv6[pos], "dev", dev, "nodad")
            self.ip("-n", self.names[name], "link", "set", "dev", dev, "up")

    def spawn(self, name, args, log):
        self.logs.append(log)
        with log.open("a") as output:
            child = subprocess.Popen(self.root + ["ip", "netns", "exec", self.names[name], *args], stdout=output, stderr=output)
        self.processes.append(child)
        return child

    def start(self, name):
        self.daemons[name] = self.spawn(name, [self.binary, "--config", str(self.paths[name]), "run"], self.paths[name].with_suffix(".log"))

    def crash(self, name):
        # Only this fixture-owned namespace, including any helper processes.
        pids = self.ip("netns", "pids", self.names[name]).stdout.split()
        if pids:
            self.command(self.root + ["kill", "-KILL", *pids])
        self.daemons[name].wait(timeout=5)
        self.wait(lambda: self.ns(name, "ip", "link", "show", "nnlan0", check=False).returncode != 0, "TUN removed")

    def failure_evidence(self, value):
        evidence = {"namespace_prefix": self.token, "error": str(value), "nodes": {}}
        for name in self.paths:
            details = {}
            for command in ["status", "routes"]:
                result = self.cli(name, command, check=False)
                try:
                    details[command] = json.loads(result.stdout)
                except json.JSONDecodeError:
                    details[command] = result.stderr
            for family in ["inet", "arp"]:
                result = self.ns(name, "nft", "-j", "list", "table", family, "nnlan", check=False)
                details[f"firewall_{family}"] = result.stdout
            evidence["nodes"][name] = details
        traffic = self.directory / "traffic.jsonl"
        if traffic.exists():
            evidence["traffic"] = traffic.read_text().splitlines()[-100:]
        Path("target/e2e-failure.json").write_text(json.dumps(evidence, indent=2) + "\n")
        for log in dict.fromkeys(self.logs):
            print(f"--- {log} ---\n{log.read_text()}", flush=True)

    def __exit__(self, kind, value, traceback):
        if kind:
            try:
                self.failure_evidence(value)
            except Exception as error:
                # Diagnostics are best effort; they must never skip teardown or
                # replace the original scenario failure (e.g. an RPC timeout).
                print(f"failure diagnostics: {error}", flush=True)
        try:
            for name in self.created:
                pids = self.ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    self.command(self.root + ["kill", "-TERM", *pids], check=False)
            for child in self.processes:
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            for name in reversed(self.created):
                pids = self.ip("netns", "pids", name, check=False).stdout.split()
                if pids:
                    self.command(self.root + ["kill", "-KILL", *pids], check=False)
                self.ip("netns", "del", name, check=False)
            for child in self.processes:
                child.wait(timeout=3)
            for dev in self.interfaces:
                if self.ip("link", "show", "dev", dev, check=False).returncode == 0:
                    self.ip("link", "del", "dev", dev, check=False)
        finally:
            self.temporary.cleanup()
