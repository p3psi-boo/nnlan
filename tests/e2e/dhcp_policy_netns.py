#!/usr/bin/env python3
"""UID-qualified DHCP exceptions and fail-closed negatives; real DHCP is a VM test."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
from netns_fixture import Network

SERVER = '''import socket,selectors,json,sys
sel=selectors.DefaultSelector()
for family,host,ports in [(socket.AF_INET,"0.0.0.0",[67,68]),(socket.AF_INET6,"::",[547,548])]:
 for port in ports:
  for kind in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
   s=socket.socket(family,kind)
   if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
   s.bind((host,port))
   if kind==socket.SOCK_STREAM:s.listen()
   sel.register(s,selectors.EVENT_READ,kind)
open(sys.argv[2],"w").close()
with open(sys.argv[1],"a",buffering=1) as log:
 while True:
  for key,_ in sel.select():
   if key.data==socket.SOCK_DGRAM:
    data,peer=key.fileobj.recvfrom(2048);key.fileobj.sendto(b"ok",peer)
   else:
    c,peer=key.fileobj.accept();c.sendall(b"ok");c.close()
   log.write(json.dumps({"source":peer[0]})+"\\n")
'''
CLIENT = '''import socket,sys,os
uid,host,source,destination,kind=sys.argv[1:]
os.setgroups([]);os.setgid(int(uid));os.setuid(int(uid))
s=socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,int(kind))
s.settimeout(0.5);s.bind(("::" if ":" in host else "0.0.0.0",int(source)))
s.connect((host,int(destination)))
if int(kind)==socket.SOCK_DGRAM:s.send(b"probe")
assert s.recv(16)==b"ok"
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        args.output.unlink(missing_ok=True)
    provenance = {"started_at": datetime.now(timezone.utc).isoformat(), "kernel": platform.release(),
                  "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  "fixture_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), Path(__file__).with_name("netns_fixture.py")]}}
    with Network(args.binary, ["a", "b"]) as net:
        net.init(["a", "b"])
        net.link("a", "b", "wan", "wan", ["192.0.2.2/24", "192.0.2.1/24"], ["fd10:dc::2/64", "fd10:dc::1/64"])
        net.ns("a", "sysctl", "-qw", "net.ipv4.ip_unprivileged_port_start=0", "net.ipv4.conf.all.rp_filter=1", "net.ipv4.conf.all.src_valid_mark=1")
        log = net.directory / "requests.jsonl"
        ready = net.directory / "ready"
        log.touch()
        net.spawn("b", ["python3", "-c", SERVER, str(log), str(ready)], net.directory / "server.log")
        net.wait(ready.exists, "listener")

        def guard(uid):
            selected = f"dhcp_client_uid = {uid}\n" if uid is not None else ""
            net.paths["a"].write_text(selected + f'[routes]\nexit_node = "{net.ids["b"]}"\n')
            net.ns("a", net.binary, "--config", str(net.paths["a"]), "guard")

        def probe(uid, success, source_delta=0, destination_delta=0, kind=2):
            for host, source, destination in [("192.0.2.1", 68, 67), ("fd10:dc::1", 546, 547)]:
                before = log.read_text()
                result = net.ns("a", "python3", "-c", CLIENT, str(uid), host, str(source + source_delta), str(destination + destination_delta), str(kind), check=False)
                assert (result.returncode == 0) == success, (uid, host, result.stderr)
                net.ns("a", "sleep", "0.05")
                assert (log.read_text() != before) == success, (uid, host, "receiver evidence")

        guard(None)
        probe(123, False)
        guard(123)
        probe(123, True)
        probe(124, False)
        probe(123, False, source_delta=1)
        probe(123, False, destination_delta=1)
        probe(123, False, kind=1)
        # Remove the policy routing barrier: nft must independently enforce UID/ports.
        for family in ["-4", "-6"]:
            net.ns("a", "ip", family, "route", "flush", "table", "33033")
        probe(124, False)
        probe(123, False, source_delta=1)
        probe(123, False, destination_delta=1)
        probe(123, False, kind=1)
        probe(123, True)
        guard(124)
        probe(123, False)
        probe(124, True)
        guard(124)
        for family in ["-4", "-6"]:
            rules = json.loads(net.ns("a", "ip", family, "-j", "rule", "show").stdout)
            owned = [r for r in rules if r.get("priority") == 23332]
            assert len(owned) == 1 and owned[0]["uid_start"] == owned[0]["uid_end"] == 124
        guard(None)
        probe(124, False)
        for family in ["-4", "-6"]:
            assert "23332" not in net.ns("a", "ip", family, "rule", "show").stdout
    provenance["finished_at"] = datetime.now(timezone.utc).isoformat()
    report = {"ok": True, "dual_stack_uid_port_protocol_filtering": True, "strict_rpf_reply": True,
              "routing_table_deletion": True, "uid_change_removal_idempotence": True, "provenance": provenance}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
