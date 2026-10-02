#!/usr/bin/env python3
"""Idle shortcut reclamation, capacity reuse and concurrent topology protection."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from netns_fixture import Network

IDLE = 60  # Production constant, not a shortened test-only timeout.


def setup(net, nodes, limit):
    for index, node in enumerate(nodes, 1):
        net.link(node, "r", "wan0", f"peer{index}", [f"198.18.{index}.2/24", f"198.18.{index}.1/24"])
        net.ns(node, "ip", "route", "add", "default", "via", f"198.18.{index}.1")
    # The relay process is independent of the fixture's physical IP router.
    net.ns("r", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    net.init([*nodes, "r"])
    net.paths["r"].write_text(f'name = "r"\nmax_neighbors = {len(nodes)}\n')
    net.start("r")
    for index, node in enumerate(nodes, 1):
        net.paths[node].write_text(f'name = "{node}"\nmax_neighbors = {limit}\n[[peers]]\nendpoint = "198.18.{index}.1:7331"\npublic_key = "{net.ids["r"]}"\n')
        net.start(node)
    net.wait(lambda: all(net.rpc(n, "status")["nodes"] == len(nodes)+1 for n in net.paths), "initial signed membership")


def adjacent(net, a, b):
    return any(p["node"] == net.ids[b] for p in net.rpc(a, "status")["neighbors"])


def pair(net, a, b):
    return adjacent(net, a, b) and adjacent(net, b, a)


def echo(net, a, b):
    result = net.rpc(a, "ping", b, "--size", "8192")
    assert result["bytes"] == 8192 and result["hop_encrypted"], result
    return result


def upgrade(net, a, b):
    def ready():
        echo(net, a, b)
        return pair(net, a, b)
    net.wait(ready, f"direct {a}-{b}")


def ping(net, a, b):
    addr = net.rpc(b, "status")["address"]
    for family, key in [("-4", "ipv4"), ("-6", "ipv6")]:
        net.ns(a, "ping", family, "-c", "2", "-i", "0.2", "-W", "2", str(addr[key]))


def capacity_and_bridge(binary):
    with Network(binary, ["a", "b", "c", "r"]) as net:
        setup(net, ["a", "b", "c"], 2)
        boots = {n: net.rpc(n, "status")["boot_id"] for n in net.paths}
        upgrade(net, "a", "b")
        assert len(net.rpc("a", "status")["neighbors"]) == 2
        # A is full. C traffic must work through R without evicting A's busy B.
        echo(net, "a", "c")
        assert not pair(net, "a", "c")
        trace = net.rpc("a", "trace", "c")
        assert [h["node"] for h in trace["hops"]] == [net.ids["r"], net.ids["c"]], trace
        started = time.monotonic()
        def reused():
            echo(net, "a", "c")
            for n in ["a", "b", "c"]:
                assert len(net.rpc(n, "status")["neighbors"]) <= 2
                assert adjacent(net, n, "r") and adjacent(net, "r", n), "configured edge pruned"
            return not adjacent(net, "a", "b") and not adjacent(net, "b", "a") and pair(net, "a", "c")
        net.wait(reused, "idle B slot reused by C", timeout=IDLE+25)
        reclaim_ms = round((time.monotonic()-started)*1000, 1)
        assert reclaim_ms >= (IDLE-5)*1000, "busy/new shortcut retired too soon"
        assert sum(net.rpc(n, "status")["idle_retired"] for n in ["a", "b", "c"]) >= 1
        print(json.dumps(dict(stage="slot_reused", elapsed_ms=reclaim_ms)), flush=True)

        # The deterministic owner receives only one-way application traffic.
        # Its outgoing PMTU, ACK, keepalive and LSA traffic must not be mistaken
        # for application use; the received application packets must be counted.
        receiver, sender = sorted(["a", "c"], key=lambda n: net.ids[n])
        destination = net.rpc(receiver, "status")["address"]["ipv4"]
        receive = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',34567));\nwhile True: s.recvfrom(2048)"
        receive_process = net.spawn(receiver, ["python3", "-c", receive], net.directory / "oneway-receive.log")
        send = f"import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);\nfor _ in range({IDLE+8}): s.sendto(b'oneway',('{destination}',34567)); time.sleep(1)"
        send_process = net.spawn(sender, ["python3", "-c", send], net.directory / "oneway-send.log")
        until = time.monotonic()+IDLE+4
        while time.monotonic() < until:
            assert pair(net, "a", "c"), "active one-way shortcut retired"
            neighbor = next(p for p in net.rpc(receiver, "status")["neighbors"] if p["node"] == net.ids[sender])
            assert neighbor["traffic_idle_ms"] < 3500, neighbor
            time.sleep(0.5)
        # The sender exits naturally; the fixture reaps the blocked receiver
        # at teardown without stopping either overlay daemon here.
        send_process.wait(timeout=10)
        assert send_process.returncode == 0 and receive_process.poll() is None
        print(json.dumps(dict(stage="one_way_activity_preserved", seconds=IDLE+4)), flush=True)
        assert {n: net.rpc(n, "status")["boot_id"] for n in net.paths} == boots

        net.crash("r")
        net.wait(lambda: all(not adjacent(net, n, "r") for n in ["a", "c"]), "bootstrap disconnected")
        # No application traffic for longer than the production idle timer.
        until = time.monotonic()+IDLE+4
        while time.monotonic() < until:
            assert pair(net, "a", "c"), "sole remaining bridge retired"
            time.sleep(0.5)
        assert all(next(p for p in net.rpc(n,"status")["neighbors"] if p["node"]==net.ids[other])["traffic_idle_ms"] >= IDLE*1000 for n,other in [("a","c"),("c","a")])
        echo(net,"a","c")
        ping(net,"a","c")
        assert {n:net.rpc(n,"status")["boot_id"] for n in ["a","c"]} == {n:boots[n] for n in ["a","c"]}
        return dict(ok=True, slot_reuse_ms=reclaim_ms, configured_edges_preserved=True, bounded_neighbors=True,
                    full_capacity_multihop=True, one_way_active_link_preserved=True, idle_essential_bridge_preserved=True,
                    bootstrap_process_offline=True, dual_stack_tun=True, endpoint_boot_ids_unchanged=True)


def concurrent_cycle(binary):
    nodes = ["a", "b", "c", "d"]
    with Network(binary, [*nodes, "r"]) as net:
        setup(net, nodes, 4)
        boots = {n:net.rpc(n,"status")["boot_id"] for n in nodes}
        for i, a in enumerate(nodes):
            for b in nodes[i+1:]: upgrade(net,a,b)
        assert all(len(net.rpc(n,"status")["neighbors"]) == 4 for n in nodes)
        net.crash("r")
        net.wait(lambda: all(not adjacent(net,n,"r") for n in nodes), "cycle bootstrap disconnected")
        started=time.monotonic()
        def tree():
            counts=[len(net.rpc(n,"status")["neighbors"]) for n in nodes]
            assert all(1 <= n <= 3 for n in counts), counts
            return sum(counts)==6
        net.wait(tree,"concurrent cycle pruning",timeout=IDLE+15)
        # Lexicographic edge ranks retain the smallest identity's star for K4.
        root=min(nodes,key=lambda n:net.ids[n])
        for n in nodes:
            expected={net.ids[other] for other in nodes if other!=n} if n==root else {net.ids[root]}
            actual={p["node"] for p in net.rpc(n,"status")["neighbors"]}
            assert actual==expected,(n,actual,expected)
        # Trace alone does not open a shortcut. Observe actual retained relays
        # before generating new application demand that may upgrade again.
        leaves=[n for n in nodes if n!=root]
        for a,b in zip(leaves,leaves[1:]):
            trace=net.rpc(a,"trace",b)
            assert trace["complete"] and [h["node"] for h in trace["hops"]]==[net.ids[root],net.ids[b]],trace
        retired=sum(net.rpc(n,"status")["idle_retired"] for n in nodes)
        assert retired==3,retired
        echo(net,leaves[0],leaves[1])
        ping(net,leaves[0],leaves[1])
        assert {n:net.rpc(n,"status")["boot_id"] for n in nodes}==boots
        return dict(ok=True, automatic_edges_before=6, automatic_edges_after=3, retired=retired,
                    elapsed_ms=round((time.monotonic()-started)*1000,1), active_multihop_trace=True,
                    dual_stack_tun=True, endpoint_boot_ids_unchanged=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",type=Path,default=Path("target/release/nnlan"))
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.output: args.output.unlink(missing_ok=True)
    provenance=dict(started_at=datetime.now(timezone.utc).isoformat(),kernel=platform.release(),binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                    fixture_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in ["neighbors_netns.py","netns_fixture.py"]})
    report=dict(ok=True,capacity_and_bridge=capacity_and_bridge(args.binary),concurrent_cycle=concurrent_cycle(args.binary),provenance=provenance)
    provenance["finished_at"]=datetime.now(timezone.utc).isoformat()
    if args.output: args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__": main()
