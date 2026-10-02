#!/usr/bin/env python3
"""Independent-process sparse overlay acceptance; no TUN/kernel forwarding claim."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rpc(path, request, timeout=9):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(path.with_suffix(".sock")))
        data = json.dumps(request).encode()
        stream.sendall(struct.pack("!I", len(data)) + data)

        def read(size):
            data = bytearray()
            while len(data) < size:
                part = stream.recv(size-len(data))
                if not part:
                    raise RuntimeError("short admin response")
                data.extend(part)
            return data

        size, = struct.unpack("!I", read(4))
        assert size <= 16 * 1024 * 1024, size
        result = json.loads(read(size))
        if "error" in result:
            raise RuntimeError(result["error"])
        return result


def resources(children):
    samples = []
    for process in children:
        proc = Path(f"/proc/{process.pid}")
        stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in (proc / "status").read_text().splitlines()}
        samples.append(dict(pid=process.pid, rss_kib=int(status["VmRSS"].split()[0]),
                            cpu_ticks=int(stat[11])+int(stat[12]), threads=int(status["Threads"]),
                            fds=len(list((proc / "fd").iterdir()))))
    return dict(at=time.monotonic(), processes=samples)


def transport_summary(states):
    """Diagnostic only: never relax the all-node convergence/traffic gates."""
    links = [peer["link"] for state in states for peer in state["neighbors"]]
    rates = sorted(link["control"]["rate_bps"] for link in links)
    return dict(
        directed_links=len(links),
        rate_bps_min=next(iter(rates), None),
        rate_bps_median=rates[len(rates)//2] if rates else None,
        at_rate_floor=sum(rate == 64_000 for rate in rates),
        queue_dropped=sum(link["queue_dropped"] for link in links),
        queued_bytes=sum(link["queued_bytes"] for link in links),
        control_decisions={name: sum(link["control"].get(name, 0) for link in links)
                           for name in ["delay_backoffs", "loss_backoffs", "stale_backoffs", "probe_events"]},
        udp_socket_dropped=sum(state["udp_socket_dropped"] for state in states),
    )


def tree_path(source, destination):
    """Include both endpoints; the fixture's fixed ternary tree is authoritative."""
    path, tail = [source], []
    while path[-1]:
        path.append((path[-1]-1)//3)
    while destination not in path:
        tail.append(destination)
        destination = (destination-1)//3
    return path[:path.index(destination)+1] + list(reversed(tail))


def exchange_batch(workers, count, ping, report, key, checkpoint, snapshot):
    """Keep every outcome, without retrying, lowering concurrency or skipping failures."""
    outcomes = report[key] = []
    failures = []
    futures = [workers.submit(ping, index) for index in range(count)]
    for future in as_completed(futures):
        outcome = future.result()
        outcomes.append(outcome)
        if not outcome["ok"]:
            failures.append(outcome)
            if len(failures) == 1:
                # Save the failure before any diagnostic RPC, which may itself fail.
                checkpoint()
                try:
                    observed = snapshot(outcome)
                except Exception as error:
                    observed = dict(snapshot_error=repr(error))
                report.setdefault("failure_snapshots", {})[key] = observed
                checkpoint()
        if len(outcomes) % 64 == 0:
            checkpoint()
    outcomes.sort(key=lambda row: row["source"])
    checkpoint()
    if failures:
        first = failures[0]
        raise RuntimeError(f'{key}: {len(failures)}/{count} exchanges failed; '
                           f'first observed {first["source"]}->{first["destination"]}: {first["error"]}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/nnlan"))
    parser.add_argument("--nodes", type=int, default=100)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--convergence-timeout", type=float, default=180)
    parser.add_argument("--verify-rekey", action="store_true",
                        help="require changed outgoing epochs, full PMTU and traffic after a natural rekey")
    parser.add_argument("--output", type=Path, default=Path("target/daemon-scale.json"))
    args = parser.parse_args()
    assert 4 <= args.nodes <= 1000 and args.seconds >= 1 and args.convergence_timeout > 0
    assert not args.verify_rekey or args.seconds >= 125, "allow the real 120 s rekey timer to fire"
    binary = str(args.binary.resolve())
    report = dict(ok=False, nodes=args.nodes, tun_enabled=False,
                  started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                  binary_sha256=digest(binary), fixture_sha256=digest(__file__),
                  convergence_timeout_seconds=args.convergence_timeout,
                  steady_seconds_requested=args.seconds, verify_rekey_requested=args.verify_rekey,
                  clock_ticks=os.sysconf("SC_CLK_TCK"), cpu_count=os.cpu_count())

    def checkpoint():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.output.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, indent=2)+"\n")
        tmp.replace(args.output)

    checkpoint()
    children, paths, ids, logs = [], [], [], []
    # A ternary tree has bounded degree and diameter even at 1,000 processes.
    # Every slot is used by an essential edge, so data tests must relay instead
    # of secretly becoming loopback full-mesh tests after the first request.
    neighbors = [set() for _ in range(args.nodes)]
    for index in range(1, args.nodes):
        parent = (index-1)//3
        neighbors[index].add(parent)
        neighbors[parent].add(index)
    temporary = tempfile.TemporaryDirectory(prefix="nnlan-scale-")
    try:
        directory = Path(temporary.name)
        with ExitStack() as reserved:
            ports = []
            for index in range(args.nodes):
                sock = reserved.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                sock.bind(("127.0.0.1", 0))
                ports.append(sock.getsockname()[1])
                path = directory / str(index) / "nnlan.toml"
                subprocess.run([binary, "--config", str(path), "init"], check=True, capture_output=True, timeout=10)
                identity = subprocess.run([binary, "--config", str(path), "identity"], check=True,
                                          capture_output=True, text=True, timeout=10).stdout.strip()
                paths.append(path)
                ids.append(identity)
            for index, path in enumerate(paths):
                config = (f'name = "n{index}"\nlisten = "127.0.0.1:{ports[index]}"\n'
                          f'max_neighbors = {len(neighbors[index])}\n[tun]\nenabled = false\n')
                if index:
                    parent = (index-1)//3
                    config += f'\n[[peers]]\nendpoint = "127.0.0.1:{ports[parent]}"\npublic_key = "{ids[parent]}"\n'
                path.write_text(config)
        started = time.monotonic()
        for path in paths:
            log = path.with_suffix(".log")
            logs.append(log)
            with log.open("w") as output:
                children.append(subprocess.Popen([binary, "--config", str(path), "run"], stdout=output, stderr=output))

        def live():
            for index, process in enumerate(children):
                assert process.poll() is None, (index, process.returncode, logs[index].read_text()[-4000:])

        def status(index):
            return rpc(paths[index], {"command": "status"})

        with ThreadPoolExecutor(max_workers=16) as workers:
            deadline = started + args.convergence_timeout
            while True:
                live()
                try:
                    states = list(workers.map(status, range(args.nodes)))
                    for index, state in enumerate(states):
                        assert len(state["neighbors"]) <= len(neighbors[index]), (index, state)
                    report["last_discovery_range"] = [min(s["nodes"] for s in states), max(s["nodes"] for s in states)]
                    report["last_transport"] = transport_summary(states)
                    report["sample_states"] = {str(i): states[i] for i in sorted(
                        {0, 1, 2, 3, args.nodes//2, args.nodes-1})}
                    if all(s["nodes"] == args.nodes and s["addresses_claimed"] for s in states):
                        break
                except (OSError, RuntimeError) as error:
                    report["last_poll_error"] = str(error)
                checkpoint()
                assert time.monotonic() < deadline, report.get("last_discovery_range")
                time.sleep(1)
            report["converged_seconds"] = time.monotonic()-started
            boots = [s["boot_id"] for s in states]
            epochs = {(index, peer["node"]): peer.get("key_epoch")
                      for index, state in enumerate(states) for peer in state["neighbors"]}
            if args.verify_rekey:
                assert all(epoch is not None for epoch in epochs.values()), "missing active epoch telemetry"
            for family in ["ipv4", "ipv6"]:
                assert len({s["address"][family] for s in states}) == args.nodes
            for index, state in enumerate(states):
                assert {p["node"] for p in state["neighbors"]} == {ids[n] for n in neighbors[index]}
            report["sparse_edges"] = sum(len(s["neighbors"]) for s in states)//2
            assert report["sparse_edges"] == args.nodes-1
            report["resources_before"] = resources(children)
            checkpoint()
            print(json.dumps(dict(nodes=args.nodes, converged_seconds=report["converged_seconds"])), flush=True)

            # Every daemon originates a real multihop encrypted exchange.
            def ping(index):
                destination = (index + args.nodes//2) % args.nodes
                start = time.monotonic()
                outcome = dict(source=index, destination=destination, ok=False)
                try:
                    reply = rpc(paths[index], {"command": "ping", "target": ids[destination], "size": 8192})
                    assert reply["hop_encrypted"] and reply["bytes"] == 8192, reply
                    outcome["ok"] = True
                except Exception as error:
                    outcome["error"] = repr(error)
                outcome["elapsed_seconds"] = time.monotonic()-start
                return outcome

            def failure_snapshot(outcome):
                path = tree_path(outcome["source"], outcome["destination"])
                selected = sorted(set(path) | {0, 1, 2, 3})
                assert len(selected) <= 16
                def observe(index):
                    try:
                        return rpc(paths[index], {"command": "status"}, timeout=2)
                    except Exception as error:
                        return dict(error=repr(error))
                # Separate bounded readers do not occupy the 16 exchange workers.
                with ThreadPoolExecutor(max_workers=8) as readers:
                    after = dict(zip(map(str, selected), readers.map(observe, selected)))
                return dict(failed_exchange=outcome, expected_path=path,
                            observed_at=time.monotonic(),
                            before={str(i): states[i] for i in selected}, after=after)

            exchange_batch(workers, args.nodes, ping, report, "encrypted_exchanges",
                           checkpoint, failure_snapshot)
            def trace(source, destination):
                expected = tree_path(source, destination)[1:]
                reply = rpc(paths[source], {"command": "trace", "target": ids[destination]})
                assert reply["complete"] and [h["node"] for h in reply["hops"]] == [ids[n] for n in expected], reply
                return dict(source=source, destination=destination, actual=reply, expected=expected)

            report["traces"] = [trace(source, destination) for source, destination in
                                [(args.nodes-1, 1), (1, args.nodes-1)]]

            def check_states(states):
                for index, state in enumerate(states):
                    assert state["boot_id"] == boots[index] and state["nodes"] == args.nodes, (index, state)
                    assert {p["node"] for p in state["neighbors"]} == {ids[n] for n in neighbors[index]}

            deadline = time.monotonic()+args.seconds
            report["steady_samples"] = []
            while True:
                live()
                states = list(workers.map(status, range(args.nodes)))
                check_states(states)
                report["steady_samples"].append(resources(children))
                checkpoint()
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(5, remaining))
            if args.verify_rekey:
                # Probes briefly reset during a handshake. Require recovery on
                # every direction, not permanently maximal PMTU during rotation.
                deadline = time.monotonic() + 10
                while True:
                    live()
                    states = list(workers.map(status, range(args.nodes)))
                    check_states(states)
                    current = {(index, peer["node"]): peer["key_epoch"]
                               for index, state in enumerate(states) for peer in state["neighbors"]}
                    changed = current.keys() == epochs.keys() and all(
                        epoch is not None and epoch != epochs[key] for key, epoch in current.items())
                    ready = all(peer["pmtu"]["confirmed"] and peer["pmtu"]["udp_payload"] == peer["pmtu"].get("maximum_udp_payload", 1232)
                                for state in states for peer in state["neighbors"])
                    report["rekey_observation"] = dict(all_epochs_changed=changed, all_paths_max_mtu=ready)
                    report["post_rekey_states"] = states
                    checkpoint()
                    if changed and ready:
                        break
                    assert time.monotonic() < deadline, report["rekey_observation"]
                    time.sleep(0.25)
                report["epoch_changes"] = [dict(source=index, peer=peer, before=epoch,
                                               after=current[(index, peer)])
                                           for (index, peer), epoch in epochs.items()]
                exchange_batch(workers, args.nodes, ping, report, "post_rekey_exchanges",
                               checkpoint, failure_snapshot)
                report["post_rekey_traces"] = [trace(source, destination) for source, destination in
                                              [(args.nodes-1, 1), (1, args.nodes-1)]]
                report["rekey_verified"] = True
            report["resources_after"] = resources(children)
            report["verified"] = True
        # Reap only our own Popen children, before temporary logs disappear.
        for process in children:
            process.terminate()
        for process in children:
            process.wait(timeout=15)
            assert process.returncode == 0, process.returncode
        report.update(ok=True, finished_at=datetime.now(timezone.utc).isoformat())
    except BaseException as error:
        report["error"] = repr(error)
        report["log_tails"] = {str(i): log.read_text()[-3000:] for i, log in enumerate(logs) if log.exists()}
        raise
    finally:
        for process in children:
            if process.poll() is None:
                process.kill()
            process.wait()
        report["all_owned_processes_reaped"] = all(p.returncode is not None for p in children)
        checkpoint()
        temporary.cleanup()
    print(json.dumps({k:report[k] for k in ["ok", "nodes", "converged_seconds", "sparse_edges", "all_owned_processes_reaped"]}, indent=2))


if __name__ == "__main__":
    main()
