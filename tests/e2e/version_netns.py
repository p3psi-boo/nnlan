#!/usr/bin/env python3
"""GGB2/GGB3 reject each other's wire packets; identities/config stay readable."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--old-binary', type=Path, required=True, help='archived GGB2 binary')
    parser.add_argument('--output', type=Path, default=Path('target/version-rejection.json'))
    args = parser.parse_args()
    binaries = {'old': str(args.old_binary.resolve()), 'new': str(args.binary.resolve())}
    report = dict(ok=False, started_at=datetime.now(timezone.utc).isoformat(),
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  binary_sha256={n: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                                 for n, p in binaries.items()})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with Network(args.binary, ['old', 'new']) as net:
            net.link('old', 'new', 'wan', 'wan', ['10.149.0.1/30', '10.149.0.2/30'])
            net.init(net.names)
            for name in net.names:
                # Compare both readers on exactly the same identity and state.
                plans = [json.loads(net.command([p, '--config', str(net.paths[name]), 'plan']).stdout)
                         for p in binaries.values()]
                for field in ['node_id', 'address_candidate']:
                    assert plans[0][field] == plans[1][field], (field, plans)
                other = 'new' if name == 'old' else 'old'
                remote = '10.149.0.2' if name == 'old' else '10.149.0.1'
                net.paths[name].write_text(
                    f'name = "{name}"\nlisten = "0.0.0.0:7331"\nmax_neighbors = 1\n'
                    f'[[peers]]\nendpoint = "{remote}:7331"\npublic_key = "{net.ids[other]}"\n'
                    '[tun]\nenabled = false\n')
                net.daemons[name] = net.spawn(name, [binaries[name], '--config', str(net.paths[name]), 'run'],
                                              net.paths[name].with_suffix('.log'))
            def states():
                return {n: net.rpc(n, 'status') for n in net.names}
            net.wait(lambda: all(s['invalid_udp'] > 0 for s in states().values()),
                     'both versions reject actual remote handshake packets')
            # Observe retries too, not just an initial transient lack of a neighbor.
            report['samples'] = []
            for _ in range(12):
                current = states()
                assert all(p.poll() is None for p in net.daemons.values())
                assert current['new']['wire_protocol'] == 'GGB3'
                assert current['new']['encryption'] == 'hop-by-hop'
                assert all(s['nodes'] == 1 and not s['neighbors'] and s['invalid_udp'] > 0
                           for s in current.values()), current
                report['samples'].append(current)
                time.sleep(0.25)
            report['identity_and_addresses_unchanged'] = True
        report['cleanup_complete'] = True
        report['ok'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'samples'}, indent=2))


if __name__ == '__main__':
    main()
