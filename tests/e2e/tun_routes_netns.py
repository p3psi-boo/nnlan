#!/usr/bin/env python3
"""Run the rtnetlink kernel regression only inside a fixture-owned namespace."""
import argparse
import json
from pathlib import Path
import subprocess
from netns_fixture import Network

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--test-binary', type=Path,
                    help='nnlan library test executable from cargo test --no-run')
args = parser.parse_args()
if args.test_binary is None:
    build = subprocess.run(['cargo', 'test', '--locked', '--lib', '--no-run', '--message-format=json'],
                           capture_output=True, text=True, check=True)
    executables = [record['executable'] for line in build.stdout.splitlines()
                   if (record := json.loads(line)).get('reason') == 'compiler-artifact'
                   and record.get('executable') and record['profile']['test']]
    assert len(executables) == 1, executables
    args.test_binary = Path(executables[0])
with Network(args.test_binary, ['routes']) as net:
    for dev in ['ggtest0', 'ggother0']:
        net.ip('-n', net.names['routes'], 'link', 'add', dev, 'type', 'dummy')
        net.ip('-n', net.names['routes'], 'link', 'set', 'dev', dev, 'up')
    result = net.ns('routes', 'env', 'NNLAN_ROUTE_TEST_NETNS=owned',
                    str(args.test_binary.resolve()), '--ignored', '--exact',
                    'runtime::tunnel::routes::tests::kernel_host_routes_preserve_conflicts_and_acknowledge_changes',
                    '--nocapture', timeout=30)
    print(result.stdout)
