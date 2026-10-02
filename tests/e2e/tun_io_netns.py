#!/usr/bin/env python3
"""Run plain/offloaded TUN I/O regression only inside a fixture-owned namespace."""
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
with Network(args.test_binary, ['io']) as net:
    result = net.ns('io', 'env', 'NNLAN_IO_TEST_NETNS=owned',
                    str(args.test_binary.resolve()), '--ignored', '--exact',
                    'runtime::tunnel::io::tests::kernel_plain_and_offloaded_tun_deliver_packets',
                    '--nocapture', timeout=30)
    print(result.stdout)
