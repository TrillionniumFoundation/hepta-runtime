"""Actual static-ELF key corpus, retained in full for unchanged Rust replay."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from file_lock_key_cases import requests, setup

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(path):
    h = hashlib.sha256()
    count = 0
    with Path(path).open('rb') as stream:
        while piece := stream.read(1 << 20):
            h.update(piece)
            count += len(piece)
    return {'bytes': count, 'sha256': h.hexdigest()}

def run(binary, destination):
    binary = Path(binary).resolve(strict=True)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    fixture = setup(destination / 'fixture')
    counts = {'local': 0, 'remote': 0}
    incoming = destination / 'requests.bin'
    with incoming.open('xb') as output, gzip.open(destination / 'requests.bin.gz', 'wb') as compressed:
        for domain, wire in requests():
            framed = struct.pack('<Q', len(wire)) + wire
            output.write(framed)
            compressed.write(framed)
            counts[domain] += 1
    report = {'schema': 'hepta.runtime.file-lock-key-corpus.v1', 'status': 'RUNNING',
        'executable': {'path': str(binary), **digest(binary)}, 'counts': counts,
        'requests': digest(incoming), 'actual_original_calls': 0,
        'fixture': str(fixture), 'timeout_seconds': 180,
        'source_files': {name: digest(HERE / name) for name in ('file_lock_key_cases.py', 'run_file_lock_key.py')}}
    started = time.monotonic()
    try:
        with incoming.open('rb') as source, (destination / 'native.stdout').open('xb') as output, (destination / 'native.stderr').open('xb') as error:
            process = subprocess.run([str(binary)], stdin=source, stdout=output, stderr=error, cwd=fixture, timeout=180)
        report['exit_code'] = process.returncode
        report['stdout'] = digest(destination / 'native.stdout')
        report['stderr'] = digest(destination / 'native.stderr')
        assert process.returncode == 0 and report['stderr']['bytes'] == 0
        observed = {'local': 0, 'remote': 0}
        with (destination / 'native.stdout').open('rb') as output:
            while size := output.read(4):
                assert len(size) == 4
                count, = struct.unpack('<I', size)
                assert 32 <= count < 0xfffffff0
                answer = output.read(count)
                assert len(answer) == count
                magic, op, length, zero = struct.unpack_from('<8s3Q', answer)
                assert magic == b'HRLKY001' and op in (1, 2) and zero == 0 and length == count - 32
                answer[32:].decode('utf-8')
                observed['local' if op == 1 else 'remote'] += 1
        assert observed == counts
        with (destination / 'native.stdout').open('rb') as source, gzip.open(destination / 'native-output.bin.gz', 'wb') as output:
            while piece := source.read(1 << 20):
                output.write(piece)
        report.update(status='PASS', actual_elf_requests=sum(counts.values()), original_rust_status='PENDING')
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        report['elapsed'] = time.monotonic() - started
        report['artifacts'] = {name: digest(destination / name) for name in
            ('requests.bin.gz', 'native-output.bin.gz', 'native.stdout', 'native.stderr') if (destination / name).exists()}
        (destination / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.binary, args.output)
    print(json.dumps({key: value for key, value in result.items() if key not in ('source_files', 'artifacts')}))
