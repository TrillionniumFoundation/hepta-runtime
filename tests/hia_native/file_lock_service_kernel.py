"""Actual threaded-service/original-owner kernel comparisons on owned fixtures."""
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
from file_lock_key_kernel import cases, normalized, create_fixture
from file_lock_fixture import snapshot, retire


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request(path):
    acquire = struct.pack('<8s7Q', b'HRLKSRV1', 1, 0, 1, len(path), 0, 0, 0) + path
    release = struct.pack('<8s7Q', b'HRLKSRV1', 6, 1, 0, 0, 0, 0, 0)
    return struct.pack('<QQ', len(acquire), 1) + acquire + struct.pack('<QQ', len(release), 2) + release


def logical_output(raw, *, native, trace):
    width = 84 if native else 76
    assert len(raw) == 2 * width
    answer, tids = bytearray(), []
    for index, op in enumerate((1, 6)):
        row = raw[index * width:(index + 1) * width]
        tag = struct.unpack_from('<Q', row)[0]
        assert tag == index + 1
        at = 16 if native else 8
        assert struct.unpack_from('<I', row, at)[0] == 64
        body = row[at + 4:]
        assert len(body) == 64 and body[:8] == b'HRFLKR01'
        assert struct.unpack_from('<Q', body, 8)[0] == op
        assert struct.unpack_from('<Q', body, 16)[0] == 0
        if native:
            tid = struct.unpack_from('<Q', row, 8)[0]
            assert tid > 0 and tid in trace['owned_thread_ids']
            tids.append(tid)
        answer.extend(struct.pack('<QI', tag, 64) + body)
    return bytes(answer), tids


def run(native, original, destination, selected=None, *, retire_fixtures=True):
    native, original = Path(native).resolve(strict=True), Path(original).resolve(strict=True)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    domain = cases() if selected is None else selected
    sources = ('file_lock_key_cases.py', 'file_lock_key_kernel.py', 'file_lock_fixture.py',
        'file_lock_service_kernel.py', 'file_lock_service_supervisor.py')
    report = {'schema': 'hepta.runtime.file-lock-service-kernel-comparison.v1', 'status': 'RUNNING',
        'directory': str(destination), 'native_executable': str(native), 'original_executable': str(original),
        'declared_cases': len(domain), 'cases': 0, 'native_processes': 0, 'original_processes': 0,
        'native_binary_sha256': sha(native.read_bytes()), 'original_binary_sha256': sha(original.read_bytes()),
        'source_files': {name: sha((HERE / name).read_bytes()) for name in sources},
        'observations': []}
    (destination / 'cases.json').write_text(json.dumps(domain, sort_keys=True, indent=2) + '\n')
    started = time.monotonic()
    try:
        for index, case in enumerate(domain):
            entry = destination / f'{index:03d}-{case["name"]}'
            entry.mkdir()
            fixture = entry / 'fixture'
            parts = create_fixture(fixture, case)
            before_fixture = snapshot(fixture)
            expected_after = ([row for row in before_fixture if row['path_hex'] != b'removed'.hex()]
                if case.get('removed') else before_fixture)
            after_fixtures = []
            path = bytes.fromhex(case['path_hex'])
            if case.get('absolute'):
                path = os.fsencode(fixture) + b'/' + path
            framed = request(path)
            (entry / 'request.bin').write_bytes(framed)
            config = {'faults': case['faults'], 'cwd_parts': parts, 'unlink_cwd': bool(case.get('removed'))}
            (entry / 'config.json').write_text(json.dumps(config, sort_keys=True, indent=2) + '\n')
            # Generic getcwd may enumerate siblings after an injected inode
            # mismatch.  Both owners must see this same complete log-name set.
            for name in ('native.stdout', 'native.stderr', 'native.trace.json',
                         'original.stdout', 'original.stderr', 'original.trace.json', 'comparison.json'):
                (entry / name).touch(exist_ok=False)
            entry_names = sorted(item.name for item in entry.iterdir())
            pair = []
            observation = {'name': case['name'], 'request_sha256': sha(framed), 'request_bytes': len(framed),
                'precreated_entry_names': entry_names, 'invocations': []}
            report['observations'].append(observation)
            for name, executable in (('native', native), ('original', original)):
                if name == 'original' and case.get('removed'):
                    (fixture / 'removed').mkdir()
                command = [sys.executable, '-I', str(HERE / 'file_lock_service_supervisor.py'),
                    '--executable', str(executable), '--fixture', str(fixture),
                    '--config', str(entry / 'config.json'), '--log', str(entry / (name + '.trace.json')), '--timeout', '15']
                if name == 'original':
                    command.append('--original-transport')
                before = time.monotonic()
                child = subprocess.run(command, input=framed, capture_output=True, timeout=20)
                (entry / (name + '.stdout')).write_bytes(child.stdout)
                (entry / (name + '.stderr')).write_bytes(child.stderr)
                record = {'name': name, 'command': command, 'timeout': 20, 'exit_code': child.returncode,
                    'stdout_sha256': sha(child.stdout), 'stdout_bytes': len(child.stdout),
                    'stderr_sha256': sha(child.stderr), 'stderr_bytes': len(child.stderr), 'elapsed': time.monotonic() - before}
                observation['invocations'].append(record)
                assert child.returncode == 0, (case['name'], name, child.stderr.decode(errors='replace'))
                trace = json.loads((entry / (name + '.trace.json')).read_bytes())
                assert trace['schema'] == 'hepta.runtime.file-lock-service-kernel-trace.v1'
                assert trace['status'] == 'PASS' and trace['failure'] is None and trace['exit_code'] == 0
                assert trace['stdout_sha256'] == sha(child.stdout) and trace['stderr_sha256'] == sha(child.stderr)
                assert trace['executable_sha256'] == sha(executable.read_bytes())
                assert trace['input_sha256'] == sha(framed) and trace['input_bytes'] == len(framed)
                assert trace['original_transport'] is (name == 'original') and trace['drop_after_complete_first_result'] is True
                if name == 'native':
                    assert child.stderr == b''
                else:
                    summary = json.loads(child.stderr)
                    assert summary == {'status': 'PASS', 'rows': 2, 'original_owner_operations': 2,
                        'operation_counts': [0, 1, 0, 0, 0, 0, 1, 0], 'borrowed_guards': True,
                        'extra_strong_observer_refs': 0}
                output, tids = logical_output(child.stdout, native=name == 'native', trace=trace)
                record['response_thread_ids'] = tids
                record['logical_output_sha256'] = sha(output)
                record['logical_output_bytes'] = len(output)
                pair.append((output, normalized(trace)))
                report[name + '_processes'] += 1
                assert entry_names == sorted(item.name for item in entry.iterdir())
                observed = snapshot(fixture)
                assert observed == expected_after, (case['name'], name, 'owned fixture state changed')
                after_fixtures.append(observed)
            observation['native_normalized_trace'] = pair[0][1]
            observation['original_normalized_trace'] = pair[1][1]
            observation['output_match'] = pair[0][0] == pair[1][0]
            observation['kernel_trace_match'] = pair[0][1] == pair[1][1]
            assert observation['output_match'], (case['name'], 'complete owner output differs')
            assert observation['kernel_trace_match'], (case['name'], 'complete owner kernel trace differs')
            raw = (json.dumps({'before': before_fixture, 'after_native': after_fixtures[0],
                'after_original': after_fixtures[1], 'removed_cwd_is_a_fixture_effect': bool(case.get('removed'))},
                sort_keys=True, separators=(',', ':')) + '\n').encode()
            with gzip.open(entry / 'fixture-snapshots.json.gz', 'xb') as stream:
                stream.write(raw)
            observation['fixture_snapshots'] = {'file': 'fixture-snapshots.json.gz',
                'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                'sha256': sha((entry / 'fixture-snapshots.json.gz').read_bytes()),
                'bytes': (entry / 'fixture-snapshots.json.gz').stat().st_size}
            if retire_fixtures:
                observation['fixture_retirement'] = retire(fixture, entry / 'fixture-retired.json.gz')
            (entry / 'comparison.json').write_text(json.dumps(observation, sort_keys=True, indent=2) + '\n')
            report['cases'] += 1
        assert report['native_binary_sha256'] == sha(native.read_bytes())
        assert report['original_binary_sha256'] == sha(original.read_bytes())
        assert report['source_files'] == {name: sha((HERE / name).read_bytes()) for name in sources}
        report.update(status='PASS', actual_native_owner_operations=2 * len(domain),
            actual_original_owner_operations=2 * len(domain),
            native_owner_effects=sum(len(row['native_normalized_trace']) for row in report['observations']),
            original_owner_effects=sum(len(row['original_normalized_trace']) for row in report['observations']))
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (destination / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.native, args.original, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != 'observations'}))
