"""Fresh paired original/native key executions and complete kernel traces."""
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
from file_lock_key_cases import request, setup
from file_lock_fixture import snapshot, retire

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def cases():
    result = []
    def case(name, path=b'.', faults=(), **details):
        result.append({'name': name, 'path_hex': path.hex(), 'faults': list(faults), **details})
    for index, path in enumerate((b'', b'.', b'/', b'//', b'dir/file', b'link/file', b'absolute-link/file',
        b'broken', b'broken/tail', b'loop', b'loop/tail', b'dir/file/', b'dir/file/.', b'dir/file/..',
        b'dir/file//./', b'dir/no', b'dir/no/', b'./missing', b'missing', b'dir/\0new', b'raw-\xff/file',
        b'raw-\xff/leaf-\xfe', b'dir/\xff', b'chain-0/file', b'over-0/file', b'long-link/file',
        b'denied/file', b'dir/../../.', b'dir/sub/../file')):
        case('ordinary-' + str(index), path)
    case('absolute-fixture-path', b'dir/file', absolute=True)
    for length in (1022, 1023, 1024, 2046, 2047, 2048, 4094):
        case('link-buffer-' + str(length), ('sized-link-' + str(length)).encode())
    for error in (4, 5, 13, 2, 34, 36):
        case('getcwd-error-' + str(error), faults=({'kind': 'getcwd', 'errno': error},))
    for error in (4, 5, 13, 22, 36):
        for path in (b'dir/file', b'dir/.'):
            case('readlink-' + str(error) + '-' + path.hex(), path,
                faults=({'kind': 'readlink', 'errno': error},))
    case('readlink-full-buffer', b'dir/file', faults=({'kind': 'readlink', 'return': 'readlink_capacity'},))
    case('readlink-zero-completion', b'dir/file', faults=({'kind': 'readlink', 'return': 0},))
    for error in (4, 5, 13, 38):
        case('access-error-' + str(error), b'dir/.', faults=({'kind': 'access', 'errno': error},))
    case('old-access-error', b'dir/.', faults=({'kind': 'access', 'errno': 38}, {'kind': 'access_old', 'errno': 13}))
    generic = {'kind': 'getcwd', 'errno': 36}
    case('generic-cwd', faults=(generic,))
    for kind, ordinals in (('stat_at', (1, 2, 3)), ('open_parent', (1, 2)), ('fstat', (1, 2, 3)),
                           ('close', (1, 2)), ('fcntl', (1, 2)), ('getdents', (1, 2))):
        for ordinal in ordinals:
            for error in (4, 5, 13):
                case('generic-' + kind + '-' + str(ordinal) + '-' + str(error),
                    faults=(generic, {'kind': kind, 'ordinal': ordinal, 'errno': error}))
    for flags in (1, 2097152):
        case('generic-fd-flags-' + str(flags), faults=(generic, {'kind': 'fcntl', 'return': flags}))
    case('generic-getdents-enoent', faults=(generic, {'kind': 'getdents', 'errno': 2}))
    case('generic-rewind', faults=(generic, {'kind': 'getdents', 'return': 0}))
    case('generic-rewind-error', faults=(generic, {'kind': 'getdents', 'return': 0}, {'kind': 'rewind', 'errno': 5}))
    case('deep-cwd', deep=47)
    case('deep-cwd-parent', b'../.', deep=47)
    case('deep-cwd-missing-child', b'./new', deep=47)
    case('unlinked-cwd', removed=True)
    return result

def normalized(trace):
    descriptors, sequence = {}, 0
    answer = []
    for raw in trace['events']:
        if raw['domain'] != 'owner':
            continue
        row = {key: value for key, value in raw.items() if key not in ('pid', 'ip', 'domain')}
        for key in ('fd', 'dirfd'):
            if key not in row or row[key] < 0:
                continue
            descriptor = row[key]
            if descriptor not in descriptors:
                sequence += 1
                descriptors[descriptor] = sequence
            row[key] = descriptors[descriptor]
        if raw['kind'] == 'close':
            # The original and fixed boundary both retire before a single
            # close attempt.  An injected error is not silently retried.
            descriptors.pop(raw['fd'], None)
        answer.append(row)
    return answer

def create_fixture(path, case):
    setup(path)
    parts = []
    if case.get('deep'):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for index in range(case['deep']):
                name = (str(index) + '-' + 'a' * 117).encode()
                os.mkdir(name, dir_fd=fd)
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = following
                parts.append(name.hex())
        finally:
            os.close(fd)
    if case.get('removed'):
        (path / 'removed').mkdir()
        parts = [b'removed'.hex()]
    return parts

def run(native, original, destination, selected=None, *, retire_fixtures=False):
    native, original = Path(native).resolve(strict=True), Path(original).resolve(strict=True)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    domain = cases() if selected is None else selected
    report = {'schema': 'hepta.runtime.file-lock-key-kernel-comparison.v1', 'status': 'RUNNING',
        'directory': str(destination), 'native_executable': str(native), 'original_executable': str(original),
        'declared_cases': len(domain), 'cases': 0, 'native_processes': 0, 'original_processes': 0,
        'native_binary_sha256': sha(native.read_bytes()), 'original_binary_sha256': sha(original.read_bytes()),
        'source_files': {name: sha((HERE / name).read_bytes()) for name in
            ('file_lock_key_cases.py', 'file_lock_key_kernel.py', 'file_lock_key_supervisor.py', 'file_lock_fixture.py')},
        'observations': []}
    (destination / 'cases.json').write_text(json.dumps(domain, sort_keys=True, indent=2) + '\n')
    started = time.monotonic()
    try:
        for index, case in enumerate(domain):
            entry = destination / f'{index:03d}-{case["name"]}'
            entry.mkdir()
            fixture = entry / 'fixture'
            parts = create_fixture(fixture, case)
            fixture_before = snapshot(fixture) if retire_fixtures else None
            expected_after = ([row for row in fixture_before if row['path_hex'] != b'removed'.hex()]
                if retire_fixtures and case.get('removed') else fixture_before)
            fixture_after = []
            path = bytes.fromhex(case['path_hex'])
            if case.get('absolute'):
                path = os.fsencode(fixture) + b'/' + path
            wire = request(path)
            framed = struct.pack('<Q', len(wire)) + wire
            (entry / 'request.bin').write_bytes(framed)
            config = {'faults': case['faults'], 'cwd_parts': parts, 'unlink_cwd': bool(case.get('removed'))}
            (entry / 'config.json').write_text(json.dumps(config, sort_keys=True, indent=2) + '\n')
            # Generic getcwd can legitimately enumerate every sibling when
            # its first inode candidate is rejected.  Do not change that
            # directory between the two actual owners by adding our logs.
            for name in ('native.stdout', 'native.stderr', 'native.trace.json',
                         'original.stdout', 'original.stderr', 'original.trace.json', 'comparison.json'):
                (entry / name).touch(exist_ok=False)
            entry_names = sorted(path.name for path in entry.iterdir())
            pair = []
            observation = {'name': case['name'], 'request_sha256': sha(framed), 'request_bytes': len(framed),
                'precreated_entry_names': entry_names, 'invocations': []}
            report['observations'].append(observation)
            for name, executable in (('native', native), ('original', original)):
                if name == 'original' and case.get('removed'):
                    (fixture / 'removed').mkdir()
                command = [sys.executable, '-I', str(HERE / 'file_lock_key_supervisor.py'),
                    '--executable', str(executable), '--fixture', str(fixture),
                    '--config', str(entry / 'config.json'), '--log', str(entry / (name + '.trace.json')), '--timeout', '15']
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
                assert trace['status'] == 'PASS' and trace['failure'] is None and trace['exit_code'] == 0
                assert trace['stdout_sha256'] == sha(child.stdout) and trace['stderr_sha256'] == sha(child.stderr)
                assert trace['executable_sha256'] == sha(executable.read_bytes())
                if name == 'native':
                    assert child.stderr == b''
                else:
                    summary = json.loads(child.stderr)
                    assert summary == {'status': 'PASS', 'rows': 1, 'local_rows': 1, 'remote_rows': 0,
                        'remote_metadata_projection_calls': 0, 'actual_original_owner_calls': 1}
                pair.append((child.stdout, normalized(trace)))
                report[name + '_processes'] += 1
                assert entry_names == sorted(path.name for path in entry.iterdir())
                if retire_fixtures:
                    observed = snapshot(fixture)
                    assert observed == expected_after, (case['name'], name, 'owned fixture state changed')
                    fixture_after.append(observed)
            observation['native_normalized_trace'] = pair[0][1]
            observation['original_normalized_trace'] = pair[1][1]
            observation['output_match'] = pair[0][0] == pair[1][0]
            observation['kernel_trace_match'] = pair[0][1] == pair[1][1]
            assert observation['output_match'], (case['name'], 'key output differs')
            assert observation['kernel_trace_match'], (case['name'], 'complete owner kernel trace differs')
            if retire_fixtures:
                raw = (json.dumps({'before': fixture_before, 'after_native': fixture_after[0],
                    'after_original': fixture_after[1], 'removed_cwd_is_a_fixture_effect': bool(case.get('removed'))},
                    sort_keys=True, separators=(',', ':')) + '\n').encode()
                with gzip.open(entry / 'fixture-snapshots.json.gz', 'xb') as stream:
                    stream.write(raw)
                observation['fixture_snapshots'] = {'file': 'fixture-snapshots.json.gz',
                    'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                    'sha256': sha((entry / 'fixture-snapshots.json.gz').read_bytes()),
                    'bytes': (entry / 'fixture-snapshots.json.gz').stat().st_size}
                observation['fixture_retirement'] = retire(fixture, entry / 'fixture-retired.json.gz')
            (entry / 'comparison.json').write_text(json.dumps(observation, sort_keys=True, indent=2) + '\n')
            report['cases'] += 1
        assert report['native_binary_sha256'] == sha(native.read_bytes())
        assert report['original_binary_sha256'] == sha(original.read_bytes())
        assert report['source_files'] == {name: sha((HERE / name).read_bytes()) for name in report['source_files']}
        report.update(status='PASS', native_owner_effects=sum(len(row['native_normalized_trace']) for row in report['observations']),
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
