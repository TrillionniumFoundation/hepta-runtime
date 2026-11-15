"""Capture every ordinary original Local spec frame and complete fixture state."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cases as cases
import observations as native_observations


def words(raw, count, start=0):
    return struct.unpack_from('<' + 'Q' * count, raw, start)


def frames(raw):
    result, at = [], 0
    while at < len(raw):
        assert len(raw) - at >= 8
        extent, = words(raw, 1, at)
        at += 8
        if extent >= 0xffff0000:
            result.append(extent)
            continue
        assert extent <= len(raw) - at
        result.append(raw[at:at + extent])
        at += extent
    return result


def cache_response(value):
    return struct.pack('<8s3Q', b'HVCAR001', int(value is not None), len(value or b''), 0) + (value or b'')


def cache_observation(raw):
    assert raw[:8] == b'HLCSCS01' and len(raw) >= 48
    extent, phase, poison, count, bodylen = words(raw, 5, 8)
    assert extent == len(raw) == bodylen + 48 and phase in (0, 1) and poison in (0, 1)
    entries, at, order = {}, 48, []
    for _ in range(count):
        assert len(raw) - at >= 16
        keylen, valuelen = words(raw, 2, at)
        at += 16
        assert keylen <= len(raw) - at and valuelen <= len(raw) - at - keylen
        key, value = raw[at:at + keylen], raw[at + keylen:at + keylen + valuelen]
        at += keylen + valuelen
        key.decode('utf-8'); value.decode('utf-8')
        assert key not in entries and valuelen <= 1 << 20
        entries[key] = value
        order.append(key)
    assert at == len(raw) and order == sorted(order)
    return dict(phase=phase, poisoned=bool(poison), entries=entries)


def observations(raw):
    at, snapshots, markers, sequence = 0, [], [], []
    while at < len(raw):
        assert len(raw) - at >= 16
        magic = raw[at:at + 8]
        extent, = words(raw, 1, at + 8)
        assert extent <= len(raw) - at
        current = raw[at:at + extent]
        if magic == b'HLCSCS01':
            snapshots.append(cache_observation(current))
            sequence.append(('cache', snapshots[-1]['phase']))
        else:
            assert magic == b'HLCARP01' and extent == 128
            assert current[72:] == bytes(56)
            event, serial, poll, wake, tid, first, second = words(current, 7, 16)
            markers.append(dict(event=event, serial=serial, poll=poll, wake=wake,
                                tid=tid, details=[first, second]))
            sequence.append(('marker', event))
        at += extent
    assert len(snapshots) == 2 and [s['phase'] for s in snapshots] == [0, 1]
    assert sequence[0] == ('cache', 0) and sequence[-1] == ('cache', 1)
    assert sorted(m['serial'] for m in markers) == list(range(1, len(markers) + 1))
    events = [m['event'] for m in markers]
    assert events.count(3) == events.count(12) == events.count(13) == events.count(6) == events.count(7) == 1
    assert not set(events) & {8, 9, 10, 11}
    assert events.count(16) == events.count(17)
    assert events.count(14) == 1
    drained = events.index(13)
    assert events.index(3) < events.index(12) < drained
    assert all(event == 14 for event in events[drained + 1:])
    assert all(index < drained for index, event in enumerate(events) if event in (16, 17))
    assert sorted(m['tid'] for m in markers if m['event'] == 16) == sorted(m['tid'] for m in markers if m['event'] == 17)
    return snapshots, markers


def validate(spec, request, stdout, stderr, work, mode):
    actual = frames(stdout)
    assert len(actual) == len(request['frames'])
    before = request['create_index']
    assert actual[:before] == [cache_response(None)] * before
    result = actual[before]
    assert isinstance(result, bytes) and len(result) >= 32 and result[:8] == b'HLCSPR01'
    operation, kind, extent = words(result, 3, 8)
    assert operation == 1 and kind in (0, 1) and len(result) == extent + 32
    message = result[32:]
    message.decode('utf-8')
    assert kind == (0 if spec['outcome'] == 'success' else 1), (spec['name'], message)
    if kind == 0:
        assert message == f"File created successfully with {len(request['content'])} bytes".encode()
        full = request['path'] if spec['absolute'] else os.fsencode(work) + b'/' + request['path']
        assert Path(os.fsdecode(full)).read_bytes() == request['content']
    elif spec['error_class'] == 'exists':
        assert message == (b'File already exists: ' + request['path'].decode('utf-8', 'replace').encode() +
            b'. Edit it with str_replace or batch_edit instead of create.')
    elif spec['error_class'] == 'write':
        assert message.startswith(b'Permission denied. Cannot write to file: ')
    elif spec['error_class'] == 'mkdir':
        assert message.startswith(b"Permission denied. Cannot create directories: Failed to create dirs for '")
    else:
        raise AssertionError('unknown source-selected error domain')
    snapshots, markers = observations(stderr) if mode == 'rust' else native_observations.observations(stderr)
    assert snapshots[0] == dict(phase=0, poisoned=spec['poison'], entries=request['seeds'])
    expected = dict(request['seeds'])
    if kind == 0 and spec['context'] == 1 and not spec['poison']:
        value = request['content'].replace(b'\r\n', b'\n')
        if len(value) <= 1 << 20:
            expected[request['canonical_key']] = value
        else:
            expected.pop(request['canonical_key'], None)
    assert snapshots[1] == dict(phase=1, poisoned=spec['poison'], entries=expected)
    inspect = [cache_response(None if spec['poison'] else expected.get(key)) for key in request['inspection_keys']]
    assert actual[before + 1:] == inspect
    if spec['error_class'] == 'exists' and mode == 'rust':
        assert [m['event'] for m in markers].count(1) == 1
        assert not any(m['event'] in (2, 16, 17) for m in markers)
    return dict(outcome=spec['outcome'], message_hex=message.hex(), context=spec['context'],
        initial_cache_entries=len(snapshots[0]['entries']), final_cache_entries=len(expected),
        poisoned=spec['poison'], cache_before=[dict(key_hex=k.hex(), value=cases.pin(v)) for k, v in sorted(request['seeds'].items())],
        cache_after=[dict(key_hex=k.hex(), value=cases.pin(v)) for k, v in sorted(expected.items())],
        marker_count=len(markers))


def save(raw, path):
    with Path(path).open('xb') as target, gzip.GzipFile(filename='', fileobj=target, mode='wb', mtime=0) as stream:
        stream.write(raw)


def run(binary, output, fixture_root, mode):
    assert mode in ('native', 'rust')
    os.umask(0o022)
    binary = Path(binary).resolve(strict=True)
    output = Path(output).resolve()
    output.mkdir(exist_ok=False)
    fixture_root = Path(fixture_root).resolve()
    fixture_root.mkdir(exist_ok=True)
    assert not any(fixture_root.iterdir())
    binary_before = cases.pin(binary.read_bytes())
    source_paths = (Path(__file__).resolve(), Path(cases.__file__).resolve(), Path(native_observations.__file__).resolve())
    source_before = {str(p): cases.pin(p.read_bytes()) for p in source_paths}
    report = dict(schema='hepta.runtime.local-create-spec-ordinary.v1', status='RUNNING', mode=mode,
        source_before=source_before, binary_before=binary_before,
        execution=dict(source=str(Path(__file__).resolve().parent), binary=str(binary), output=str(output), fixtures=str(fixture_root)),
        cases=cases.CASES, rows=[], process_deadline_seconds=60, qualifier_deadline_seconds=180,
        actual_root_processes=0, retired_fixtures=0, public_handler_qualified=False,
        full_create_file_spec_qualified=False, whole_runtime_replaced=False)
    started = time.monotonic()
    try:
        for spec in cases.CASES:
            assert time.monotonic() - started < 180
            folder = output / spec['name']; folder.mkdir()
            work = fixture_root / spec['name']
            request = cases.setup(spec, work)
            initial, initial_contents = cases.snapshot(work)
            save(request['wire'], folder / 'stdin.bin.gz')
            for key, raw in initial_contents.items():
                save(raw, folder / ('initial-file-' + hashlib.sha256(bytes.fromhex(key)).hexdigest() + '.bin.gz'))
            record = dict(name=spec['name'], status='RUNNING', command=[str(binary)], cwd=str(work),
                environment={'PATH': '', 'LC_ALL': 'C'}, umask=0o022, stdin=cases.pin(request['wire']),
                binary_before=binary_before, initial_filesystem=initial, timeout_seconds=60,
                timed_out=False, actual_pid=None)
            clock = time.monotonic()
            process = subprocess.Popen([str(binary)], cwd=work, env=record['environment'], umask=0o022,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            record['actual_pid'] = process.pid
            (folder / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            try:
                stdout, stderr = process.communicate(request['wire'], timeout=60)
            except subprocess.TimeoutExpired:
                record['timed_out'] = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
            record.update(exit_code=process.returncode, elapsed_seconds=time.monotonic() - clock,
                stdout=cases.pin(stdout), stderr=cases.pin(stderr))
            save(stdout, folder / 'stdout.bin.gz'); save(stderr, folder / 'stderr.bin.gz')
            final, contents = cases.snapshot(work)
            record['final_filesystem'] = final
            for key, raw in contents.items():
                save(raw, folder / ('final-file-' + hashlib.sha256(bytes.fromhex(key)).hexdigest() + '.bin.gz'))
            try:
                assert process.returncode == 0 and not record['timed_out'] and record['elapsed_seconds'] < 60
                record['semantic_capture'] = validate(spec, request, stdout, stderr, work, mode)
                record['status'] = 'PASS'
                cases.retire(work); assert not work.exists()
                report['retired_fixtures'] += 1
            except BaseException as error:
                record.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
                raise
            finally:
                (folder / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            report['actual_root_processes'] += 1
            report['rows'].append(record)
            (output / 'summary.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
            print(json.dumps(dict(case=report['actual_root_processes'], name=spec['name'], mode=mode, status='PASS')), flush=True)
        report['binary_after'] = cases.pin(binary.read_bytes())
        report['source_after'] = {str(p): cases.pin(p.read_bytes()) for p in source_paths}
        assert report['binary_after'] == binary_before and report['source_after'] == source_before
        assert report['actual_root_processes'] == report['retired_fixtures'] == len(cases.CASES)
        assert not any(fixture_root.iterdir())
        report['status'] = 'SPEC_ORDINARY_CAPTURE_PASS'
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'summary.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], cases=len(cases.CASES),
        elapsed_seconds=report['elapsed_seconds'], actual_root_processes=report['actual_root_processes'])), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fixtures', required=True)
    parser.add_argument('--mode', choices=('native','rust'), required=True)
    arguments = parser.parse_args()
    run(arguments.binary, arguments.output, arguments.fixtures, arguments.mode)
