"""Pure complete-wire and complete-journal regression controls.

Creation runs after all native/original observation processes have exited. The
two journal copies preserve every byte except one declared fixed-size record.
Verification only rereads existing copies and receipts; it never recreates a
control, launches a process, or executes a HIA image.
"""
from __future__ import annotations
import collections
import copy
import gzip
import json
from pathlib import Path
import stat
import struct

import read_public_journal as journal_reader
from wire_compare import compare_wire, checked_clock_wire, native_records, pin, WIRE_CLOCK

ROOT = Path(__file__).resolve().parent


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def put(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    with Path(path).open('xb') as stream:
        assert stream.write(raw) == len(raw)


def document(path):
    return json.loads(journal_reader.read(path))


def refuse(action):
    try:
        action()
    except (AssertionError, ValueError, KeyError, IndexError, struct.error) as failure:
        return {'type': type(failure).__name__, 'message': str(failure)}
    raise AssertionError('the declared complete-evidence mutation was accepted')


def comparator_controls(original_run, joined, *, prepared, collected=None):
    """Retain the seven existing wire refusals against fresh original bytes."""
    wire = prepared['wire']
    observed = wire.original_reader.stream_file(
        Path(original_run) / 'public/processes/public-original.stdout')
    expected = joined['wire']['original_reference']['public']['cases']
    first_success = None
    anonymous = None
    counts = collections.Counter()
    total_bytes = 0
    for (declared, input_wire), row, (header, body) in zip(wire.rows(), expected, observed, strict=True):
        assert declared['sequence'] == row['sequence'] == header[0]
        assert pin(input_wire) == row['input'] and pin(body) == row['output']
        classification = row['result_kind']
        compare_wire(declared, classification, body, body, 0, 60_000_000_000)
        counts[classification] += 1
        total_bytes += len(body)
        if classification == 'success' and first_success is None:
            first_success = (declared, body)
        if declared['frames'] == 2 and anonymous is None:
            first_line = json.loads(body.splitlines()[0])
            if 'error' in first_line and 'id' not in first_line:
                anonymous = (declared, classification, body)
    assert sum(counts.values()) == 1394
    assert counts == {'success': 600, 'business': 196, 'typed': 546, 'model': 24,
                      'initialize': 1, 'notification': 1, 'control': 24, 'close': 2}
    assert first_success is not None and anonymous is not None
    declared, original = first_success
    parsed = json.loads(original)
    identifier = parsed['id']
    assert type(identifier) is int
    needle = b'"id":' + str(identifier).encode()
    assert original.count(needle) == 1
    changed_id = original.replace(needle, b'"id":' + str(identifier + 1).encode(), 1)
    inner = json.loads(parsed['result']['content'][0]['text'])
    key = next(key for key in sorted(inner) if key != 'native_operation_wall_seconds')
    assert key.isascii()
    needle = b'\\"' + key.encode() + b'\\"'
    assert original.count(needle) == 1
    changed_key = original.replace(needle, b'\\"' + (key + '_changed').encode() + b'\\"', 1)
    match = WIRE_CLOCK.search(original)
    assert match is not None
    def clock(value):
        return original[:match.start(2)] + value + original[match.end(2):]
    controls = []
    mutations = [('changed-request-id', changed_id),
                 ('changed-solver-key', changed_key),
                 ('missing-final-LF', original[:-1]),
                 ('extra-response', original + original),
                 ('negative-clock', clock(b'-1')),
                 ('out-of-window-clock', clock(b'61'))]
    for name, changed in mutations:
        assert changed != original
        refusal = refuse(lambda: compare_wire(declared, 'success', original, changed, 0, 60_000_000_000))
        if collected is not None:
            collected.append((name, original, changed))
        controls.append({'name': name, 'sequence': declared['sequence'],
                         'original': pin(original), 'mutated': pin(changed), 'refusal': refusal})
    declared_bad, classification, original_bad = anonymous
    lines = original_bad.splitlines(keepends=True)
    assert lines[0].startswith(b'{')
    changed_bad = b'{"id":null,' + lines[0][1:] + b''.join(lines[1:])
    refusal = refuse(lambda: compare_wire(declared_bad, classification, original_bad, changed_bad, 0, 60_000_000_000))
    if collected is not None:
        collected.append(('anonymous-error-id-null', original_bad, changed_bad))
    controls.append({'name': 'anonymous-error-id-null', 'sequence': declared_bad['sequence'],
                     'original': pin(original_bad), 'mutated': pin(changed_bad), 'refusal': refusal})
    zero_clock = clock(b'0')
    assert checked_clock_wire(zero_clock)[0] == checked_clock_wire(original)[0]
    compare_wire(declared, 'success', original, zero_clock, 0, 60_000_000_000)
    if collected is not None:
        collected.append(('clock-only-normalization', original, zero_clock))
    return {'status': 'FRESH_ORIGINAL_COMPLETE_WIRE_CONTROLS_PASS',
            'records': 1394, 'classifications': dict(counts),
            'response_wire_bytes': total_bytes, 'refusals': controls,
            'clock_only_normalization_control': 'PASS',
            'actual_native_or_rust_executed': False, 'reader_writes': 0}


def session_inputs(capture, joined):
    folder = Path(capture) / 'session-0'
    process = document(folder / 'process/process.json')
    windows = []
    with journal_reader.regular(folder / 'responses.bin').open('rb') as stream:
        for header, body in native_records(stream):
            sequence, opcode, session, ilen, olen, before, after, jbefore, jafter, pid, zero = header
            assert session == 0 and pid == process['pid'] and zero == 0
            windows.append({'sequence': sequence, 'before': before, 'after': after,
                            'jbefore': jbefore, 'jafter': jafter,
                            'wire': body, 'closed': opcode == 2})
    original = [row for row in joined['wire']['original_reference']['public']['cases'] if row['session'] == 0]
    return folder / 'process/host-journal.bin', windows, original, process


def mutation_plan(capture, joined):
    path, _, _, _ = session_inputs(capture, joined)
    cases = joined['journal']['journals'][0]['case_bindings']
    selected = next(row for row in cases if row.get('raw_return') == 0 and row['jobs'])
    job = selected['jobs'][0]
    core = []
    last_writer = None
    terminal = None
    for offset, magic, raw in journal_reader.journal_records(path):
        if magic != b'HBCLOCK1' or journal_reader.get(raw, 16) != job:
            continue
        owner = journal_reader.get(raw, 32)
        if owner == 1 and len(core) < 2:
            core.append((offset, raw))
        if owner == 2:
            if journal_reader.get(raw, 96) == 14:
                assert last_writer is not None
                terminal = (offset, raw, last_writer)
            last_writer = (offset, raw)
    assert len(core) == 2 and terminal is not None
    assert core[0][1] != core[1][1] and terminal[1] != terminal[2][1]
    pairs = [('repeated-core-clock', core[0], core[1]),
             ('omitted-terminal-writer-clock', terminal[:2], terminal[2])]
    plan = []
    for name, before, replacement in pairs:
        assert len(before[1]) == len(replacement[1]) == 192
        plan.append({'name': name, 'session': 0, 'sequence': selected['sequence'], 'job': job,
                     'offset': before[0], 'replacement_observed_offset': replacement[0],
                     'before_hex': before[1].hex(), 'replacement_hex': replacement[1].hex(),
                     'record_bytes': 192})
    return path, plan


def copy_changed(source, destination, change):
    at = 0
    before = bytes.fromhex(change['before_hex'])
    replacement = bytes.fromhex(change['replacement_hex'])
    start = change['offset']
    with journal_reader.regular(source).open('rb') as source_stream, Path(destination).open('xb') as output:
        while raw := source_stream.read(1024 * 1024):
            end = at + len(raw)
            left, right = max(at, start), min(end, start + len(before))
            if left < right:
                assert raw[left - at:right - at] == before[left - start:right - start]
                raw = raw[:left - at] + replacement[left - start:right - start] + raw[right - at:]
            assert output.write(raw) == len(raw)
            at = end
    assert at >= start + len(before)


def compare_changed(source, destination, change):
    before = bytes.fromhex(change['before_hex'])
    replacement = bytes.fromhex(change['replacement_hex'])
    start, at = change['offset'], 0
    with journal_reader.regular(source).open('rb') as original, journal_reader.regular(destination).open('rb') as altered:
        while raw := original.read(1024 * 1024):
            actual = altered.read(len(raw))
            assert len(actual) == len(raw)
            end = at + len(raw)
            left, right = max(at, start), min(end, start + len(before))
            if left < right:
                assert raw[left - at:right - at] == before[left - start:right - start]
                raw = raw[:left - at] + replacement[left - start:right - start] + raw[right - at:]
            assert actual == raw, ('complete physical mutation differs', at)
            at = end
        assert altered.read(1) == b'' and at >= start + len(before)
    return {'bytes_compared': at, 'changed_record_bytes': len(before),
            'baseline': journal_reader.file_pin(source), 'mutated': journal_reader.file_pin(destination)}


def inspect_mutation(capture, joined, destination, *, prepared):
    _, windows, original, process = session_inputs(capture, joined)
    changed_process = copy.deepcopy(process)
    changed_process['journal'].update(journal_reader.file_pin(destination))
    return refuse(lambda: journal_reader.inspect_session(destination, windows, original,
                   changed_process, prepared['prepared_journal']))


def create(capture, original_run, joined, output, *, prepared):
    """Create fresh complete physical controls; call before installing the guard."""
    output = Path(output)
    output.mkdir(mode=0o700)
    collected = []
    comparator = comparator_controls(original_run, joined, prepared=prepared, collected=collected)
    wire_folder = output / 'wire-controls'
    wire_folder.mkdir(mode=0o700)
    assert len(collected) == 8
    for name, original, changed in collected:
        put(wire_folder / (name + '.original.bin'), original)
        put(wire_folder / (name + '.changed.bin'), changed)
    source, plan = mutation_plan(capture, joined)
    results = []
    for change in plan:
        folder = output / change['name']
        folder.mkdir(mode=0o700)
        destination = folder / 'host-journal.bin'
        copy_changed(source, destination, change)
        comparison = compare_changed(source, destination, change)
        refusal = inspect_mutation(capture, joined, destination, prepared=prepared)
        result = {'change': change, 'comparison': comparison, 'refusal': refusal}
        put(folder / 'CONTROL.json', result)
        results.append(result)
    result = {'status': 'COMPLETE_PUBLIC_READER_CONTROLS_PASS', 'wire': comparator,
              'physical_journal_refusals': results, 'native_or_rust_executions': 0}
    put(output / 'CONTROLS.json', result)
    return result


def verify(capture, original_run, joined, output, *, prepared):
    """Reread full already-created physical controls without writes or execution."""
    output = Path(output)
    source, plan = mutation_plan(capture, joined)
    expected_files = {'CONTROLS.json'}
    collected = []
    comparator = comparator_controls(original_run, joined, prepared=prepared, collected=collected)
    assert len(collected) == 8
    for name, original, changed in collected:
        for suffix, raw in (('original', original), ('changed', changed)):
            relative = 'wire-controls/' + name + '.' + suffix + '.bin'
            expected_files.add(relative)
            assert journal_reader.read(output / relative) == raw
    results = []
    for change in plan:
        folder = output / change['name']
        expected_files.update({change['name'] + '/host-journal.bin', change['name'] + '/CONTROL.json'})
        destination = folder / 'host-journal.bin'
        comparison = compare_changed(source, destination, change)
        refusal = inspect_mutation(capture, joined, destination, prepared=prepared)
        result = {'change': change, 'comparison': comparison, 'refusal': refusal}
        assert document(folder / 'CONTROL.json') == result
        results.append(result)
    files = set()
    directories = {'.'}
    for path in output.rglob('*'):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.add(path.relative_to(output).as_posix())
        else:
            assert stat.S_ISREG(mode)
            files.add(path.relative_to(output).as_posix())
    assert files == expected_files
    assert directories == {'.', 'wire-controls', *(row['name'] for row in plan)}
    result = {'status': 'COMPLETE_PUBLIC_READER_CONTROLS_PASS',
              'wire': comparator,
              'physical_journal_refusals': results, 'native_or_rust_executions': 0}
    assert document(output / 'CONTROLS.json') == result
    return result


def verify_observer_process_controls(output, *, prepared):
    """Read ten actual Python transport controls and all retained stream bytes."""
    output = Path(output)
    owner = prepared['observer_controls']
    summary = document(output / 'CONTROLS.json')
    assert summary['status'] == 'COMPLETE_OBSERVER_PROCESS_CONTROLS_PASS'
    assert summary['original_native_deadline_seconds'] == 180
    assert summary['original_exchange_deadline_seconds'] == 60
    assert summary['actual_native_or_rust_executed'] is False and summary['public_native_qualified'] is False
    assert len(owner.CASES) == len(summary['cases']) == 10
    assert summary['sources'] == {name: journal_reader.file_pin(ROOT / name)
        for name in ('capture_stdio.py', 'observer_process_controls.py')}
    binary = output / 'owned-python-stdio'
    assert journal_reader.file_pin(binary) == summary['fixture']
    assert stat.S_IMODE(binary.lstat().st_mode) == 0o700
    expected_files, expected_dirs = {'owned-python-stdio', 'CONTROLS.json'}, {'.'}
    cases = []
    for name, result in zip(owner.CASES, summary['cases'], strict=True):
        folder = output / name
        expected_dirs.update({name, name + '/process'})
        expected_files.update({name + '.stdout', name + '.stderr', name + '.process.json',
            name + '/CONTROL.json', name + '/config.json', name + '/process/host-journal.bin'})
        outer = document(output / (name + '.process.json'))
        stdout = journal_reader.read(output / (name + '.stdout'))
        stderr = journal_reader.read(output / (name + '.stderr'))
        assert outer['stdout'] == pin(stdout) and outer['stderr'] == pin(stderr) == pin(b'')
        assert outer['returncode'] == 0 and outer['timeout_seconds'] == 30
        assert type(outer['elapsed_ns']) is int and 0 <= outer['elapsed_ns'] <= 31_000_000_000
        command = outer['command']
        assert len(command) == 9 and command[1] == '-B'
        assert Path(command[2]).name == 'observer_process_controls.py'
        assert command[3:6] == ['--one', name, '--binary'] and command[7] == '--output'
        old_folder = Path(command[8])
        assert old_folder.is_absolute() and old_folder.name == name
        assert command[6] == str(old_folder.parent / 'owned-python-stdio')
        assert journal_reader.read(binary) == ('#!' + command[0] + '\n' + owner.FIXTURE).encode()
        assert stdout == (json.dumps(result, sort_keys=True) + '\n').encode()
        assert document(folder / 'CONTROL.json') == result
        assert journal_reader.read(folder / 'config.json') == encoded({})
        assert result['status'] == 'OWNED_PYTHON_OBSERVER_CONTROL_PASS' and result['case'] == name
        assert result['actual_native_or_rust_executed'] is False and result['public_native_qualified'] is False
        assert result['all_owned_streams_closed'] is True
        assert type(result['elapsed_ns']) is int and 0 <= result['elapsed_ns'] <= outer['elapsed_ns']
        assert len(result['spawned']) == int(name != 'occupied-owned-fd3')
        for child in result['spawned']:
            assert type(child['pid']) is int and child['pid'] > 0
            assert type(child['returncode']) is int and child['owned_group_absent'] is True
        if name == 'complete-streams':
            assert result['failure'] is None and result['spawned'][0]['returncode'] == 0
        else:
            assert isinstance(result['failure'], dict)
        if name.endswith('-enospc'):
            assert result['failure']['errno'] == 28
        if name == 'occupied-owned-fd3':
            assert result['failure'] == {'type': 'AssertionError',
                'message': 'fixed owned journal FD3 is unavailable', 'errno': None}
            expected_files.add(name + '/occupied.bin')
            assert journal_reader.read(folder / 'occupied.bin') == b''
            assert journal_reader.read(folder / 'process/host-journal.bin') == b''
            cases.append({'name': name, 'control': journal_reader.file_pin(folder / 'CONTROL.json'),
                          'process': outer, 'streams': {}})
            continue
        expected_files.add(name + '/process/exchanges.jsonl')
        raw_streams = {}
        for stream_name in ('attempted-stdin', 'stdin', 'stdout', 'stderr'):
            relative = name + '/process/' + stream_name + '.bin.gz'
            expected_files.add(relative)
            raw_streams[stream_name] = gzip.decompress(journal_reader.read(output / relative))
        if name != 'startup-receipt-enospc':
            expected_files.add(name + '/process/started.json')
            start = document(folder / 'process/started.json')
            assert start['command'] == [command[6], '--runtime-config', str(old_folder / 'config.json')]
            assert start['cwd'] == str(old_folder) and start['environment'] == {'PATH': '', 'LC_ALL': 'C'}
            assert start['pid'] == start['pgid'] == result['spawned'][0]['pid']
            assert type(start['parent_pid']) is int and start['parent_pid'] > 0
            assert start['binary'] == summary['fixture']
            assert start['journal_fd'] == 3 and start['deadline_seconds'] == 180
        if name != 'stream-close-enospc':
            expected_files.add(name + '/process/process.json')
            receipt = document(folder / 'process/process.json')
            assert receipt['schema'] == 'hepta.runtime.bellman-public-native-process.v1'
            assert receipt['command'] == [command[6], '--runtime-config', str(old_folder / 'config.json')]
            assert receipt['cwd'] == str(old_folder) and receipt['environment'] == {'PATH': '', 'LC_ALL': 'C'}
            assert receipt['pid'] == receipt['pgid'] == result['spawned'][0]['pid']
            assert receipt['returncode'] == result['spawned'][0]['returncode']
            assert receipt['deadline_seconds'] == 180 and receipt['exchange_deadline_seconds'] == 60
            assert receipt['private_owned_journal_fd'] == 3
            assert receipt['binary'] == receipt['binary_after'] == summary['fixture']
            assert set(receipt['streams']) == set(raw_streams)
            for stream_name, raw in raw_streams.items():
                row = receipt['streams'][stream_name]
                filename = stream_name + '.bin.gz'
                assert row['file'] == filename and row['uncompressed'] == pin(raw)
                assert row['compressed'] == journal_reader.file_pin(folder / 'process' / filename)
            for field, filename in (('journal', 'host-journal.bin'), ('exchanges', 'exchanges.jsonl')):
                assert receipt[field]['file'] == filename
                assert {key: receipt[field][key] for key in ('bytes', 'sha256')} == journal_reader.file_pin(folder / 'process' / filename)
            exchanges_raw = journal_reader.read(folder / 'process/exchanges.jsonl')
            exchanges = [json.loads(line) for line in exchanges_raw.splitlines()]
            assert len(exchanges) == receipt['exchanges']['records']
            if name == 'accepted-input-enospc':
                assert len(exchanges) == 1 and exchanges[0]['accepted_input']['bytes'] > 0
                assert exchanges[0]['ranges']['stdin']['bytes'] == 0 and exchanges[0]['error']['errno'] == 28
            if name == 'complete-streams':
                assert receipt['failure'] is None and receipt['cleanup_errors'] == []
                assert receipt['timed_out'] is False and receipt['kill_requested'] is False
                assert receipt['returncode'] == 0 and receipt['pipe_eof'] == {'stdout': True, 'stderr': True}
                assert receipt['pending_stdout'] == pin(b'')
        if name == 'complete-streams':
            wires = [b'NOTE\n', b'A' * (1024 * 1024 + 37) + b'\n', b'PAIR\n']
            expected = {'attempted-stdin': b''.join(wires), 'stdin': b''.join(wires),
                        'stdout': wires[1] + b'one\ntwo\n',
                        'stderr': b''.join(b'observed:' + len(value).to_bytes(8, 'little') for value in wires[1:])}
            assert raw_streams == expected
            assert journal_reader.read(folder / 'process/host-journal.bin') == b''.join(
                b'CONTROL1' + len(value).to_bytes(8, 'little') for value in wires)
        cases.append({'name': name, 'control': journal_reader.file_pin(folder / 'CONTROL.json'),
                      'process': outer, 'streams': {key: pin(value) for key, value in raw_streams.items()}})
    files, directories, inventory = set(), {'.'}, {}
    for path in output.rglob('*'):
        relative = path.relative_to(output).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.add(relative)
        else:
            assert stat.S_ISREG(mode)
            files.add(relative)
            inventory[relative] = journal_reader.file_pin(path)
    assert files == expected_files and directories == expected_dirs
    return {'status': 'COMPLETE_OBSERVER_PROCESS_CONTROL_READBACK_PASS',
            'actual_python_cases': 10, 'cases': cases, 'complete_file_bytes': inventory,
            'native_or_rust_executions': 0, 'reader_writes': 0,
            'public_native_qualified': False}
