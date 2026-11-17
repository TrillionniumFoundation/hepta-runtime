"""Read complete native stdio captures against the current, unchanged SDK oracle.

This layer proves bytes and process custody only. A final public qualification
must also admit the frozen host graph and read every host/worker journal with
the fixed SDK pump reader. No process, native image, or Rust binary is executed
by this module, and no input artifact is rewritten.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'reference'))
from wire_compare import compare_wire, native_records, pin
from observe_native import source_pin
from capture_stdio import encoded
import verify as original_reader
from wire_cases import rows, frame


def regular(path):
    assert stat.S_ISREG(path.lstat().st_mode), path
    return path


def read(path):
    return regular(path).read_bytes()


def document(path):
    return json.loads(read(path))


def file_pin(path):
    regular(path)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


def fixture_evidence(folder, process):
    before = document(folder / 'fixture-before.json')
    after = document(folder / 'fixture-after.json')
    fields = {'path', 'mode', 'dev', 'ino', 'uid', 'gid', 'nlink', 'mtime_ns', 'ctime_ns'}
    tables = []
    for rows in (before, after):
        table = {}
        for row in rows:
            path = PurePosixPath(row['path'])
            assert not path.is_absolute() and '..' not in path.parts
            assert str(path) == row['path'] and row['path'] not in table
            for field in fields - {'path'}:
                assert type(row[field]) is int and row[field] >= 0
            assert row['ino'] > 0 and row['nlink'] > 0
            if stat.S_ISREG(row['mode']):
                assert set(row) == fields | {'content_hex', 'bytes', 'sha256'}
                value = bytes.fromhex(row['content_hex'])
                assert row['content_hex'] == value.hex()
                assert pin(value) == {key: row[key] for key in ('bytes', 'sha256')}
            else:
                assert stat.S_ISDIR(row['mode']) and set(row) == fields
            table[row['path']] = row
        assert list(table) == ['.', *sorted(name for name in table if name != '.')]
        assert stat.S_ISDIR(table['.']['mode'])
        tables.append(table)
    initial, final = tables
    assert set(initial) == {'.', 'controller-state', 'workspace', 'runtime.json'}
    assert set(initial) <= set(final)
    assert all(name in initial or name.startswith('controller-state/') for name in final)
    root = PurePosixPath(process['command'][2]).parent
    assert root.name == 'fixture' and process['cwd'] == str(root / 'workspace')
    expected = {'state_dir': str(root / 'controller-state'),
                'controller_workspace_roots': [str(root / 'workspace')],
                'hosts': {'owned': {'ssh_target': 'not-contacted-owned-fixture',
                                   'remote_state_dir': '/unused-state'}}}
    assert bytes.fromhex(initial['runtime.json']['content_hex']) == encoded(expected)
    assert initial['runtime.json'] == final['runtime.json']
    for name in ('.', 'controller-state', 'workspace'):
        assert stat.S_IMODE(initial[name]['mode']) == 0o700
        assert all(initial[name][key] == final[name][key]
                   for key in ('mode', 'dev', 'ino', 'uid', 'gid'))
    assert stat.S_IMODE(initial['runtime.json']['mode']) == 0o600
    physical = folder / 'fixture'
    paths = [physical, *sorted(physical.rglob('*'))]
    assert {path.relative_to(physical).as_posix() for path in paths} == set(final)
    for path in paths:
        row = final[path.relative_to(physical).as_posix()]
        mode = path.lstat().st_mode
        assert mode == row['mode']
        if stat.S_ISREG(mode):
            assert read(path) == bytes.fromhex(row['content_hex'])
        else:
            assert stat.S_ISDIR(mode)
    return {'before': file_pin(folder / 'fixture-before.json'),
            'after': file_pin(folder / 'fixture-after.json'),
            'entries': len(final), 'all_owned_file_bytes_checked': True,
            'source_inode_identifiers_are_provenance': True}


class FullStream:
    def __init__(self, path, expected):
        assert expected['file'] == path.name
        assert file_pin(path) == expected['compressed']
        self.raw = path.open('rb')
        self.input = gzip.GzipFile(fileobj=self.raw, mode='rb')
        self.expected = expected['uncompressed']
        self.size = 0
        self.digest = hashlib.sha256()

    def exact(self, wanted):
        value = self.input.read(len(wanted))
        assert value == wanted
        self.size += len(value)
        self.digest.update(value)

    def remaining(self):
        while value := self.input.read(1024 * 1024):
            self.size += len(value)
            self.digest.update(value)

    def finish(self):
        try:
            assert self.input.read(1) == b''
            assert {'bytes': self.size, 'sha256': self.digest.hexdigest()} == self.expected
        finally:
            self.input.close()
            self.raw.close()

    def close(self):
        self.input.close()
        self.raw.close()


def session_admission(folder, expected_binary, producer_pid):
    report = document(folder / 'CAPTURE.json')
    assert report['status'] == 'ACTUAL_NATIVE_STDIO_BYTES_CAPTURED_READER_REQUIRED'
    assert report['session'] in (0, 1)
    for flag in ('native_graph_admitted_by_this_observer', 'public_handler_qualified',
                 'cross_session_pool_qualified'):
        assert report[flag] is False
    process = document(folder / 'process/process.json')
    started = document(folder / 'process/started.json')
    assert process == report['process']
    assert process['schema'] == 'hepta.runtime.bellman-public-native-process.v1'
    for key in ('pid', 'pgid', 'parent_pid', 'started_ns', 'finished_ns'):
        assert type(process[key]) is int and process[key] > 0
    assert process['pid'] == process['pgid'] and process['parent_pid'] == producer_pid
    assert process['returncode'] == 0 and process['failure'] is None
    assert process['timed_out'] is False and process['kill_requested'] is False
    assert process['cleanup_errors'] == [] and process['private_owned_journal_fd'] == 3
    assert process['pipe_eof'] == {'stdout': True, 'stderr': True}
    assert process['pending_stdout'] == pin(b'')
    assert process['deadline_seconds'] == 180 and process['exchange_deadline_seconds'] == 60
    assert process['started_ns'] <= process['finished_ns']
    assert process['finished_ns'] - process['started_ns'] <= 180_000_000_000
    assert process['binary'] == process['binary_after'] == expected_binary
    assert process['environment'] == {'PATH': '', 'LC_ALL': 'C'}
    assert len(process['command']) == 3 and process['command'][1] == '--runtime-config'
    assert all(Path(process['command'][index]).is_absolute() for index in (0, 2))
    assert Path(process['cwd']).is_absolute()
    fixture_evidence(folder, process)
    assert set(started) == {'command', 'cwd', 'environment', 'pid', 'pgid', 'parent_pid',
                            'started_ns', 'deadline_seconds', 'binary', 'journal_fd'}
    assert started['journal_fd'] == 3
    assert all(started[key] == process[key] for key in started if key != 'journal_fd')
    assert file_pin(folder / 'responses.bin') == report['output']
    assert set(process['streams']) == {'attempted-stdin', 'stdin', 'stdout', 'stderr'}
    journal = process['journal']
    assert journal['file'] == 'host-journal.bin'
    assert file_pin(folder / 'process' / journal['file']) == {k: journal[k] for k in ('bytes', 'sha256')}
    exchange_pin = process['exchanges']
    assert exchange_pin['file'] == 'exchanges.jsonl'
    raw = read(folder / 'process/exchanges.jsonl')
    assert pin(raw) == {k: exchange_pin[k] for k in ('bytes', 'sha256')}
    assert raw.endswith(b'\n')
    exchanges = [json.loads(line) for line in raw.splitlines()]
    assert len(exchanges) == exchange_pin['records']
    assert [row['index'] for row in exchanges] == list(range(len(exchanges)))
    assert {path.name for path in folder.iterdir()} == {
        'CAPTURE.json', 'responses.bin', 'fixture', 'fixture-before.json',
        'fixture-after.json', 'process'}
    assert {path.name for path in (folder / 'process').iterdir()} == {
        'process.json', 'started.json', 'host-journal.bin', 'exchanges.jsonl',
        'stdin.bin.gz', 'attempted-stdin.bin.gz', 'stdout.bin.gz', 'stderr.bin.gz'}
    streams = {}
    try:
        for name, value in process['streams'].items():
            streams[name] = FullStream(folder / 'process' / (name + '.bin.gz'), value)
    except BaseException:
        for stream in streams.values():
            stream.close()
        raise
    return report, process, exchanges, streams


def verify(capture, original_run, *, expected_binary):
    """Verify bytes after an external, strict frozen-graph admission step."""
    original = original_reader.verify(ROOT / 'reference', original_run)
    expected_rows = original['public']['cases']
    assert len(expected_rows) == 1394
    report = document(capture / 'CAPTURE.json')
    assert report['status'] == 'COMPLETE_NATIVE_STDIO_OBSERVATION_READER_REQUIRED'
    assert report['sources'] == document(capture / 'observer-source.json') == source_pin()
    assert report['binary'] == expected_binary
    assert report['records'] == 1394 and report['public_cases'] == 1366
    assert report['actual_native_processes'] == 2 and report['actual_sessions_per_process'] == 1
    assert report['original_reference_processes'] == 1 and report['original_sessions_per_process'] == 2
    assert report['process_deadline_seconds'] == 180 and report['exchange_deadline_seconds'] == 60
    assert report['producer_pid'] > 0 and report['producer_parent_pid'] > 0
    for flag in ('cross_session_pool_qualified', 'native_graph_admitted_by_this_observer',
                 'public_handler_qualified', 'whole_runtime_replaced'):
        assert report[flag] is False
    assert file_pin(capture / 'inputs.bin') == report['inputs']
    assert report['inputs'] == file_pin(original_run / 'public/public.stdin')
    index = document(capture / 'input-index.json')
    assert len(index) == 1394
    assert {path.name for path in capture.iterdir()} == {
        'CAPTURE.json', 'inputs.bin', 'input-index.json', 'observer-source.json',
        'session-0', 'session-1'}
    sessions = {}
    files = []
    streams = []
    try:
        for session in (0, 1):
            folder = capture / ('session-' + str(session))
            admitted, process, exchanges, full = session_admission(folder, expected_binary, report['producer_pid'])
            assert admitted == report['sessions'][session] and admitted['session'] == session
            handle = regular(folder / 'responses.bin').open('rb')
            files.append(handle)
            streams.extend(full.values())
            sessions[session] = {'report': admitted, 'process': process,
                'exchanges': exchanges, 'full': full, 'responses': native_records(handle),
                'last_after': process['started_ns'], 'last_journal': 0,
                'last_offsets': dict.fromkeys(full, 0), 'at': 0, 'closed': False, 'rows': 0}
        assert sessions[0]['process']['pid'] != sessions[1]['process']['pid']
        evidence = []
        original_stream = original_reader.stream_file(original_run / 'public/processes/public-original.stdout')
        with regular(capture / 'inputs.bin').open('rb') as corpus:
            for (declared, wire), expected, (old_header, old_wire) in zip(rows(), expected_rows, original_stream, strict=True):
                sequence = declared['sequence']
                assert expected['sequence'] == sequence and expected['input'] == pin(wire)
                raw = frame(declared, wire)
                assert index[sequence] == {'sequence': sequence, 'session': declared['session'],
                    'offset': corpus.tell(), **pin(raw)}
                assert corpus.read(len(raw)) == raw
                state = sessions[declared['session']]
                assert not state['closed']
                header, body = next(state['responses'])
                seq, opcode, session, input_length, output_length, before, after, jbefore, jafter, pid, zero = header
                assert (seq, opcode, session, input_length, output_length, pid, zero) == (
                    sequence, declared['opcode'], declared['session'], len(wire), len(body), state['process']['pid'], 0)
                assert state['last_after'] <= before <= after <= state['process']['finished_ns']
                assert after - before <= 60_000_000_000
                assert state['last_journal'] <= jbefore <= jafter <= state['process']['journal']['bytes']
                state['last_after'] = after
                state['last_journal'] = jafter
                assert old_header[:4] == (sequence, declared['opcode'], declared['session'], len(wire))
                compared = compare_wire(declared, expected['result_kind'], old_wire, body, before, after)
                if opcode == 1:
                    observed = state['exchanges'][state['at']]
                    for key in ('index', 'sequence', 'session', 'before_ns', 'after_ns',
                                'journal_before', 'journal_after'):
                        assert type(observed[key]) is int and observed[key] >= 0
                    assert observed['sequence'] == sequence and observed['session'] == session
                    assert observed['before_ns'] == before and observed['after_ns'] == after
                    assert observed['journal_before'] == jbefore and observed['journal_after'] == jafter
                    assert observed['deadline_seconds'] == 60 and observed['error'] is None
                    assert observed['timed_out'] is False
                    assert observed['attempted_input'] == observed['accepted_input'] == pin(wire)
                    assert set(observed['ranges']) == set(state['full'])
                    assert observed['responses'] == [pin(line) for line in body.splitlines(keepends=True)]
                    for name, wanted in [('attempted-stdin', wire), ('stdin', wire), ('stdout', body)]:
                        assert observed['ranges'][name] == {'offset': state['last_offsets'][name], 'bytes': len(wanted)}
                        state['full'][name].exact(wanted)
                        state['last_offsets'][name] += len(wanted)
                    stderr_range = observed['ranges']['stderr']
                    assert stderr_range['offset'] == state['last_offsets']['stderr']
                    state['last_offsets']['stderr'] += stderr_range['bytes']
                    state['at'] += 1
                else:
                    assert wire == body == b'' and jafter == state['process']['journal']['bytes']
                    assert after == state['process']['finished_ns']
                    state['closed'] = True
                state['rows'] += 1
                evidence.append(compared)
            assert corpus.read(1) == b''
        for state in sessions.values():
            assert state['closed'] and state['rows'] == state['report']['records']
            assert state['at'] == len(state['exchanges'])
            assert next(state['responses'], None) is None
            state['full']['stderr'].remaining()
            assert state['last_offsets']['stderr'] <= state['full']['stderr'].size
            for stream in state['full'].values():
                stream.finish()
        return {'status': 'COMPLETE_PUBLIC_WIRE_PARITY_PROCESS_LAYER_PASS',
                'records': len(evidence), 'public_cases': 1366,
                'response_count': original['public']['response_count'],
                'original_reference': original,
                'only_normalized_field': 'native_operation_wall_seconds',
                'complete_wire_bytes_compared': True, 'cases': evidence,
                'native_processes': 2, 'sessions_per_native_process': 1,
                'host_graph_and_journal_reader_required': True,
                'native_or_rust_executed_by_reader': False,
                'verified_tree_writes': False, 'public_handler_qualified': False,
                'cross_session_pool_qualified': False, 'whole_runtime_replaced': False}
    finally:
        for stream in streams:
            stream.close()
        for handle in files:
            handle.close()
