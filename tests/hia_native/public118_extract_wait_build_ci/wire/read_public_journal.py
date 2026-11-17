"""Read every fixed-FD3 port/worker journal for the unchanged serial1394 domain.

The caller first admits the fresh public graph and invokes unchanged read_wire.
This module never executes a HIA image, a native process, or a Rust binary.
It verifies the existing port continuation and worker projection contracts;
it does not claim the request-task asynchronous domain or cross-session pools.
"""
from __future__ import annotations
import collections
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
import types

sys.dont_write_bytecode = True
PACKAGE_SHA = '2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1'
DELIVERY = 0xffffffcd
WORKER_MAGICS = {b'HBWPL001', b'HBCLOCK1', b'HBPWHLD1', b'HBWPEND1', b'HBWPROC1'}
PORT_MAGICS = {b'HBPWIN01', b'HBPMSR01', b'HBPAC001', b'HBPAA001'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def regular(path):
    path = Path(path)
    assert stat.S_ISREG(path.lstat().st_mode), str(path)
    return path


def read(path):
    return regular(path).read_bytes()


def file_pin(path):
    path = regular(path)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


def get(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def words(raw):
    assert len(raw) % 8 == 0
    return struct.unpack('<' + 'Q' * (len(raw) // 8), raw)


def package_sources(root):
    root = Path(root)
    raw = read(root / 'PACKAGE.json')
    assert pin(raw)['sha256'] == PACKAGE_SHA
    manifest = json.loads(raw)
    assert manifest['schema'] == 'hepta.runtime.bellman-public-port-source.v1'
    assert manifest['runtime_hia_images'] == 8
    assert manifest['worker_source_pins_sha256'] == '6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2'
    assert len(manifest['files']) == 142
    actual = set()
    directories = {'.'}
    for path in root.rglob('*'):
        mode = path.lstat().st_mode
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(mode):
            directories.add(name)
        else:
            assert stat.S_ISREG(mode), name
            actual.add(name)
    assert actual == set(manifest['files']) | {'PACKAGE.json'}
    expected_directories = {'.'}
    for name, expected in manifest['files'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert relative.as_posix() == name
        assert file_pin(root / relative) == expected, name
        expected_directories.update(parent.as_posix() for parent in relative.parents)
    assert directories == expected_directories
    return {'package': pin(raw), 'files': manifest['files']}


def prepare(port_package):
    """Preload the unchanged pure worker checker before any read-only guard."""
    root = Path(port_package).resolve(strict=True)
    sources = package_sources(root)
    path = root / 'recipe/worker_projection.py'
    raw = read(path)
    module = types.ModuleType('_public_wire_frozen_worker_projection')
    module.__file__ = str(path)
    module.__package__ = None
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return {'root': root, 'sources': sources, 'projection': module,
            'projection_source': pin(raw)}


def journal_records(path):
    size = regular(path).stat().st_size
    at = 0
    with path.open('rb') as stream:
        while at < size:
            prefix = stream.read(16)
            assert len(prefix) == 16, ('partial journal header', at)
            magic = prefix[:8]
            extent = get(prefix, 8)
            assert magic in WORKER_MAGICS | PORT_MAGICS
            assert 16 <= extent <= min(128 << 20, size - at), (magic, extent)
            tail = stream.read(extent - 16)
            assert len(tail) == extent - 16
            if magic == b'HBWPL001':
                assert extent == 256
            if magic == b'HBCLOCK1':
                assert extent == 192
            if magic in {b'HBPWHLD1', b'HBWPROC1'}:
                assert extent == 64
            if magic in {b'HBPAC001', b'HBPAA001'}:
                assert extent == 144
            yield at, magic, prefix + tail
            at += extent
        assert at == size and stream.read(1) == b''


def inspect_session(journal, windows, original_rows, process, prepared):
    """Verify a complete physical journal against already-admitted response windows."""
    projection = prepared['projection']
    assert process['private_owned_journal_fd'] == 3
    assert file_pin(journal) == {key: process['journal'][key] for key in ('bytes', 'sha256')}
    assert windows and len(windows) == len(original_rows)
    expected = {row['sequence']: row for row in original_rows}
    assert len(expected) == len(original_rows)
    assert [window['sequence'] for window in windows] == list(expected)
    for window in windows:
        assert window['before'] <= window['after']
        assert 0 <= window['jbefore'] <= window['jafter'] <= process['journal']['bytes']
    assert windows[-1]['closed']
    requests, outputs, actions = [], [], []
    action = None
    pending, sequences, tags, submitted, taken, ready = {}, {}, {}, {}, {}, {}
    admitted_jobs = {}
    last_magic = None
    by_case = {window['sequence']: [] for window in windows}
    window_index = 0
    frame_count = 0
    for at, magic, raw in journal_records(journal):
        frame_count += 1
        last_magic = magic
        if magic == b'HBPAC001':
            assert action is None
            while window_index < len(windows) and at >= windows[window_index]['jafter']:
                window_index += 1
            assert window_index < len(windows), ('port action outside a public exchange', at)
            window = windows[window_index]
            assert not window['closed']
            assert window['jbefore'] <= at < window['jafter']
            tag = get(raw, 16)
            d = words(raw[32:])
            assert tag > 0 and raw[32:40] == b'HBLCAC01'
            assert get(raw, 24) == admitted_jobs.get(tag, 0)
            assert d[1] > 0 and d[2] <= 2 and d[3] <= 1 and d[8:] == (0,) * 6
            if tag in tags:
                assert tags[tag] == window['sequence'], 'private tag crossed public requests'
            else:
                tags[tag] = window['sequence']
            if d[3] == 0:
                assert d[1] > sequences.get(tag, 0)
                sequences[tag] = d[1]
            else:
                assert tag in pending and (d[1], d[2], d[5]) == pending[tag][:3]
            action = {'before': raw, 'offset': at, 'requests': [], 'outputs': [],
                      'sequence': window['sequence'], 'window': window}
            actions.append(action)
            by_case[window['sequence']].append(action)
        elif magic == b'HBPWIN01':
            request = raw[16:]
            assert len(request) >= 64 and request[:8] == b'HBWKRQ01'
            assert len(request) == 64 + get(request, 40)
            assert get(request, 8) in (1, 2, 3, 4)
            assert get(request, 32) == get(request, 48) == get(request, 56) == 0
            assert action is not None and get(action['before'], 48) == 2
            assert get(action['before'], 56) == 0
            assert get(request, 16) == get(action['before'], 16)
            requests.append(request)
            action['requests'].append(request)
        elif magic == b'HBPMSR01':
            assert len(raw) >= 192 and len(raw) == 192 + get(raw, 48)
            assert get(raw, 8) == len(raw) and get(raw, 56) == 0
            event, tag, job = get(raw, 16), get(raw, 24), get(raw, 32)
            assert event in (1, 2)
            outputs.append(raw)
            if event == 1:
                assert action is not None
                action['outputs'].append(raw)
                assert len(action['requests']) == 1
                request = action['requests'][0]
                command = get(request, 8)
                assert tag == get(request, 16)
                if command == 1:
                    assert tag not in admitted_jobs
                    admitted_jobs[tag] = job
                if command == 1 and job:
                    assert job not in submitted
                    submitted[job] = {'tag': tag, 'sequence': action['sequence'],
                                      'request': request, 'submit_reply': raw}
                if get(raw, 48):
                    assert command == 4 and job in submitted and job in ready
                    assert job not in taken
                    assert submitted[job]['sequence'] == action['sequence']
                    taken[job] = {'body': raw[192:], 'response': raw,
                                  'sequence': action['sequence']}
            else:
                assert job in submitted and job not in ready
                assert tag == submitted[job]['tag'] and get(raw, 48) == 0
                ready[job] = raw
        elif magic == b'HBPAA001':
            assert action is not None
            before = action['before']
            d, ack = words(before[32:]), words(raw[32:])
            tag = get(raw, 16)
            assert tag == get(before, 16) and raw[32:96] == before[32:96]
            assert get(raw, 24) == admitted_jobs.get(tag, 0)
            assert ack[8] == d[1] and ack[10:12] == (0, 0) and ack[13] == 0 and ack[12] > 0
            assert ack[9] == (ack[12] if ack[12] <= ack[7] else DELIVERY)
            if d[3] == 1:
                assert not action['requests'] and not action['outputs']
                assert ack[12] == pending[tag][3]
            elif d[2] == 2:
                assert len(action['requests']) == len(action['outputs']) == 1
                response, request = action['outputs'][0], action['requests'][0]
                assert get(response, 24) == tag
                assert get(request, 8) == 1 or get(response, 32) == get(request, 24)
                assert ack[12] == len(response)
            else:
                assert not action['requests'] and not action['outputs']
            if ack[9] == DELIVERY:
                pending[tag] = (d[1], d[2], d[5], ack[12])
            else:
                pending.pop(tag, None)
            action['after'] = raw
            action['end'] = at + len(raw)
            assert action['end'] <= action['window']['jafter']
            action = None
    assert action is None and not pending and last_magic == b'HBWPEND1'
    worker = projection.verify_projection(requests, outputs,
        ((magic, raw) for _, magic, raw in journal_records(journal)
         if magic in WORKER_MAGICS), process['pid'])
    assert set(submitted) == set(taken) == set(ready)
    assert worker['jobs'] == worker['physical_clones'] == worker['physical_reaps'] == len(submitted)
    assert worker['held_jobs'] == worker['successful_complete_without_take'] == 0
    evidence = []
    last_started = 0
    for window in windows:
        sequence = window['sequence']
        old = expected[sequence]
        started = old['started'] - last_started
        assert started in (0, 1)
        last_started = old['started']
        actual_actions = by_case[sequence]
        primary = [item for item in actual_actions if get(item['before'], 56) == 0]
        param = sum(get(item['before'], 48) == 0 for item in primary)
        diagnostic = sum(get(item['before'], 48) == 1 for item in primary)
        assert param == int(old['model_kind'] == 1), ('actual typed dispatch', sequence)
        assert diagnostic == int(old['model_kind'] == 1 and old['model_status'] == 1)
        jobs = [job for job, info in submitted.items() if info['sequence'] == sequence]
        assert len(jobs) == started, ('actual worker admission', sequence, jobs, started)
        result = {'sequence': sequence, 'actions': len(actual_actions),
                  'params': param, 'diagnostic': diagnostic, 'jobs': jobs}
        if jobs:
            job = jobs[0]
            body = taken[job]['body']
            header, parts, value = projection.decode_body(body)
            assert header[10] == 0
            assert window['before'] <= header[5] <= header[6] <= window['after']
            assert old['model_kind'] == 1 and old['model_status'] in (0, 2)
            if old['model_status'] == 0:
                assert header[9] == 0 and old['result_kind'] == 'success'
                message = json.loads(window['wire'])
                text = message['result']['content'][0]['text'].encode('utf-8')
                assert text == parts[2][64:], 'public text differs from actual worker renderer bytes'
            else:
                assert header[9] != 0 and old['result_kind'] == 'business' and value is None
            result.update(job_body=pin(body), core=pin(parts[0]), commitment=pin(parts[1]),
                          result=pin(parts[2]), start_ns=header[5], finish_ns=header[6],
                          elapsed_sample_ns=header[11], raw_return=header[9])
        evidence.append(result)
    assert last_started == len(submitted)
    return {'status': 'COMPLETE_SERIAL_PUBLIC_WORKER_JOURNAL_PASS',
            'journal': file_pin(journal), 'records': frame_count, 'worker': worker,
            'actions': len(actions), 'mode1_actions': sum(get(a['before'], 56) == 1 for a in actions),
            'private_tags': len(tags), 'actual_worker_controls': len(requests),
            'ready_events': len(ready), 'case_bindings': evidence,
            'all_successful_rendered_text_bound_to_public_wire': True,
            'all_port_actions_bound_to_observed_exchange': True,
            'async_request_task_domain_qualified': False,
            'cross_session_pool_qualified': False,
            'native_or_rust_executions': 0, 'reader_writes': 0}


def verify(capture, wire_evidence, *, prepared):
    """Join two complete journals to the unchanged read_wire.verify result."""
    from wire_compare import native_records
    capture = Path(capture)
    assert package_sources(prepared['root']) == prepared['sources']
    assert pin(read(prepared['root'] / 'recipe/worker_projection.py')) == prepared['projection_source']
    assert wire_evidence['status'] == 'COMPLETE_PUBLIC_WIRE_PARITY_PROCESS_LAYER_PASS'
    assert wire_evidence['records'] == 1394 and wire_evidence['public_cases'] == 1366
    original = wire_evidence['original_reference']['public']
    assert original['records'] == 1394
    result = []
    for session in (0, 1):
        folder = capture / ('session-' + str(session))
        process = json.loads(read(folder / 'process/process.json'))
        original_rows = [row for row in original['cases'] if row['session'] == session]
        windows = []
        with regular(folder / 'responses.bin').open('rb') as stream:
            for header, body in native_records(stream):
                seq, opcode, sid, input_length, output_length, before, after, jbefore, jafter, pid, zero = header
                assert sid == session and pid == process['pid'] and zero == 0
                windows.append({'sequence': seq, 'before': before, 'after': after,
                    'jbefore': jbefore, 'jafter': jafter, 'wire': body, 'closed': opcode == 2})
        item = inspect_session(folder / 'process/host-journal.bin', windows, original_rows, process, prepared)
        assert item['worker']['jobs'] == original['per_session_counts'][session][1]
        result.append(item)
    assert sum(len(row['case_bindings']) for row in result) == 1394
    return {'status': 'COMPLETE_SERIAL_PUBLIC_WIRE_AND_JOURNAL_PASS',
            'records': 1394, 'native_processes': 2, 'sessions_per_native_process': 1,
            'journals': result, 'port_package_sha256': PACKAGE_SHA,
            'requires_fresh_public_graph_admission': True,
            'full_sdk_qualified': False, 'async_pending_registry_qualified': False,
            'cross_session_pool_qualified': False, 'public_handler_qualified': False,
            'whole_runtime_replaced': False, 'native_or_rust_executions': 0, 'reader_writes': 0}
