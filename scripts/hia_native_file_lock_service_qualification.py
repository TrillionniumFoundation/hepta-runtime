"""Inspect complete lock-service artifacts and actual completed executions."""
from __future__ import annotations
import collections
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'scripts', ROOT / 'tests/hia_native'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import hia_native_file_lock_qualification as base
from hia_native_file_lock_service_build import (
    inspect_bundle, source_contract as imported_contract, source_pins, IMAGES,
    PREFIX_SIZE, PREFIX_SHA, TABLE, EXECUTABLE_SHA, read, obj, sha, canonical,
    exact, require, file_record,
)
import file_lock_key_cases
import file_lock_key_kernel
import file_lock_service_kernel
import test_file_lock_service
from hia_native_atomic_write_build import pairs

OWN = (
    'native/file_lock_service.hepta', 'native/file_lock_service_composition.json',
    'native/file_lock_service_packer.hepta', 'native/file_lock_service_layout.json',
    'native/file_lock_service_abi.md', 'scripts/hia_native_file_lock_service_build.py',
    'scripts/hia_native_file_lock_service_qualification.py',
    'tests/hia_native/test_file_lock_service.py', 'tests/hia_native/test_file_lock_service_contract.py',
    'tests/hia_native/test_file_lock_service_evidence.py', 'tests/hia_native/file_lock_service_kernel.py',
    'tests/hia_native/file_lock_service_supervisor.py', 'tests/hia_native/oracle_file_lock_service.rs',
    'tests/hia_native/compare_file_lock_service_original.py',
    'tests/hia_native/file_lock_service_oracle/Cargo.toml',
    'tests/hia_native/file_lock_service_oracle/Cargo.lock',
    'tests/hia_native/file_lock_service_oracle/build.rs',
)
SERVICE_ROWS = 237424
SERIAL_ROWS = 231214
CONCURRENT_ROWS = 6210
ORIGINAL_CONCURRENT = {'status': 'PASS', 'original_owner_operations': 6210,
    'mutual_exclusion_rounds': 128, 'retained_growth_leases': 2080,
    'operation_counts': [0, 2592, 0, 512, 384, 128, 2592, 2], 'actual_std_threads': 5184}


def pins(root=ROOT):
    root = Path(root)
    return dict(base.pins(root), **{name: file_record(root / name) for name in OWN})


def source_contract(root=ROOT, hepta=None):
    root = Path(root)
    original = base.source_contract(root)
    source_pins(root)
    for module in (base, file_lock_key_cases, file_lock_key_kernel, file_lock_service_kernel,
                   test_file_lock_service):
        name = Path(module.__file__).name
        relative = ('scripts/' if name.startswith('hia_') else 'tests/hia_native/') + name
        exact(read(module.__file__), read(root / relative), 'loaded service evidence dependency differs')
    exact(read(root / 'tests/hia_native/file_lock_service_oracle/build.rs'),
        read(root / 'tests/hia_native/file_lock_oracle/build.rs'), 'service original owner extraction differs')
    lock = tomllib.loads(read(root / 'tests/hia_native/file_lock_service_oracle/Cargo.lock').decode())
    for name, value in original['locked_dependencies'].items():
        found = [item for item in lock['package'] if item['name'] == name]
        exact(len(found), 1, 'service original locked dependency missing')
        for key in ('version', 'checksum'):
            exact(found[0][key], value[key], 'service original locked dependency changed')
    if hepta is not None:
        imported_contract(hepta, root)
    return {'source_files': pins(root), 'controller_imported_functions': 4,
        'original_owner_bytes': original['original_owner_bytes'],
        'original_owner_sha256': original['original_owner_sha256'],
        'locked_dependencies': original['locked_dependencies'],
        'asynchronous_wait_scheduler_closed': False, 'upper_file_io_closed': False,
        'whole_runtime_replaced': False, 'production_activated': False}


def completed(summary, stdout):
    require(stdout is not None, 'actual completed service process stdout is mandatory')
    exact(obj(stdout), summary, 'actual completed service stdout differs')
    return file_record(stdout)


def array_value(path):
    value = json.loads(read(path), object_pairs_hook=pairs)
    require(type(value) is list, 'service artifact must contain an array')
    return value


def fixture_evidence(directory, record, *, expected_path=None):
    directory = Path(directory)
    exact(record['file'], 'fixture.json.gz', 'service fixture filename differs')
    path = directory / record['file']
    exact(file_record(path), {key: record[key] for key in ('bytes', 'sha256')}, 'service fixture archive changed')
    exact(base.gzip_record(path), {'bytes': record['raw_bytes'], 'sha256': record['raw_sha256']},
        'service complete fixture bytes changed')
    captured = json.loads(gzip.decompress(read(path)))
    exact(captured['schema'], 'hepta.runtime.file-lock-fixture.v1', 'service fixture schema differs')
    require(Path(captured['path']).is_absolute(), 'service fixture path must be absolute')
    if expected_path is not None:
        exact(captured['path'], str(expected_path), 'service fixture origin differs')
    exact(record['entries'], len(captured['entries']), 'service fixture entries omitted')
    exact(record['retired'], True, 'service fixture retirement incomplete')
    require(not (directory / 'fixture').exists(), 'service live fixture was retained in artifact output')
    previous = None
    for row in captured['entries']:
        name = bytes.fromhex(row['path_hex'])
        require(name and not name.startswith(b'/') and b'\0' not in name, 'fixture relative path differs')
        require(all(part not in (b'', b'.', b'..') for part in name.split(b'/')), 'fixture path escapes its owner')
        require(previous is None or previous < name, 'fixture path order or uniqueness differs')
        previous = name
        require(type(row['mode']) is int and 0 <= row['mode'] <= 0o7777, 'fixture mode differs')
        if row['kind'] == 'file':
            raw = bytes.fromhex(row['data_hex'])
            exact((len(raw), sha(raw)), (row['bytes'], row['sha256']), 'fixture complete file bytes differ')
        else:
            require(row['kind'] in ('symlink', 'directory'), 'fixture kind differs')
    return captured, {'file': file_record(path), 'raw': base.gzip_record(path), 'entries': len(captured['entries'])}


def session_evidence(folder, value, *, binary_sha, serial, rows, binary_path=None):
    folder = Path(folder)
    exact(obj(folder / 'result.json'), value, 'service session result changed')
    for key, wanted in {'status': 'PASS', 'actual_elf_requests': rows, 'exit_code': 0,
        'response_timeout_seconds': 30, 'shutdown_timeout_seconds': 10}.items():
        exact(value.get(key), wanted, 'service actual session differs: ' + key)
    base.duration(value['elapsed'], 'service session missed unchanged suite budget')
    require(type(value['command']) is list and len(value['command']) == 1 and Path(value['command'][0]).is_absolute(),
        'service actual command differs')
    exact(Path(value['command'][0]).name, 'file-lock-service.elf', 'service actual executable entry differs')
    if binary_path is not None:
        exact(value['command'], [str(binary_path)], 'service command differs from its inspected bundle')
    require(Path(value['cwd']).is_absolute(), 'service actual cwd is not recorded')
    names = ('requests.bin.gz', 'native-wire.bin.gz', 'native-output.bin.gz', 'native.stderr')
    exact(set(value['files']), set(names), 'service complete session channels differ')
    exact({item.name for item in folder.iterdir()}, {*names, 'result.json'}, 'service session artifact set differs')
    files = {}
    for name in names:
        record = file_record(folder / name)
        exact(value['files'][name], record, 'service actual session file changed')
        if name.endswith('.gz'):
            raw = base.gzip_record(folder / name)
            if name != 'requests.bin.gz':
                exact(raw['bytes'], rows * (84 if name == 'native-wire.bin.gz' else 76), 'service full response extent differs')
            record = dict(record, raw_bytes=raw['bytes'], raw_sha256=raw['sha256'])
        files[name] = record
    exact(read(folder / 'native.stderr'), b'', 'service native session emitted stderr')
    tids, tags = set(), set()
    with gzip.open(folder / 'requests.bin.gz', 'rb') as incoming, gzip.open(folder / 'native-wire.bin.gz', 'rb') as wire, \
         gzip.open(folder / 'native-output.bin.gz', 'rb') as logical:
        for index in range(rows):
            header = incoming.read(16)
            require(len(header) == 16, 'service input header truncated')
            length, tag = struct.unpack('<QQ', header)
            require(64 <= length <= (5 << 20) + 64, 'service corpus input extent differs')
            exact(tag, index + 1, 'service input tag sequence differs')
            payload = incoming.read(length)
            require(len(payload) == length and payload[:8] == b'HRLKSRV1', 'service complete input frame differs')
            actual = wire.read(84)
            require(len(actual) == 84, 'service actual output frame truncated')
            reply_tag, tid, code = struct.unpack_from('<QQI', actual)
            require(1 <= reply_tag <= rows and reply_tag not in tags and tid > 0, 'service response correlation differs')
            if serial:
                exact(reply_tag, tag, 'serial service output reordered')
            exact(code, 64, 'service valid corpus response refused')
            exact(actual[20:28], b'HRFLKR01', 'service response header differs')
            exact(logical.read(76), actual[:8] + actual[16:], 'normalized service output differs from actual thread output')
            tags.add(reply_tag); tids.add(tid)
        for stream in (incoming, wire, logical):
            exact(stream.read(), b'', 'service complete stream contains extra rows')
    exact(value['native_thread_ids'], sorted(tids), 'service actual thread identities changed')
    require(1 <= len(tids) <= 4, 'service observed thread count differs from its fixed pool')
    return {'result': file_record(folder / 'result.json'), 'files': files, 'rows': rows, 'session': value['session'],
        'native_thread_ids': sorted(tids), 'binary_sha256': binary_sha}


def serial_pair(inputs, outputs):
    header = inputs.read(16)
    require(len(header) == 16, 'service serial input missing')
    size, tag = struct.unpack('<QQ', header)
    require(64 <= size <= (5 << 20) + 64, 'service serial input extent differs')
    wire = inputs.read(size); answer = outputs.read(76)
    require(len(wire) == size and len(answer) == 76, 'service serial row truncated')
    exact(answer[:12], struct.pack('<QI', tag, 64), 'service serial output tag differs')
    return wire, answer[12:]


def native_evidence(bundle, directory, state_corpus, *, source_root=ROOT, hepta=None, stdout):
    root, directory, state_corpus = Path(source_root), Path(directory), Path(state_corpus)
    before = pins(root); closure = source_contract(root, hepta); artifact = inspect_bundle(bundle, source_root=root)
    value = obj(directory / 'result.json')
    recorded_bundle = Path(value['bundle_path'])
    require(recorded_bundle.is_absolute() and recorded_bundle.name == 'manifest.json', 'service execution bundle path differs')
    binary_path = recorded_bundle.parent / 'file-lock-service.elf'
    for key, wanted in {'schema': 'hepta.runtime.file-lock-service-native.v1', 'status': 'PASS',
        'groups': 3, 'actual_original_calls': 0, 'original_status': 'PENDING',
        'production_activated': False, 'full_edit_chain_closed': False, 'bundle_artifacts': artifact,
        'executable': {'bytes': artifact['executable']['inspection']['bytes'], 'sha256': EXECUTABLE_SHA}}.items():
        exact(value.get(key), wanted, 'service complete native receipt differs: ' + key)
    base.duration(value['elapsed'], 'service native suite missed unchanged budget')
    exact(value['sources'], {name: file_record(root / name) for name in test_file_lock_service.SOURCES}, 'service actual source set changed')
    exact(set(value['results']), {'state', 'canonical', 'concurrent'}, 'service native domain omitted')
    exact(base.gzip_record(state_corpus / 'requests.bin.gz', base.STATE_INPUT), dict(zip(('bytes', 'sha256'), base.STATE_INPUT)), 'state input bridge differs')
    base.gzip_record(state_corpus / 'native-output.bin.gz', base.STATE_OUTPUT)
    state = value['results']['state']
    for key, wanted in {'status': 'PASS', 'actual_elf_requests': 51783, 'original_reference_bridge_rows': 51783,
        'excluded_fixture_lifecycle_rows': 46, 'input_source': file_record(state_corpus / 'requests.bin.gz'),
        'expected_source': file_record(state_corpus / 'native-output.bin.gz')}.items():
        exact(state.get(key), wanted, 'service state bridge differs')
    exact(len(state['sessions']), 23, 'service complete state sessions omitted')
    state_sessions, count = [], 0
    active = inputs = outputs = None
    with gzip.open(state_corpus / 'requests.bin.gz', 'rb') as original_inputs, gzip.open(state_corpus / 'native-output.bin.gz', 'rb') as original_outputs:
        try:
            while header := original_inputs.read(16):
                require(len(header) == 16, 'state bridge header truncated')
                sid, size = struct.unpack('<QQ', header)
                packet, expected = original_inputs.read(size), original_outputs.read(64)
                require(len(packet) == size and len(expected) == 64, 'state bridge row truncated')
                op, ident = struct.unpack_from('<2Q', packet, 8)
                if op == 0:
                    require(active is None, 'state bridge session overlaps')
                    active = sid; folder = directory / 'state' / ('session-' + str(sid)); session_count = 0
                    inputs = gzip.open(folder / 'requests.bin.gz', 'rb'); outputs = gzip.open(folder / 'native-output.bin.gz', 'rb')
                elif op == 9:
                    exact(sid, active, 'state bridge lifecycle differs')
                    exact(inputs.read(), b'', 'state session has extra requests'); exact(outputs.read(), b'', 'state session has extra responses')
                    inputs.close(); outputs.close(); inputs = outputs = None
                    observed = state['sessions'][len(state_sessions)]
                    exact(observed['session'], sid, 'state session order changed')
                    state_sessions.append(session_evidence(folder, observed, binary_sha=EXECUTABLE_SHA, serial=True, rows=session_count, binary_path=binary_path))
                    active = None
                else:
                    exact(sid, active, 'state bridge session identity changed')
                    wire, answer = serial_pair(inputs, outputs)
                    exact(wire, test_file_lock_service.request(op, ident, kind=1 if op == 1 else 0, path=packet[64:]), 'state-to-service input adaptation changed')
                    exact(answer, expected, 'complete original state result differs')
                    session_count += 1; count += 1
            exact(original_outputs.read(), b'', 'state bridge has extra output')
        finally:
            if inputs is not None: inputs.close()
            if outputs is not None: outputs.close()
    exact((count, active, len(state_sessions)), (51783, None, 23), 'complete state bridge differs')
    exact({item.name for item in (directory / 'state').iterdir()},
        {'session-' + str(item['session']) for item in state['sessions']}, 'state session artifact set differs')
    canonical = value['results']['canonical']; folder = directory / 'canonical'
    for key, wanted in {'status': 'PASS', 'key_requests': 89715, 'actual_elf_requests': 179431,
        'fresh_original_status': 'PENDING'}.items():
        exact(canonical.get(key), wanted, 'canonical service domain differs')
    canonical_session = session_evidence(folder / 'process', canonical['process'], binary_sha=EXECUTABLE_SHA, serial=True, rows=179431, binary_path=binary_path)
    counts = collections.Counter()
    with gzip.open(folder / 'process/requests.bin.gz', 'rb') as incoming, gzip.open(folder / 'process/native-output.bin.gz', 'rb') as answers:
        for domain, packet in file_lock_key_cases.requests():
            kind, npath, nhost, port = struct.unpack_from('<4Q', packet, 8)
            wire, answer = serial_pair(incoming, answers)
            exact(wire, test_file_lock_service.request(1, kind=kind, path=packet[64:64 + npath], host=packet[64 + npath:], port=port), 'complete canonical service input changed')
            fields = struct.unpack('<7Q', answer[8:]); exact(fields[:2], (1, 0), 'canonical admission failed')
            require(fields[2] > 0 and fields[3] > 0 and fields[5] == 2 and fields[6] == 0, 'canonical admission ownership differs')
            wire, released = serial_pair(incoming, answers)
            exact(wire, test_file_lock_service.request(6, fields[2]), 'canonical lease release missing')
            exact(struct.unpack('<7Q', released[8:]), (6, 0, fields[2], fields[3], fields[4], 1, 0), 'canonical release result differs')
            counts[domain] += 1
        wire, answer = serial_pair(incoming, answers)
        exact(wire, test_file_lock_service.request(7), 'canonical terminal statistics missing')
        exact(struct.unpack('<7Q', answer[8:])[5], 0, 'canonical leases leaked')
        exact(incoming.read(), b'', 'canonical service input has extra rows'); exact(answers.read(), b'', 'canonical output has extra rows')
    exact(dict(counts), {'local': 89499, 'remote': 216}, 'canonical original domain omitted')
    captured, canonical_fixture = fixture_evidence(folder, canonical['fixture'], expected_path=canonical['process']['cwd'])
    concurrent = concurrent_evidence(directory / 'concurrent', value['results']['concurrent'], binary_path=binary_path)
    summary = {key: value[key] for key in ('status', 'groups', 'elapsed', 'actual_original_calls', 'original_status')}
    summary['result'] = file_record(directory / 'result.json')
    output = completed(summary, stdout)
    exact(pins(root), before, 'service evidence sources changed during inspection')
    return {'schema': 'hepta.runtime.file-lock-service-native-evidence.v1', 'status': 'PASS',
        'source_files': before, 'source_contract': closure, 'artifacts': artifact,
        'result': file_record(directory / 'result.json'), 'completed_stdout': output,
        'state_sessions': state_sessions, 'canonical_session': canonical_session, 'canonical_fixture': canonical_fixture,
        'concurrent': concurrent, 'actual_elf_requests': SERVICE_ROWS, 'serial_rows': SERIAL_ROWS,
        'concurrent_property_operations': CONCURRENT_ROWS, 'actual_original_calls': 0,
        'evidence_kind': 'retained_completed_native_execution', 'asynchronous_wait_scheduler_closed': False,
        'upper_file_io_closed': False, 'whole_runtime_replaced': False, 'production_activated': False}


def concurrent_evidence(folder, value, *, binary_path=None):
    folder = Path(folder)
    for key, wanted in {'status': 'PASS', 'alias_mutual_exclusion_rounds': 128, 'retained_growth_leases': 2080,
        'automatic_await_scheduler_closed': False, 'fresh_original_status': 'PENDING'}.items():
        exact(value.get(key), wanted, 'concurrent service domain differs')
    session = session_evidence(folder / 'process', value['process'], binary_sha=EXECUTABLE_SHA, serial=False, rows=6210, binary_path=binary_path)
    exact(len(session['native_thread_ids']), 4, 'all four actual worker threads were not exercised')
    exact(file_record(folder / 'schedule.json'), value['schedule'], 'concurrent retained schedule changed')
    schedule = array_value(folder / 'schedule.json'); exact(len(schedule), 128, 'alias contention rounds omitted')
    packets, replies, order = {}, {}, []
    with gzip.open(folder / 'process/requests.bin.gz', 'rb') as incoming, gzip.open(folder / 'process/native-output.bin.gz', 'rb') as outputs:
        for index in range(6210):
            size, tag = struct.unpack('<QQ', incoming.read(16)); packets[tag] = incoming.read(size)
            row = outputs.read(76); reply_tag, code = struct.unpack_from('<QI', row)
            exact(code, 64, 'concurrent response refused')
            replies[reply_tag] = struct.unpack('<7Q', row[20:]); order.append(reply_tag)
    at = 1; reply_at = 0
    def group(wanted):
        nonlocal at, reply_at
        tags = list(range(at, at + len(wanted)))
        for tag, packet in zip(tags, wanted): exact(packets[tag], packet, 'concurrent complete input sequence differs')
        emitted = order[reply_at:reply_at + len(tags)]
        exact(set(emitted), set(tags), 'concurrent group response domain differs')
        values = [replies[tag] for tag in emitted]
        at += len(tags); reply_at += len(tags)
        return tags, values
    for index, saved in enumerate(schedule):
        aliases = (b'file', b'./file', b'alias', os.fsencode(Path(value['process']['cwd']) / 'file'))
        admissions, values = group([test_file_lock_service.request(1, kind=1, path=path) for path in aliases])
        require(all(row[0] == 1 and row[1] == 0 for row in values), 'alias admission failed')
        leases = [row[2] for row in values]
        exact(len(set(leases)), 4, 'concurrent leases are not distinct'); exact(len({row[3] for row in values}), 1, 'aliases did not share one lock')
        polls, values = group([test_file_lock_service.request(3, ident) for ident in leases])
        require(all(row[0] == 3 and row[1] in (0, 1) for row in values), 'concurrent poll status differs')
        held = [row[2] for row in values if row[1] == 0]; pending = [row[2] for row in values if row[1] == 1]
        exact(len(held), 1, 'concurrent mutual exclusion failed'); exact(set(held + pending), set(leases), 'concurrent poll identity differs')
        exact(saved, {'round': index, 'admissions': admissions, 'polls': polls, 'held': held[0], 'cancelled': pending}, 'retained concurrency schedule differs from actual outputs')
        for ident in pending:
            _, result = group([test_file_lock_service.request(4, ident)]); exact(result[0][:3], (4, 0, ident), 'pending waiter cancellation differs')
        _, result = group([test_file_lock_service.request(5, held[0])]); exact(result[0][:3], (5, 0, held[0]), 'guard release differs')
        exact(result[0][-1], 0, 'cancelled waiter was spuriously awakened')
        for ident in leases:
            _, result = group([test_file_lock_service.request(6, ident)]); exact(result[0][:3], (6, 0, ident), 'alias lease drop differs')
    leases = []
    for index in range(520):
        _, values = group([test_file_lock_service.request(1, kind=1, path=f'growth-{index}-{i}'.encode()) for i in range(4)])
        require(all(row[0] == 1 and row[1] == 0 and row[2] > 0 for row in values), 'shared growth admission failed')
        leases.extend(row[2] for row in values)
    exact(len(set(leases)), 2080, 'shared growth lost or reused live leases')
    _, result = group([test_file_lock_service.request(7)]); exact(result[0][5], 2080, 'shared arena growth lost references')
    require(result[0][4] >= 2080, 'live nodes were swept during shared arena growth')
    for index in range(0, len(leases), 4):
        _, result = group([test_file_lock_service.request(6, ident) for ident in leases[index:index + 4]])
        exact({row[2] for row in result}, set(leases[index:index + 4]), 'concurrent growth lease release differs')
        require(all(row[0] == 6 and row[1] == 0 for row in result), 'growth lease drop failed')
    _, result = group([test_file_lock_service.request(7)]); exact(result[0][5], 0, 'concurrent live leases leaked')
    exact((at, reply_at), (6211, 6210), 'concurrent actual rows omitted')
    captured, fixture = fixture_evidence(folder, value['fixture'], expected_path=value['process']['cwd'])
    exact(captured['entries'], [
        {'path_hex': b'alias'.hex(), 'mode': 0o777, 'kind': 'symlink', 'target_hex': b'file'.hex()},
        {'path_hex': b'file'.hex(), 'mode': 0o644, 'kind': 'file', 'bytes': 8, 'sha256': sha(b'original'), 'data_hex': b'original'.hex()},
    ], 'concurrent alias fixture differs')
    return {'status': 'PASS', 'session': session, 'schedule': file_record(folder / 'schedule.json'),
        'fixture': fixture, 'original_property_operations': 6210, 'actual_native_threads': 4}


def contract_evidence(bundle, directory, *, source_root=ROOT, stdout):
    root, directory = Path(source_root), Path(directory); bundle = Path(bundle)
    artifact = inspect_bundle(bundle, source_root=root); value = obj(directory / 'result.json')
    for key, wanted in {'schema': 'hepta.runtime.file-lock-service-contract.v1', 'status': 'PASS', 'groups': 3,
        'bundle_artifacts': artifact, 'actual_original_calls': 0, 'direct_native_calls': 133,
        'actual_native_pack_calls': 6, 'actual_elf_processes': 13}.items():
        exact(value.get(key), wanted, 'service native contract receipt differs')
    base.duration(value['elapsed'], 'service contract suite missed unchanged budget')
    names = ('tests/hia_native/test_file_lock_service_contract.py', 'tests/hia_native/test_file_lock_service.py',
        'scripts/hia_native_loader.py', 'scripts/hia_native_file_lock_service_build.py')
    exact(value['source_files'], {name: file_record(root / name) for name in names}, 'service actual contract sources changed')
    exact(sha(canonical(value['controller'])), '4f2c55b8cc3c6b77ecac9322b717b5745949605cdbb0fe1df3d65b375c5b1de0', 'complete direct controller refusal domain changed')
    counts = collections.Counter(row['domain'] for row in value['controller'])
    exact(dict(counts), {'frame': 88, 'capacity': 5, 'growth': 1, 'key_request': 1,
        'key_completion_refusal': 25, 'key_utf8_refusal': 1, 'state_request': 1,
        'state_completion_refusal': 9, 'synthetic_completion': 1, 'terminal_reentry_refusal': 1}, 'controller contract domain omitted')
    expected = {'eof': 0, 'argv': 64, 'partial-prefix': 74, 'partial-payload': 74,
        'invalid-continue': 0, 'overflow-allocation': 71, 'broken-stdout': 74}
    transport = [row for row in value['transport'] if row['domain'] == 'transport']
    exact(len(transport), 7, 'threaded transport controls omitted')
    exact({row['name']: row['exit_code'] for row in transport}, expected, 'threaded transport exit contract differs')
    for row in transport:
        exact(row['executable_sha256'], EXECUTABLE_SHA, 'transport used another executable')
        exact(row['stderr_hex'], '', 'threaded transport emitted stderr')
        exact(row['timeout_seconds'], 10, 'threaded transport deadline changed')
        require(0 < row['elapsed'] < 10, 'threaded transport missed its deadline')
        if row['name'] == 'invalid-continue':
            output = bytes.fromhex(row['stdout_hex']); exact(len(output), 40, 'invalid frame response extent differs')
            records = [struct.unpack_from('<QQI', output, at) for at in (0, 20)]
            exact({row[0] for row in records}, {1, 2}, 'invalid frame continuation lost a response')
            require(all(row[1] > 0 and row[2] == 0xffffffff for row in records), 'invalid frame status differs')
        elif row['name'] != 'broken-stdout':
            exact(row['stdout_hex'], '', 'refused transport published a payload')
    probes = [row for row in value['transport'] if row['domain'] == 'invalid_image_fixture']
    exact(len(probes), 6, 'actual native return fixtures omitted')
    expected_probes = {(kind, name) for kind in ('controller', 'key', 'state') for name in ('unknown-return', 'dirty-upper-return')}
    exact({(row['kind'], row['name']) for row in probes}, expected_probes, 'return fixture profile set differs')
    files = {}
    for row in probes:
        wanted = 'b807000000c3' if row['name'] == 'unknown-return' else '48b84000000001000000c3'
        exact(row['image_hex'], wanted, 'invalid return fixture bytes changed')
        for key, wanted in {'packer_image_sha256': IMAGES['packer'], 'exit_code': 70,
            'stdout_hex': '', 'stderr_hex': '', 'timeout_seconds': 10, 'actual_native_pack_calls': 1}.items():
            exact(row.get(key), wanted, 'actual native return fixture receipt differs')
        require(0 < row['elapsed'] < 10, 'return fixture missed its unchanged deadline')
        path = directory / (row['kind'] + '-' + row['name'] + '.elf'); raw = read(path)
        exact(file_record(path), row['packed_elf'], 'actual packed probe artifact changed')
        images = [bytes.fromhex(row['image_hex']) if kind == row['kind'] else read(bundle.parent / (kind + '.image.bin'))
            for kind in ('controller', 'key', 'state')]
        exact(len(raw), PREFIX_SIZE + sum(map(len, images)), 'probe image extent differs')
        exact(struct.unpack_from('<4Q', raw, TABLE), (*map(len, images), int.from_bytes(b'HFLKSIM1', 'little')), 'probe image table differs')
        exact(struct.unpack_from('<2Q', raw, 96), (len(raw), len(raw)), 'probe ELF extent fields differ')
        prefix = bytearray(raw[:PREFIX_SIZE]); prefix[96:112] = bytes(16); prefix[TABLE:TABLE + 24] = bytes(24)
        exact(sha(prefix), PREFIX_SHA, 'probe did not exercise the actual fixed thread boundary')
        exact(raw[PREFIX_SIZE:], b''.join(images), 'probe embedded images differ')
        files[path.name] = file_record(path)
    summary = {key: value[key] for key in ('status', 'groups', 'elapsed', 'direct_native_calls',
        'actual_native_pack_calls', 'actual_elf_processes', 'actual_original_calls')}
    summary['result'] = file_record(directory / 'result.json')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'),
        'completed_stdout': completed(summary, stdout), 'direct_native_calls': 133,
        'actual_native_pack_calls': 6, 'actual_elf_processes': 13, 'probe_files': files,
        'actual_original_calls': 0, 'evidence_kind': 'retained_completed_native_execution'}


def kernel_evidence(directory, native_sha, original_sha, *, source_root=ROOT):
    """Reconstruct every paired thread-owned kernel case from retained files."""
    directory, root = Path(directory), Path(source_root)
    value = obj(directory / 'result.json'); domain = file_lock_key_kernel.cases()
    for key, wanted in {'schema': 'hepta.runtime.file-lock-service-kernel-comparison.v1', 'status': 'PASS',
        'declared_cases': 112, 'cases': 112, 'native_processes': 112, 'original_processes': 112,
        'actual_native_owner_operations': 224, 'actual_original_owner_operations': 224,
        'native_binary_sha256': native_sha, 'original_binary_sha256': original_sha}.items():
        exact(value.get(key), wanted, 'service paired kernel receipt differs')
    exact(array_value(directory / 'cases.json'), domain, 'service full kernel domain differs')
    names = ('file_lock_key_cases.py', 'file_lock_key_kernel.py', 'file_lock_fixture.py',
        'file_lock_service_kernel.py', 'file_lock_service_supervisor.py')
    exact(value['source_files'], {name: sha(read(root / 'tests/hia_native' / name)) for name in names}, 'service actual kernel sources changed')
    base.duration(value['elapsed'], 'service paired kernel suite missed unchanged budget')
    exact(len(value['observations']), len(domain), 'service kernel pair omitted')
    origin = Path(value['directory']); require(origin.is_absolute(), 'service kernel origin must be absolute')
    files, effects = {}, {'native': 0, 'original': 0}
    for index, (case, observed) in enumerate(zip(domain, value['observations'])):
        entry = directory / f'{index:03d}-{case["name"]}'; recorded = origin / entry.name
        exact(obj(entry / 'comparison.json'), observed, 'service pair result changed')
        exact(observed['name'], case['name'], 'service kernel case order differs')
        path = bytes.fromhex(case['path_hex'])
        if case.get('absolute'): path = os.fsencode(recorded / 'fixture') + b'/' + path
        raw = read(entry / 'request.bin'); exact(raw, file_lock_service_kernel.request(path), 'service complete kernel inputs changed')
        exact((observed['request_bytes'], observed['request_sha256']), (len(raw), sha(raw)), 'service pair input digest differs')
        parts = [(str(i) + '-' + 'a' * 117).encode().hex() for i in range(case.get('deep', 0))]
        if case.get('removed'): parts = [b'removed'.hex()]
        config = {'faults': case['faults'], 'cwd_parts': parts, 'unlink_cwd': bool(case.get('removed'))}
        exact(obj(entry / 'config.json'), config, 'service declared kernel controls differ')
        expected_names = ['comparison.json', 'config.json', 'fixture', 'native.stderr', 'native.stdout',
            'native.trace.json', 'original.stderr', 'original.stdout', 'original.trace.json', 'request.bin']
        exact(observed['precreated_entry_names'], expected_names, 'service fixture log-name custody differs')
        exact(len(observed['invocations']), 2, 'service actual kernel side omitted')
        pair = []
        for name, record, binary_sha in zip(('native', 'original'), observed['invocations'], (native_sha, original_sha)):
            exact(record['name'], name, 'service kernel side order differs')
            exact(record['exit_code'], 0, 'service actual kernel process failed')
            exact(record['timeout'], 20, 'service kernel outer deadline changed')
            require(0 < record['elapsed'] < 20, 'service actual kernel process missed its deadline')
            output, error = read(entry / (name + '.stdout')), read(entry / (name + '.stderr'))
            for key, payload in (('stdout', output), ('stderr', error)):
                exact((record[key + '_bytes'], record[key + '_sha256']), (len(payload), sha(payload)), 'service actual kernel channel changed')
            if name == 'native':
                exact(error, b'', 'service native kernel process emitted stderr')
            else:
                exact(json.loads(error), {'status': 'PASS', 'rows': 2, 'original_owner_operations': 2,
                    'operation_counts': [0, 1, 0, 0, 0, 0, 1, 0], 'borrowed_guards': True,
                    'extra_strong_observer_refs': 0}, 'service actual original kernel summary differs')
            trace = obj(entry / (name + '.trace.json'))
            command = record['command']
            require(type(command) is list and len(command) == (13 if name == 'native' else 14)
                and Path(command[0]).is_absolute(), 'service kernel process command differs')
            exact(command[1], '-I', 'service kernel isolated Python flag changed')
            exact(Path(command[2]).name, 'file_lock_service_supervisor.py', 'service kernel supervisor changed')
            wanted = ['--executable', value[name + '_executable'], '--fixture', str(recorded / 'fixture'),
                '--config', str(recorded / 'config.json'), '--log', str(recorded / (name + '.trace.json')), '--timeout', '15']
            if name == 'original': wanted.append('--original-transport')
            exact(command[3:], wanted, 'service kernel command or deadline differs')
            for key, wanted in {'schema': 'hepta.runtime.file-lock-service-kernel-trace.v1', 'status': 'PASS',
                'failure': None, 'exit_code': 0, 'executable_sha256': binary_sha, 'config': config,
                'fixture': str(recorded / 'fixture'), 'input_bytes': len(raw), 'input_sha256': sha(raw),
                'stdout_bytes': len(output), 'stdout_sha256': sha(output), 'stderr_bytes': len(error), 'stderr_sha256': sha(error),
                'original_transport': name == 'original', 'drop_after_complete_first_result': True,
                'owner_epoch': 'first-read-on-stdin-before-any-owner-syscall'}.items():
                exact(trace.get(key), wanted, 'service raw kernel trace differs: ' + key)
            require(0 < trace['elapsed'] < 15, 'service kernel supervisor missed its unchanged deadline')
            require(set(trace['memory_readers']) <= {'owned-process-vm-readv', 'owned-proc-mem-pread'}, 'unapproved service target-memory reader')
            require(type(trace['owned_thread_ids']) is list and trace['owned_thread_ids']
                == sorted(set(trace['owned_thread_ids'])) and all(type(tid) is int and tid > 0 for tid in trace['owned_thread_ids']),
                'service owned thread identity set differs')
            require(len(trace['owned_thread_ids']) <= (5 if name == 'native' else 1), 'service kernel thread count exceeds its profile')
            counts = collections.Counter(); seen_threads = set()
            for event in trace['events']:
                require(event['pid'] in trace['owned_thread_ids'], 'service kernel event escaped its owned thread group')
                seen_threads.add(event['pid'])
                require(event['domain'] in ('owner', 'startup', 'transport'), 'unclassified service kernel event')
                if event['domain'] != 'owner':
                    exact(event['completion'], 'kernel_continue', 'startup/transport syscall was synthetically changed')
                    if event['domain'] == 'transport': require(event['syscall'] in (0, 1), 'transport classification hid an owner effect')
                    continue
                require(event['syscall'] not in (0, 1), 'owner classification includes transport IO')
                counts[event['kind']] += 1
                exact(event['ordinal'], counts[event['kind']], 'service owner syscall ordinal omitted')
                faults = [fault for fault in case['faults'] if fault['kind'] == event['kind'] and fault.get('ordinal', 1) == event['ordinal']]
                require(len(faults) <= 1, 'duplicate declared service kernel fault')
                if faults:
                    fault = faults[0]
                    if 'errno' in fault:
                        exact(event['completion'], 'injected_errno_without_kernel_effect', 'service errno control omitted')
                        exact(event['errno'], fault['errno'], 'service errno control changed')
                    else:
                        exact(event['completion'], 'injected_value_without_kernel_effect', 'service value control omitted')
                        expected = event['capacity'] if fault['return'] == 'readlink_capacity' else fault['return']
                        exact(event['value'], expected, 'service injected value changed')
                else:
                    exact(event['completion'], 'kernel_continue', 'undeclared synthetic service owner effect')
            exact(seen_threads, set(trace['owned_thread_ids']), 'service verified thread set is not supported by actual syscall events')
            exact(dict(counts), trace['counts'], 'service complete raw syscall counts differ')
            for fault in case['faults']:
                require(counts[fault['kind']] >= fault.get('ordinal', 1), 'service declared fault never executed')
            logical, tids = file_lock_service_kernel.logical_output(output, native=name == 'native', trace=trace)
            exact(record['response_thread_ids'], tids, 'service response thread identities changed')
            exact((record['logical_output_bytes'], record['logical_output_sha256']), (len(logical), sha(logical)), 'service logical response digest differs')
            normalized = file_lock_key_kernel.normalized(trace)
            exact(observed[name + '_normalized_trace'], normalized, 'service normalized trace omitted raw owner events')
            effects[name] += len(normalized); pair.append((logical, normalized))
        exact(pair[0], pair[1], 'service complete native/original kernel pair differs')
        exact(observed['output_match'], True, 'service original output comparison failed')
        exact(observed['kernel_trace_match'], True, 'service original trace comparison failed')
        snapshots = observed['fixture_snapshots']; exact(snapshots['file'], 'fixture-snapshots.json.gz', 'service fixture snapshot filename differs')
        exact(file_record(entry / snapshots['file']), {key: snapshots[key] for key in ('bytes', 'sha256')}, 'service complete fixture snapshot changed')
        exact(base.gzip_record(entry / snapshots['file']), {'bytes': snapshots['raw_bytes'], 'sha256': snapshots['raw_sha256']}, 'service fixture snapshot truncated')
        captured = json.loads(gzip.decompress(read(entry / snapshots['file'])))
        after = ([row for row in captured['before'] if row['path_hex'] != b'removed'.hex()] if case.get('removed') else captured['before'])
        exact(captured['after_native'], after, 'native lock operation changed its filesystem fixture')
        exact(captured['after_original'], after, 'original lock operation changed its filesystem fixture')
        exact(captured['removed_cwd_is_a_fixture_effect'], bool(case.get('removed')), 'removed-cwd classification differs')
        retired = observed['fixture_retirement']
        exact(retired['file'], 'fixture-retired.json.gz', 'service retired fixture filename differs')
        exact(retired['retired'], True, 'service kernel fixture retirement incomplete')
        require(not (entry / 'fixture').exists(), 'service kernel fixture remains live')
        exact(file_record(entry / retired['file']), {key: retired[key] for key in ('bytes', 'sha256')}, 'service retired fixture archive changed')
        exact(base.gzip_record(entry / retired['file']), {'bytes': retired['raw_bytes'], 'sha256': retired['raw_sha256']}, 'service retired complete fixture truncated')
        archive = json.loads(gzip.decompress(read(entry / retired['file'])))
        exact(archive['path'], str(recorded / 'fixture'), 'service retired fixture path differs')
        exact(archive['entries'], after, 'service retired fixture differs from actual kernel observation')
        expected_files = set(expected_names) - {'fixture'} | {'fixture-snapshots.json.gz', 'fixture-retired.json.gz'}
        exact({path.name for path in entry.iterdir()}, expected_files, 'service kernel artifact set differs')
        for path in entry.iterdir(): files[str(path.relative_to(directory))] = file_record(path)
    exact(effects['native'], effects['original'], 'service paired owner effect counts differ')
    for name in ('native', 'original'):
        exact(value[name + '_owner_effects'], effects[name], 'service complete effect accounting differs')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'cases': 112,
        'native_processes': 112, 'original_processes': 112, 'original_owner_operations': 224,
        'owner_effects_each': effects['native'], 'files': files, 'evidence_kind': 'retained_completed_kernel_execution'}


def original_evidence(directory, bundle, native_corpus, native_stdout, state_corpus, *, source_root=ROOT, stdout):
    """Validate retained actual reference execution; never invoke a compiler."""
    directory, root = Path(directory), Path(source_root)
    native_corpus = Path(native_corpus)
    before = pins(root); artifact = inspect_bundle(bundle, source_root=root)
    native = native_evidence(bundle, native_corpus, state_corpus, source_root=root, stdout=native_stdout)
    value = obj(directory / 'result.json')
    for key, wanted in {'schema': 'hepta.runtime.file-lock-service-original-comparison.v1', 'status': 'PASS',
        'source_files': before, 'source_contract': source_contract(root), 'artifacts': artifact, 'native': native,
        'original_build_is_fresh': True, 'original_replay_is_fresh': True,
        'serial_byte_compared_rows': 231214, 'concurrent_property_operations': 6210,
        'kernel_original_owner_operations': 224, 'total_original_owner_operations': 237648,
        'asynchronous_wait_scheduler_closed': False, 'upper_file_io_closed': False,
        'whole_runtime_replaced': False, 'production_activated': False, 'concurrent': ORIGINAL_CONCURRENT}.items():
        exact(value.get(key), wanted, 'actual original service comparison differs: ' + key)
    base.duration(value['elapsed'], 'original service recipe missed unchanged 180-second budget')
    origin, origin_root, origin_native = map(Path, (value['directory'], value['source_root'], value['native_corpus']))
    require(all(path.is_absolute() for path in (origin, origin_root, origin_native)), 'original service execution paths must be absolute')
    exact(Path(obj(native_corpus / 'result.json')['state_corpus']), Path(value['state_corpus']), 'actual original state corpus origin changed')
    cleared = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
        'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
    exact(value['cleared_environment_names'], cleared, 'service original Rust override sanitation changed')
    require(all(name in cleared or name.startswith('HIA_') for name in value['removed_environment_names']), 'unclassified original override')
    exact(set(value['tools']), {'cargo', 'rustc', 'rustfmt'}, 'service selected toolchain set differs')
    for name, tool in value['tools'].items():
        require(Path(tool['path']).is_absolute() and Path(tool['path']).name == name
            and Path(tool['resolved_path']).is_absolute() and type(tool['bytes']) is int and tool['bytes'] > 0
            and len(tool['sha256']) == 64, 'service original toolchain identity record differs')
    exact(value['selected_environment'], {'RUSTC': value['tools']['rustc']['path'],
        'CARGO_TARGET_DIR': str(origin / 'target'), 'HIA_REFERENCE_RUNTIME': str(origin_root),
        'TMPDIR': str(origin / 'tmp')}, 'actual original service environment differs')
    binary = value['original_binary']; binary_name = 'target/release/hia-file-lock-service-original'
    exact(binary['path'], str(origin / binary_name), 'executed original service binary path differs')
    exact(file_record(directory / binary_name), {key: binary[key] for key in ('bytes', 'sha256')}, 'executed original service binary changed')
    sessions = obj(native_corpus / 'result.json')['results']['state']['sessions']
    names = ['rustc-version', 'format-check', 'cargo-build'] + ['original-session-' + str(item['session']) for item in sessions] + ['original-canonical', 'original-concurrent']
    exact([row['name'] for row in value['records']], names, 'actual original service process sequence omitted')
    exact(len(value['state']), 23, 'actual original state service summaries omitted')
    commands = {
        'rustc-version': [value['tools']['rustc']['path'], '-Vv'],
        'format-check': [value['tools']['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(origin_root / 'rustfmt.toml'), '--check', str(origin_root / 'tests/hia_native/oracle_file_lock_service.rs'),
            str(origin_root / 'tests/hia_native/file_lock_service_oracle/build.rs')],
        'cargo-build': [value['tools']['cargo']['path'], 'build', '--release', '--locked', '--manifest-path',
            str(origin_root / 'tests/hia_native/file_lock_service_oracle/Cargo.toml')],
        'original-canonical': [binary['path']], 'original-concurrent': [binary['path'], '--concurrent'],
    }
    files, summaries = {}, {}
    for index, session in enumerate(sessions):
        name = 'session-' + str(session['session']); process = 'original-' + name
        commands[process] = [binary['path']]
        expected_input = base.gzip_record(native_corpus / 'state' / name / 'requests.bin.gz')
        expected_output = base.gzip_record(native_corpus / 'state' / name / 'native-output.bin.gz')
        exact(file_record(directory / (name + '.stdin')), expected_input, 'actual original state input truncated')
        exact(file_record(directory / (process + '.stdout')), expected_output, 'actual original state result bytes differ')
        counts = [0] * 8
        with (directory / (name + '.stdin')).open('rb') as incoming:
            while header := incoming.read(16):
                require(len(header) == 16, 'actual original state frame truncated')
                size, tag = struct.unpack('<QQ', header); require(64 <= size <= (5 << 20) + 64, 'original state frame extent differs')
                packet = incoming.read(size); require(len(packet) == size, 'actual original state input row missing')
                op = struct.unpack_from('<Q', packet, 8)[0]; require(1 <= op <= 7, 'private lifecycle row entered original replay')
                counts[op] += 1
        rows = sum(counts)
        summary = {'status': 'PASS', 'rows': rows, 'original_owner_operations': rows,
            'operation_counts': counts, 'borrowed_guards': True, 'extra_strong_observer_refs': 0}
        exact(obj(directory / (process + '.stderr')), summary, 'actual original state stderr changed')
        exact(value['state'][index], {'session': session['session'], 'rows': rows, 'summary': summary,
            'output': expected_output}, 'actual original state comparison summary changed')
        summaries[process] = expected_input
        files[name + '.stdin'] = file_record(directory / (name + '.stdin'))
    canonical_input = base.gzip_record(native_corpus / 'canonical/process/requests.bin.gz')
    canonical_output = base.gzip_record(native_corpus / 'canonical/process/native-output.bin.gz')
    exact(file_record(directory / 'canonical.stdin'), canonical_input, 'actual original canonical input differs')
    exact(file_record(directory / 'original-canonical.stdout'), canonical_output, 'actual original canonical result differs')
    canonical_summary = {'status': 'PASS', 'rows': 179431, 'original_owner_operations': 179431,
        'operation_counts': [0, 89715, 0, 0, 0, 0, 89715, 1], 'borrowed_guards': True, 'extra_strong_observer_refs': 0}
    exact(obj(directory / 'original-canonical.stderr'), canonical_summary, 'actual original canonical stderr changed')
    exact(value['canonical']['rows'], 179431, 'original canonical row count differs')
    exact(value['canonical']['summary'], canonical_summary, 'original canonical retained summary differs')
    exact(value['canonical']['output'], canonical_output, 'original canonical full output custody differs')
    exact(obj(directory / 'original-concurrent.stdout'), ORIGINAL_CONCURRENT, 'actual original concurrency stdout changed')
    exact(read(directory / 'original-concurrent.stderr'), b'', 'actual original concurrency failed')
    for row in value['records']:
        name = row['name']; wanted = commands[name]
        if name == 'cargo-build' and row['command'] == wanted + ['--offline']: wanted += ['--offline']
        exact(row['command'], wanted, 'actual original service command changed')
        budget = 10 if name in ('rustc-version', 'format-check') else 120 if name == 'cargo-build' else 180 if name == 'original-canonical' else 60
        exact(row['timeout_seconds'], budget, 'original service subprocess deadline changed')
        exact((row['timed_out'], row['exit_code']), (False, 0), 'failed original service process accepted')
        require(type(row['elapsed']) in (int, float) and 0 < row['elapsed'] < budget, 'original service subprocess missed its deadline')
        cwd = origin_native / 'state' if name.startswith('original-session-') else origin_native / 'canonical/fixture' if name == 'original-canonical' else origin_native / 'concurrent/fixture' if name == 'original-concurrent' else origin / 'empty-cwd'
        exact(row['cwd'], str(cwd), 'actual original service cwd changed')
        for channel in ('stdout', 'stderr'):
            path = directory / (name + '.' + channel)
            exact(file_record(path), row[channel], 'actual original service stdout/stderr changed')
            files[path.name] = file_record(path)
        expected_input = summaries.get(name, canonical_input if name == 'original-canonical' else {'bytes': 0, 'sha256': sha(b'')})
        exact(row['input'], expected_input, 'actual original service stdin changed')
    version = read(directory / 'rustc-version.stdout')
    require(version.startswith(b'rustc 1.95.0 ') and b'host: x86_64-unknown-linux-gnu\n' in version, 'actual original Rust version or target differs')
    for name in ('rustc-version.stderr', 'format-check.stdout', 'format-check.stderr'):
        exact(read(directory / name), b'', 'actual original version/format process failed')
    text = read(root / 'src/mcp/fs/text_editing.rs'); start = text.index(b'// Thread-safe file locking infrastructure'); end = text.index(b'/// Test-only visibility', start)
    remote = read(root / 'src/mcp/fs/remote.rs'); at = remote.index(b'#[derive(Debug, Clone)]\npub enum PathSource {'); until = remote.index(b'\nimpl PathSource {', at)
    key = remote.index(b'\tpub fn lock_key(&self) -> String {'); key_end = remote.index(b'\n\t/// Human-readable path', key)
    bodies = {'file_lock_original.rs': text[start:end], 'path_source_original.rs': remote[at:until],
        'path_key_original.rs': b'impl PathSource {\n' + remote[key:key_end] + b'\n}\n'}
    exact(set(value['compiled_original_sources']), set(bodies), 'complete compiled original service owner omitted')
    for name, expected in bodies.items():
        recorded = value['compiled_original_sources'][name]
        relative = Path(recorded['build_path']).relative_to(origin)
        require(len(relative.parts) == 6 and relative.parts[:3] == ('target', 'release', 'build')
            and relative.parts[3].startswith('hia-file-lock-service-original-')
            and relative.parts[4:] == ('out', name), 'original compiled body path escaped its Cargo output')
        exact(read(directory / relative), expected, 'actual Cargo owner body changed')
        exact(read(directory / name), expected, 'retained compiled original owner body changed')
        exact(file_record(directory / name), {key: recorded[key] for key in ('bytes', 'sha256')}, 'compiled original body digest differs')
        files[name] = file_record(directory / name)
    for kind, record in (('canonical', value['canonical']['fixture']), ('concurrent', value['concurrent_fixture'])):
        filename = kind + '-original-fixture.json.gz'; exact(record['file'], filename, 'original service fixture filename differs')
        exact(record['retired'], True, 'actual original service fixture retirement incomplete')
        exact(file_record(directory / filename), {key: record[key] for key in ('bytes', 'sha256')}, 'actual original full fixture archive changed')
        exact(base.gzip_record(directory / filename), {'bytes': record['raw_bytes'], 'sha256': record['raw_sha256']}, 'actual original fixture archive truncated')
        captured = json.loads(gzip.decompress(read(directory / filename)))
        exact(captured, json.loads(gzip.decompress(read(native_corpus / kind / 'fixture.json.gz'))), 'actual original fixture differed from actual native fixture')
        files[filename] = file_record(directory / filename)
    kernel = kernel_evidence(directory / 'kernel', EXECUTABLE_SHA, binary['sha256'], source_root=root)
    exact(value['kernel_evidence'], kernel, 'actual service kernel evidence changed')
    exact(value['kernel_summary'], {key: item for key, item in obj(directory / 'kernel/result.json').items() if key != 'observations'}, 'actual service kernel summary omitted a field')
    exact(pins(root), before, 'original service evidence sources changed during inspection')
    summary = {key: value[key] for key in ('status', 'elapsed', 'serial_byte_compared_rows',
        'concurrent_property_operations', 'kernel_original_owner_operations', 'total_original_owner_operations')}
    summary['result'] = file_record(directory / 'result.json')
    return {'schema': 'hepta.runtime.file-lock-service-original-evidence.v1', 'status': 'PASS',
        'result': file_record(directory / 'result.json'), 'completed_stdout': completed(summary, stdout),
        'source_files': before, 'files': files, 'serial_byte_compared_rows': 231214,
        'concurrent_property_operations': 6210, 'kernel_original_owner_operations': 224,
        'total_original_owner_operations': 237648, 'kernel': kernel,
        'evidence_kind': 'retained_completed_original_execution',
        'actual_new_native_calls': 0, 'actual_new_original_calls': 0}


def controls_evidence(directory, native, contract, *, source_root=ROOT, stdout):
    directory = Path(directory); value = obj(directory / 'result.json')
    for key, wanted in {'schema': 'hepta.runtime.file-lock-service-evidence-controls.v1', 'status': 'PASS',
        'groups': 3, 'source_files': pins(source_root), 'actual_native_calls': 0, 'actual_original_calls': 0,
        'rejected_candidates': 26, 'owned_control_copies_retired': True}.items():
        exact(value.get(key), wanted, 'service evidence-control receipt differs')
    base.duration(value['elapsed'], 'service evidence controls missed unchanged budget')
    require(not (directory / 'owned-control-copies').exists(), 'owned service control copies were not retired')
    for name, expected in (('native', native), ('contract', contract)):
        path = directory / ('accepted-' + name + '-evidence.json')
        exact(obj(path), expected, 'service controls inspected another retained execution')
        exact(file_record(path), value['accepted_' + name + '_evidence'], 'accepted service evidence changed')
    artifact_names = ('controller.image.bin', 'key.image.bin', 'state.image.bin', 'packer.image.bin',
        'file-lock-service.elf', 'controller-build/module.output.bin', 'key-build/module.stdout.log',
        'state-build/module.receipt.json', 'pack/pack.input.bin', 'pack/pack.output.bin',
        'pack/pack.stdout.log', 'pack/pack.receipt.json')
    expected_names = {'artifact-' + name.replace('/', '-') for name in artifact_names}
    expected_names |= {'rehash-image-' + kind for kind in ('controller', 'key', 'state', 'packer')}
    expected_names |= {'rehash-fixed-prefix', 'false-production', 'wrong-compiler', 'state-input',
        'actual-thread-output', 'canonical-output', 'concurrent-schedule', 'missing-completed-result-binding',
        'omitted-controller-refusal', 'false-contract-original-calls'}
    exact(len(value['refusals']), 26, 'service refusal control omitted')
    exact({row['name'] for row in value['refusals']}, expected_names, 'service refusal domain changed')
    artifacts = native['artifacts']; originals = {'bundle/manifest.json': artifacts['manifest'],
        'bundle/file-lock-service.elf': artifacts['executable']['inspection'], 'contract/result.json': contract['result'],
        'native.stdout': native['completed_stdout'],
        'native/canonical/process/native-output.bin.gz': native['canonical_session']['files']['native-output.bin.gz'],
        'native/concurrent/schedule.json': native['concurrent']['schedule']}
    first = native['state_sessions'][0]
    for name in ('requests.bin.gz', 'native-wire.bin.gz'):
        originals['native/state/session-' + str(first['session']) + '/' + name] = first['files'][name]
    for kind, record in artifacts['modules'].items():
        originals['bundle/' + kind + '.json'] = record['manifest']
        originals['bundle/' + kind + '.image.bin'] = record['compilation']['module.image.bin']
        for name, identity in record['compilation'].items(): originals['bundle/' + kind + '-build/' + name] = identity
    for name, identity in artifacts['executable']['pack_files'].items(): originals['bundle/pack/' + name] = identity
    for row in value['refusals']:
        for key, expected in {'status': 'REFUSED', 'actual_native_calls': 0, 'actual_original_calls': 0}.items():
            exact(row.get(key), expected, 'service control claimed semantic execution or accepted a mutation')
        require(type(row['error']) is str and row['error'], 'service control omitted its actual refusal')
        require(type(row['changed_files']) is dict and row['changed_files'], 'service control omitted actual changed bytes')
        for name, change in row['changed_files'].items():
            require(name in originals, 'service control modified an undeclared file')
            exact(change['before'], {key: originals[name][key] for key in ('bytes', 'sha256')}, 'service control did not start from the accepted artifact')
            require(change['before'] != change['after'], 'service control did not modify its actual candidate')
            require(set(change) in ({'before', 'after', 'byte_changes'}, {'before', 'after', 'replacement_hex'}), 'service control mutation record differs')
            if 'replacement_hex' in change:
                raw = bytes.fromhex(change['replacement_hex'])
                exact(change['after'], {'bytes': len(raw), 'sha256': sha(raw)}, 'service replacement bytes differ')
            else:
                exact(change['after']['bytes'], change['before']['bytes'], 'service byte mutation extent differs')
                previous = -1
                for at, old, new in change['byte_changes']:
                    require(type(at) is int and previous < at < change['before']['bytes']
                        and type(old) is int and type(new) is int and 0 <= old <= 255 and 0 <= new <= 255 and old != new,
                        'service byte mutation is not a complete ordered change list')
                    previous = at
                require(previous >= 0, 'service byte mutation list is empty')
    summary = {key: value[key] for key in ('status', 'groups', 'elapsed', 'rejected_candidates',
        'actual_native_calls', 'actual_original_calls')}; summary['result'] = file_record(directory / 'result.json')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'),
        'completed_stdout': completed(summary, stdout), 'rejected_candidates': 26,
        'source_files': pins(source_root), 'actual_native_calls': 0, 'actual_original_calls': 0,
        'evidence_kind': 'retained_completed_evidence_controls'}
