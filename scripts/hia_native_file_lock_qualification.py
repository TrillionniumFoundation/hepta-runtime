"""Inspect complete, source-bound file-lock executions; never synthesize a run."""
from __future__ import annotations
import collections
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'scripts', ROOT / 'tests/hia_native'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from hia_native_file_lock_build import (
    inspect_bundle, inspect_elf, source_contract as imported_contract, source_pins,
    IMAGES, PREFIX, FROZEN, COMMIT, COMPILER, read, obj, exact, require,
    sha, canonical, file_record,
)
import file_lock_key_cases
import file_lock_key_kernel

OWN = (
    'native/file_lock_state.hepta', 'native/file_lock_state_composition.json',
    'native/file_lock_state_packer.hepta', 'native/file_lock_state_layout.json',
    'native/file_lock_key.hepta', 'native/file_lock_key_composition.json',
    'native/file_lock_key_packer.hepta', 'native/file_lock_key_layout.json',
    'native/file_locks_abi.md', 'scripts/hia_native_file_lock_build.py',
    'scripts/hia_native_file_lock_qualification.py', 'tests/hia_native/test_file_lock_state.py',
    'tests/hia_native/test_file_lock_key.py', 'tests/hia_native/test_file_lock_evidence.py',
    'tests/hia_native/file_lock_key_cases.py', 'tests/hia_native/file_lock_key_kernel.py',
    'tests/hia_native/file_lock_key_supervisor.py', 'tests/hia_native/file_lock_fixture.py',
    'tests/hia_native/run_file_lock_key.py', 'tests/hia_native/oracle_file_lock_state.rs',
    'tests/hia_native/oracle_file_lock_key.rs', 'tests/hia_native/compare_file_locks_original.py',
    'tests/hia_native/file_lock_oracle/Cargo.toml', 'tests/hia_native/file_lock_oracle/Cargo.lock',
    'tests/hia_native/file_lock_oracle/build.rs',
)
REFERENCES = ('src/mcp/fs/text_editing.rs', 'src/mcp/fs/remote.rs', 'native/text_budget.hepta',
    'native/atomic_write.hepta', 'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
    'scripts/hia_native_atomic_write_build.py', 'rustfmt.toml')
STATE_COUNTS = {'capacity_refusals': 4, 'frame_refusals': 75, 'growth_refusals': 57,
    'lifecycle_operations': 46, 'native_calls': 51972, 'original_owner_operations': 51783,
    'reference_rows': 51829, 'refusal_fixture_initializations': 1, 'state_refusals': 6}
STATE_INPUT = (25300373, '086b4d0be0b4acb2d1d2d676d997b01ef9767d3f98942421b8873a5c2981f47a')
STATE_OUTPUT = (3317056, '0ca151ce3fd5f421aecf29acdbb21435ee499af54ad3d70d4ae3a6478654837f')
STATE_DOMAINS = (4231733, '8561539e1c16a1cd3f1c38571776e669a3227f7c392bf3883f40f0a85cef404f')
STATE_SUMMARY = {'status': 'PASS', 'rows': 51829, 'original_owner_rows': 51783,
    'lifecycle_rows': 46, 'operation_counts': [23, 18061, 3197, 2984, 2718, 509, 21258, 3056, 0, 23],
    'borrowed_guards': True, 'extra_strong_observer_refs': 0}
KEY_SUMMARY = {'status': 'PASS', 'rows': 89715, 'local_rows': 89499, 'remote_rows': 216,
    'remote_metadata_projection_calls': 1728, 'actual_original_owner_calls': 91227}

def pins(root=ROOT):
    root = Path(root)
    return {name: file_record(root / name) for name in (*OWN, *REFERENCES)}

def source_contract(root=ROOT, hepta=None):
    root = Path(root)
    source_pins(root)
    exact(read(root / 'rustfmt.toml'), b'hard_tabs = true\n', 'original reference formatting configuration changed')
    for relative, blob in (('src/mcp/fs/text_editing.rs', '4a8114e72a51238608201e108288294c6282ab20'),
                           ('src/mcp/fs/remote.rs', 'b570130be0f545e91160339076388f255bd83abe')):
        raw = read(root / relative)
        exact(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), blob, 'file-lock original Git blob changed')
    raw = read(root / 'src/mcp/fs/text_editing.rs')
    start = raw.index(b'// Thread-safe file locking infrastructure')
    end = raw.index(b'/// Test-only visibility', start)
    exact(sha(raw[start:end]), '177460f70c88a723d33d4c67a708808b636f70cf4160d3fc11865871e8e395f1', 'complete lock owner block changed')
    for module in (file_lock_key_cases, file_lock_key_kernel):
        exact(read(module.__file__), read(root / 'tests/hia_native' / Path(module.__file__).name), 'loaded lock case/helper differs')
    lock = tomllib.loads(read(root / 'tests/hia_native/file_lock_oracle/Cargo.lock').decode())
    expected = {'tokio': ('1.53.1', '202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed'),
        'anyhow': ('1.0.104', '330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470'),
        'libc': ('0.2.189', '3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2')}
    for name, (version, digest) in expected.items():
        found = [p for p in lock['package'] if p['name'] == name]
        exact(len(found), 1, 'original file-lock dependency missing')
        for key, value in {'version': version, 'checksum': digest,
            'source': 'registry+https://github.com/rust-lang/crates.io-index'}.items():
            exact(found[0].get(key), value, 'original file-lock dependency differs')
    if hepta is not None:
        imported_contract(hepta, root)
    return {'source_files': pins(root), 'imported_functions': 13, 'original_owner_bytes': end - start,
        'original_owner_sha256': sha(raw[start:end]), 'locked_dependencies': {name: {'version': value[0], 'checksum': value[1]} for name, value in expected.items()},
        'whole_runtime_replaced': False, 'concurrent_shared_owner_closed': False}

def gzip_record(path, expected=None):
    total, digest = 0, hashlib.sha256()
    with gzip.open(path, 'rb') as stream:
        while part := stream.read(1 << 20):
            total += len(part)
            if expected is not None:
                require(total <= expected[0], 'file-lock gzip exceeds complete declared domain')
            digest.update(part)
    value = {'bytes': total, 'sha256': digest.hexdigest()}
    if expected is not None:
        exact(value, dict(zip(('bytes', 'sha256'), expected)), 'file-lock complete gzip domain differs')
    return value

def duration(value, message):
    require(type(value) in (int, float) and 0 < value < 180, message)

def completed(value, path):
    require(path is not None, 'actual completed process stdout is required')
    exact(obj(path), value, 'file-lock completed process stdout differs')
    return file_record(path)

def state_evidence(directory, artifact, *, source_root=ROOT, stdout=None):
    directory, root = Path(directory), Path(source_root)
    value = obj(directory / 'result.json')
    for key, expected in {'schema': 'hepta.runtime.file-lock-state-native.v1', 'status': 'PASS',
        'groups': 6, 'counts': STATE_COUNTS, 'actual_filesystem_effects': 0,
        'original_rust_status': 'PENDING', 'native_cross_thread_serialization_proved': False,
        'complete_canonical_file_lock_owner': False, 'production_activated': False,
        'bundle_artifacts': artifact}.items():
        exact(value.get(key), expected, 'file-lock state execution differs: ' + key)
    duration(value['elapsed'], 'file-lock state missed unchanged suite budget')
    exact(value['identity'], {'source_sha256': FROZEN['native/file_lock_state.hepta'],
        'image_sha256': IMAGES['state'], 'manifest_sha256': artifact['modules']['state']['manifest']['sha256'],
        'compiler_commit': COMMIT}, 'actual loaded state image differs')
    wanted = ('native/file_lock_state.hepta', 'native/file_lock_state_composition.json', 'tests/hia_native/test_file_lock_state.py')
    exact(value['source_sha256'], {name: sha(read(root / name)) for name in wanted}, 'actual state test source differs')
    files = {}
    for name in ('requests.bin.gz', 'native-output.bin.gz', 'domains.jsonl.gz', 'growth.json',
                 'elf-request.bin', 'elf.stdout', 'elf.stderr'):
        observed = file_record(directory / name)
        if name.endswith('.gz'):
            expected = {'requests.bin.gz': STATE_INPUT, 'native-output.bin.gz': STATE_OUTPUT,
                'domains.jsonl.gz': STATE_DOMAINS}[name]
            raw = gzip_record(directory / name, expected)
            observed.update(raw_bytes=raw['bytes'], raw_sha256=raw['sha256'])
        exact(value['corpus'].get(name), observed, 'actual state corpus file changed')
        files[name] = observed
    exact(set(value['corpus']), set(files), 'state corpus file set differs')
    exact(files['growth.json'], {'bytes': 25515, 'sha256': '1ab6b7a5683369be666f2fa36e33af3bc00c31f42a41ed41a4084969be93e480'}, 'all 57 unchanged-state growth refusals must be retained')
    rows, sessions = 0, set()
    with gzip.open(directory / 'requests.bin.gz', 'rb') as source, gzip.open(directory / 'native-output.bin.gz', 'rb') as answers, \
         gzip.open(directory / 'domains.jsonl.gz', 'rb') as domains, (directory / 'elf-request.bin').open('rb') as frames, \
         (directory / 'elf.stdout').open('rb') as elf:
        while header := source.read(16):
            require(len(header) == 16, 'state input envelope truncated')
            sid, size = struct.unpack('<QQ', header)
            require(64 <= size <= (5 << 20) + 64, 'state input extent changed')
            wire = source.read(size)
            require(len(wire) == size, 'state input row truncated')
            op = struct.unpack_from('<Q', wire, 8)[0]
            rows += 1
            sessions.add(sid)
            exact(json.loads(domains.readline()), {'ordinal': rows, 'session': sid, 'op': op,
                'domain': 'lifecycle_operations' if op in (0, 9) else 'original_owner_operations'}, 'state domain row changed')
            answer = answers.read(64)
            require(len(answer) == 64 and answer[:8] == b'HRFLKR01', 'state output row truncated')
            exact(struct.unpack_from('<Q', answer, 8)[0], op, 'state response operation differs')
            exact(frames.read(8 + size), header[8:] + wire, 'actual persistent ELF input differs from complete corpus')
            exact(elf.read(68), struct.pack('<I', 64) + answer, 'actual persistent ELF output differs from direct image')
        for stream in (answers, domains, frames, elf):
            exact(stream.read(), b'', 'state retained stream has extra rows')
    exact(rows, 51829, 'state complete row count differs')
    exact(len(sessions), 23, 'state session coverage differs')
    executable = value['persistent_executable']
    for key, expected in {'actual_elf_requests': rows, 'sessions': 23, 'actual_original_calls': 0,
        'exit_code': 0, 'timeout_seconds': 180, 'stdin_file': 'elf-request.bin', 'stdout_file': 'elf.stdout',
        'stderr_file': 'elf.stderr', 'stdin_sha256': files['elf-request.bin']['sha256'],
        'stdout_sha256': files['elf.stdout']['sha256'],
        'executable_sha256': artifact['executables']['state']['inspection']['sha256']}.items():
        exact(executable.get(key), expected, 'state actual executable receipt differs')
    duration(executable['elapsed'], 'state ELF missed unchanged budget')
    exact(read(directory / 'elf.stderr'), b'', 'state ELF emitted stderr')
    result = {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'files': files,
        'direct_native_calls': 51972, 'actual_elf_requests': rows, 'reference_rows': rows,
        'evidence_kind': 'retained_completed_native_execution'}
    if stdout is not None:
        result['completed_stdout'] = completed(value, stdout)
    return result

def bulk_evidence(directory, binary_sha):
    directory = Path(directory)
    value = obj(directory / 'result.json')
    for key, expected in {'schema': 'hepta.runtime.file-lock-key-corpus.v1', 'status': 'PASS',
        'counts': {'local': 89499, 'remote': 216}, 'actual_original_calls': 0, 'timeout_seconds': 180,
        'exit_code': 0, 'actual_elf_requests': 89715, 'original_rust_status': 'PENDING'}.items():
        exact(value.get(key), expected, 'canonical native corpus receipt differs')
    exact(value['executable']['sha256'], binary_sha, 'actual canonical executable differs')
    duration(value['elapsed'], 'canonical native corpus missed unchanged budget')
    exact(file_record(directory / 'requests.bin'), value['requests'], 'canonical input changed')
    for name, expected in value['artifacts'].items():
        exact(file_record(directory / name), expected, 'canonical retained file changed')
    require(set(value['artifacts']) == {'requests.bin.gz', 'native-output.bin.gz', 'native.stdout', 'native.stderr'}, 'canonical corpus artifact set differs')
    exact(gzip_record(directory / 'requests.bin.gz'), value['requests'], 'canonical full input gzip differs')
    exact(file_record(directory / 'native.stdout'), value['stdout'], 'canonical actual stdout changed')
    exact(gzip_record(directory / 'native-output.bin.gz'), value['stdout'], 'canonical full output gzip differs')
    exact(read(directory / 'native.stderr'), b'', 'canonical ELF emitted stderr')
    counts = collections.Counter()
    with (directory / 'requests.bin').open('rb') as source, (directory / 'native.stdout').open('rb') as answers:
        for domain, wire in file_lock_key_cases.requests():
            counts[domain] += 1
            exact(source.read(8 + len(wire)), struct.pack('<Q', len(wire)) + wire, 'canonical domain row omitted or changed')
            count = answers.read(4)
            require(len(count) == 4, 'canonical output header truncated')
            size, = struct.unpack('<I', count)
            require(32 <= size <= (15 << 20) + 65536, 'canonical output extent differs')
            answer = answers.read(size)
            require(len(answer) == size, 'canonical output row truncated')
            magic, op, length, zero = struct.unpack_from('<8s3Q', answer)
            exact((magic, op, length, zero), (b'HRLKY001', 1 if domain == 'local' else 2, size - 32, 0), 'canonical output header differs')
            answer[32:].decode('utf-8')
        exact(source.read(), b'', 'canonical input has extra rows')
        exact(answers.read(), b'', 'canonical output has extra rows')
    exact(dict(counts), value['counts'], 'canonical complete domain count differs')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'cases': sum(counts.values()),
        'files': {name: file_record(directory / name) for name in ('requests.bin', *value['artifacts'])}}

def key_evidence(directory, artifact, *, source_root=ROOT, stdout=None):
    directory, root = Path(directory), Path(source_root)
    value = obj(directory / 'result.json')
    for key, expected in {'schema': 'hepta.runtime.file-lock-key-native.v1', 'status': 'PASS', 'groups': 4,
        'actual_original_calls': 0, 'original_rust_status': 'PENDING', 'bundle_artifacts': artifact}.items():
        exact(value.get(key), expected, 'canonical native execution differs')
    duration(value['elapsed'], 'canonical native suite missed unchanged budget')
    names = ('tests/hia_native/test_file_lock_key.py', 'tests/hia_native/file_lock_key_cases.py',
        'tests/hia_native/file_lock_fixture.py', 'tests/hia_native/run_file_lock_key.py', 'scripts/hia_native_loader.py')
    exact(value['source_files'], {name: file_record(root / name) for name in names}, 'actual canonical test sources changed')
    bulk = bulk_evidence(directory / 'bulk', artifact['executables']['key']['inspection']['sha256'])
    exact(value['bulk'], obj(directory / 'bulk/result.json'), 'canonical embedded bulk receipt differs')
    fixture = value['fixture']
    exact(fixture.get('retired'), True, 'native canonical fixture was not retired')
    require(not (directory / 'bulk/fixture').exists(), 'native canonical fixture still occupies artifact output')
    exact(file_record(directory / 'bulk' / fixture['file']), {key: fixture[key] for key in ('bytes', 'sha256')}, 'canonical fixture archive changed')
    exact(gzip_record(directory / 'bulk' / fixture['file']), {'bytes': fixture['raw_bytes'], 'sha256': fixture['raw_sha256']}, 'canonical full fixture snapshot differs')
    domains = collections.Counter(row['domain'] for row in value['admission'])
    exact(sha(canonical(value['admission'])), 'f4e39edee85044b3203b2d5b74f8ac7fc9be62cbf1ddd7b223eaae3dbb7f1a60', 'complete actual canonical admission corpus changed')
    exact(dict(domains), {'frame': 76, 'capacity': 4, 'effect_creation': 1, 'completion': 18, 'output_growth': 1}, 'canonical refusal domain omitted')
    for row in value['admission']:
        domain = row['domain']
        if domain in ('frame', 'completion'):
            exact(row['code'], 0xffffffff if domain == 'frame' else 0xfffffff9, 'canonical refusal status differs')
            exact(row['workspace_before_sha256'], row['workspace_after_sha256'], 'canonical refusal mutated workspace')
            exact(row['output_sha256'], sha(b'\xa5' * 128), 'canonical refusal published payload')
        elif domain == 'capacity':
            exact(row['code'], 0xfffffffe, 'canonical capacity refusal differs')
        elif domain == 'effect_creation':
            exact(row['code'], 0xfffffff0, 'canonical effect continuation differs')
        else:
            exact(row['continuation'], 0xffffffee, 'canonical output growth was changed to semantic failure')
            exact(row['actual_native_calls'], 2, 'canonical growth resumption omitted')
    exact(len(value['transport']), 16, 'canonical transport controls omitted')
    for kind in ('state', 'key'):
        rows = [row for row in value['transport'] if row['kind'] == kind]
        expected = {'eof': 0, 'argv': 64, 'partial-prefix': 74, 'partial-payload': 74,
            'invalid-continue': 0, 'overflow-allocation': 71, 'unknown-return': 70, 'dirty-upper-return': 70}
        exact({row['name']: row['exit_code'] for row in rows}, expected, 'actual transport refusal set differs')
        for row in rows:
            exact(row['stderr_hex'], '', 'actual transport stderr differs')
            exact(row['stdout_hex'], struct.pack('<II', 0xffffffff, 0xffffffff).hex() if row['name'] == 'invalid-continue' else '', 'actual transport output differs')
            if row['domain'] == 'invalid_image_fixture':
                image = bytes.fromhex(row['image_hex'])
                path = directory / (kind + '-' + row['name'] + '.elf')
                exact(file_record(path), row['packed_elf'], 'actual boundary probe changed')
                inspect_elf(read(path), image, kind)
                exact(row['packer_image_sha256'], IMAGES[kind + '-packer'], 'probe did not use current native packer')
            else:
                exact(row['executable_sha256'], artifact['executables'][kind]['inspection']['sha256'], 'actual transport executable differs')
                exact(row['timeout_seconds'], 10, 'transport control timeout changed')
    answer = {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'bulk': bulk,
        'admission_calls': 101, 'transport_processes': 16, 'native_packer_calls': 4,
        'actual_original_calls': 0, 'evidence_kind': 'retained_completed_native_execution'}
    if stdout is not None:
        summary = {'status': 'PASS', 'groups': 4, 'elapsed': value['elapsed'], 'bulk_actual_elf_requests': 89715,
            'admission_records': 100, 'transport_processes': 16, 'result': file_record(directory / 'result.json')}
        answer['completed_stdout'] = completed(summary, stdout)
    return answer

def native_evidence(bundle, state_directory, key_directory, *, source_root=ROOT, hepta=None,
                    state_stdout=None, key_stdout=None):
    require(state_stdout is not None and key_stdout is not None, 'all native process completion stdout is mandatory')
    before = pins(source_root)
    closure = source_contract(source_root, hepta)
    artifacts = inspect_bundle(bundle, source_root=source_root)
    state = state_evidence(state_directory, artifacts, source_root=source_root, stdout=state_stdout)
    key = key_evidence(key_directory, artifacts, source_root=source_root, stdout=key_stdout)
    exact(pins(source_root), before, 'file-lock sources changed during complete evidence review')
    return {'schema': 'hepta.runtime.file-lock-native-evidence.v1', 'status': 'PASS', 'source_files': before,
        'source_contract': closure, 'artifacts': artifacts, 'state': state, 'key': key,
        'actual_original_calls': 0, 'evidence_kind': 'retained_completed_native_execution',
        'whole_runtime_replaced': False, 'production_activated': False, 'concurrent_shared_owner_closed': False}

def kernel_evidence(directory, native_sha, original_sha, *, source_root=ROOT):
    """Reconstruct all 112 pairs from complete raw traces and retained bytes."""
    directory, root = Path(directory), Path(source_root)
    value = obj(directory / 'result.json')
    domain = file_lock_key_kernel.cases()
    for key, expected in {'schema': 'hepta.runtime.file-lock-key-kernel-comparison.v1', 'status': 'PASS',
        'declared_cases': 112, 'cases': 112, 'native_processes': 112, 'original_processes': 112,
        'native_binary_sha256': native_sha, 'original_binary_sha256': original_sha}.items():
        exact(value.get(key), expected, 'file-lock paired kernel receipt differs')
    exact(json.loads(read(directory / 'cases.json')), domain, 'complete canonical kernel domain changed')
    names = ('file_lock_key_cases.py', 'file_lock_key_kernel.py', 'file_lock_key_supervisor.py', 'file_lock_fixture.py')
    exact(value['source_files'], {name: sha(read(root / 'tests/hia_native' / name)) for name in names}, 'actual kernel helper sources changed')
    duration(value['elapsed'], 'canonical paired kernel suite missed unchanged budget')
    exact(len(value['observations']), len(domain), 'canonical kernel pair omitted')
    recorded_directory = Path(value['directory'])
    require(recorded_directory.is_absolute(), 'kernel execution directory must be recorded absolutely')
    files, effects = {}, {'native': 0, 'original': 0}
    for index, (case, observed) in enumerate(zip(domain, value['observations'])):
        entry = directory / f'{index:03d}-{case["name"]}'
        recorded_entry = recorded_directory / entry.name
        exact(obj(entry / 'comparison.json'), observed, 'canonical pair result changed')
        exact(observed['name'], case['name'], 'canonical kernel case order differs')
        raw = read(entry / 'request.bin')
        path = bytes.fromhex(case['path_hex'])
        if case.get('absolute'):
            path = str(recorded_entry / 'fixture').encode() + b'/' + path
        wire = file_lock_key_cases.request(path)
        exact(raw, struct.pack('<Q', len(wire)) + wire, 'canonical kernel input bytes differ')
        exact(observed['request_sha256'], sha(raw), 'canonical pair input digest differs')
        exact(observed['request_bytes'], len(raw), 'canonical pair input length differs')
        parts = [(str(i) + '-' + 'a' * 117).encode().hex() for i in range(case.get('deep', 0))]
        if case.get('removed'):
            parts = [b'removed'.hex()]
        config = {'faults': case['faults'], 'cwd_parts': parts, 'unlink_cwd': bool(case.get('removed'))}
        exact(obj(entry / 'config.json'), config, 'canonical declared kernel controls differ')
        exact(len(observed['invocations']), 2, 'canonical actual side omitted')
        pair = []
        for name, record, binary_sha in zip(('native', 'original'), observed['invocations'], (native_sha, original_sha)):
            exact(record['name'], name, 'canonical kernel side order differs')
            exact(record['exit_code'], 0, 'actual kernel process failed')
            exact(record['timeout'], 20, 'actual kernel outer deadline changed')
            duration(record['elapsed'], 'actual kernel process did not complete in suite budget')
            require(record['elapsed'] < 20, 'actual kernel outer deadline missed')
            output, error = read(entry / (name + '.stdout')), read(entry / (name + '.stderr'))
            for key, payload in (('stdout', output), ('stderr', error)):
                exact(record[key + '_sha256'], sha(payload), 'actual kernel channel digest changed')
                exact(record[key + '_bytes'], len(payload), 'actual kernel channel length changed')
            if name == 'native':
                exact(error, b'', 'native canonical kernel process emitted stderr')
            else:
                exact(json.loads(error), {'status': 'PASS', 'rows': 1, 'local_rows': 1, 'remote_rows': 0,
                    'remote_metadata_projection_calls': 0, 'actual_original_owner_calls': 1}, 'actual original kernel summary differs')
            trace = obj(entry / (name + '.trace.json'))
            exact(trace['fixture'], str(recorded_entry / 'fixture'), 'actual kernel fixture identity differs')
            command = record['command']
            require(type(command) is list and len(command) == 13 and Path(command[0]).is_absolute(), 'kernel process command differs')
            exact(command[1:3], ['-I', command[2]], 'kernel isolated Python flag changed')
            exact(Path(command[2]).name, 'file_lock_key_supervisor.py', 'kernel supervisor entry changed')
            exact(command[3:], ['--executable', value[name + '_executable'], '--fixture', str(recorded_entry / 'fixture'),
                '--config', str(recorded_entry / 'config.json'), '--log', str(recorded_entry / (name + '.trace.json')),
                '--timeout', '15'], 'kernel command or unchanged deadline differs')
            for key, expected in {'schema': 'hepta.runtime.file-lock-key-kernel-trace.v1', 'status': 'PASS',
                'failure': None, 'exit_code': 0, 'executable_sha256': binary_sha, 'config': config,
                'stdout_bytes': len(output), 'stdout_sha256': sha(output), 'stderr_bytes': len(error),
                'stderr_sha256': sha(error), 'owner_epoch': 'first-read-on-stdin-before-any-owner-syscall'}.items():
                exact(trace.get(key), expected, 'actual complete kernel trace differs: ' + key)
            require(type(trace['elapsed']) in (int, float) and 0 < trace['elapsed'] < 15, 'canonical supervisor missed unchanged deadline')
            require(set(trace['memory_readers']) <= {'owned-process-vm-readv', 'owned-proc-mem-pread'}, 'unapproved target memory reader')
            counts = collections.Counter()
            for event in trace['events']:
                require(event['domain'] in ('owner', 'startup', 'transport'), 'unclassified kernel event')
                if event['domain'] != 'owner':
                    exact(event['completion'], 'kernel_continue', 'startup/transport kernel event was changed')
                    continue
                counts[event['kind']] += 1
                exact(event['ordinal'], counts[event['kind']], 'raw owner syscall ordinal omitted')
                faults = [fault for fault in case['faults'] if fault['kind'] == event['kind']
                    and fault.get('ordinal', 1) == event['ordinal']]
                require(len(faults) <= 1, 'duplicate declared syscall control')
                if faults:
                    fault = faults[0]
                    if 'errno' in fault:
                        exact(event['completion'], 'injected_errno_without_kernel_effect', 'declared errno control not applied')
                        exact(event['errno'], fault['errno'], 'declared errno control changed')
                    else:
                        exact(event['completion'], 'injected_value_without_kernel_effect', 'declared value control not applied')
                        wanted = event['capacity'] if fault['return'] == 'readlink_capacity' else fault['return']
                        exact(event['value'], wanted, 'declared value control changed')
                else:
                    exact(event['completion'], 'kernel_continue', 'undeclared synthetic owner effect')
            exact(dict(counts), trace['counts'], 'complete raw syscall counts differ')
            for fault in case['faults']:
                require(counts[fault['kind']] >= fault.get('ordinal', 1), 'declared kernel fault was never exercised')
            normalized = file_lock_key_kernel.normalized(trace)
            exact(observed[name + '_normalized_trace'], normalized, 'retained normalized trace dropped raw owner events')
            effects[name] += len(normalized)
            pair.append((output, normalized))
        exact(pair[0], pair[1], 'actual native/original kernel pair differs')
        exact(observed['output_match'], True, 'canonical pair output did not match')
        exact(observed['kernel_trace_match'], True, 'canonical pair trace did not match')
        require(not (entry / 'fixture').exists(), 'qualified canonical fixture was not retired')
        snapshots = observed['fixture_snapshots']
        exact(file_record(entry / snapshots['file']), {key: snapshots[key] for key in ('bytes', 'sha256')}, 'full kernel fixture archive changed')
        exact(gzip_record(entry / snapshots['file']), {'bytes': snapshots['raw_bytes'], 'sha256': snapshots['raw_sha256']}, 'full kernel fixture state truncated')
        captured = json.loads(gzip.decompress(read(entry / snapshots['file'])))
        expected_after = ([row for row in captured['before'] if row['path_hex'] != b'removed'.hex()]
            if case.get('removed') else captured['before'])
        exact(captured['after_native'], expected_after, 'native canonical invocation changed the fixture')
        exact(captured['after_original'], expected_after, 'original canonical invocation changed the fixture')
        exact(captured['removed_cwd_is_a_fixture_effect'], bool(case.get('removed')), 'removed-cwd domain attribution differs')
        retired = observed['fixture_retirement']
        exact(retired['retired'], True, 'canonical fixture retirement incomplete')
        exact(file_record(entry / retired['file']), {key: retired[key] for key in ('bytes', 'sha256')}, 'retired canonical state archive changed')
        exact(gzip_record(entry / retired['file']), {'bytes': retired['raw_bytes'], 'sha256': retired['raw_sha256']}, 'retired canonical full state truncated')
        exact(json.loads(gzip.decompress(read(entry / retired['file'])))['entries'], expected_after, 'retired canonical state differs from actual observation')
        expected_names = {'request.bin', 'config.json', 'comparison.json', 'native.stdout', 'native.stderr',
            'original.stdout', 'original.stderr', 'native.trace.json', 'original.trace.json',
            'fixture-snapshots.json.gz', 'fixture-retired.json.gz'}
        exact({path.name for path in entry.iterdir()}, expected_names, 'canonical kernel artifact set differs')
        for path in entry.iterdir():
            files[str(path.relative_to(directory))] = file_record(path)
    for name in ('native', 'original'):
        exact(value[name + '_owner_effects'], effects[name], 'complete original/native owner effect accounting differs')
    exact(effects['native'], effects['original'], 'canonical paired effect counts differ')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'cases': 112,
        'native_processes': 112, 'original_processes': 112, 'owner_effects_each': effects['native'],
        'files': files, 'evidence_kind': 'retained_completed_kernel_execution'}

def original_evidence(directory, bundle, state_corpus, *, source_root=ROOT, stdout):
    """Verify a retained completed reference run; this function runs no Rust."""
    directory, root = Path(directory), Path(source_root)
    value = obj(directory / 'result.json')
    before = pins(root)
    artifact = inspect_bundle(bundle, source_root=root)
    state = state_evidence(state_corpus, artifact, source_root=root)
    for key, expected in {'schema': 'hepta.runtime.file-lock-original-comparison.v1', 'status': 'PASS',
        'source_files': before, 'source_contract': source_contract(root), 'artifacts': artifact, 'native_state': state,
        'original_build_is_fresh': True, 'original_replay_is_fresh': True,
        'concurrent_shared_owner_closed': False, 'canonical_to_state_composition_closed': False,
        'whole_runtime_replaced': False, 'production_activated': False,
        'state_summary': STATE_SUMMARY, 'key_summary': KEY_SUMMARY}.items():
        exact(value.get(key), expected, 'actual original file-lock comparison differs: ' + key)
    duration(value['elapsed'], 'original file-lock recipe missed unchanged 180-second budget')
    recorded, recorded_root = Path(value['directory']), Path(value['source_root'])
    require(recorded.is_absolute() and recorded_root.is_absolute(), 'original execution roots are not absolute')
    cleared = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
        'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
    exact(value['cleared_environment_names'], cleared, 'original Rust override sanitation changed')
    require(all(name in cleared or name.startswith('HIA_') for name in value['removed_environment_names']), 'original override record has unclassified names')
    exact(set(value['tools']), {'cargo', 'rustc', 'rustfmt'}, 'original selected toolchain set differs')
    for name, tool in value['tools'].items():
        require(Path(tool['path']).is_absolute() and Path(tool['path']).name == name
            and Path(tool['resolved_path']).is_absolute() and type(tool['bytes']) is int and tool['bytes'] > 0
            and len(tool['sha256']) == 64, 'original selected toolchain record differs')
    exact(value['selected_environment'], {'RUSTC': value['tools']['rustc']['path'],
        'CARGO_TARGET_DIR': str(recorded / 'target'), 'HIA_REFERENCE_RUNTIME': str(recorded_root),
        'TMPDIR': str(recorded / 'tmp')}, 'actual original build environment differs')
    binaries = {}
    for kind, name in (('state', 'hia-file-lock-original'), ('key', 'hia-file-lock-key-original')):
        identity = value['binaries'][kind]
        exact(identity['path'], str(recorded / 'target/release' / name), 'actual original binary path differs')
        exact(file_record(directory / 'target/release' / name), {key: identity[key] for key in ('bytes', 'sha256')}, 'executed original binary changed')
        binaries[kind] = identity
    expected_names = ['rustc-version', 'format-check', 'cargo-build', 'original-state', 'original-key']
    exact([row['name'] for row in value['records']], expected_names, 'actual original process sequence omitted')
    format_sources = [str(recorded_root / 'tests/hia_native' / name) for name in
        ('oracle_file_lock_state.rs', 'oracle_file_lock_key.rs', 'file_lock_oracle/build.rs')]
    commands = {
        'rustc-version': [value['tools']['rustc']['path'], '-Vv'],
        'format-check': [value['tools']['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(recorded_root / 'rustfmt.toml'), '--check', *format_sources],
        'cargo-build': [value['tools']['cargo']['path'], 'build', '--release', '--locked', '--manifest-path',
            str(recorded_root / 'tests/hia_native/file_lock_oracle/Cargo.toml')],
        'original-state': [binaries['state']['path']], 'original-key': [binaries['key']['path']],
    }
    files = {}
    for row, budget in zip(value['records'], (10, 10, 120, 60, 180)):
        name = row['name']
        wanted = commands[name]
        if name == 'cargo-build' and row['command'] == wanted + ['--offline']:
            wanted = wanted + ['--offline']
        exact(row['command'], wanted, 'actual original command changed')
        exact(row['timeout_seconds'], budget, 'original reference deadline changed')
        exact(row['timed_out'], False, 'timed-out original reference was accepted')
        exact(row['exit_code'], 0, 'failed original reference was accepted')
        require(type(row['elapsed']) in (int, float) and 0 < row['elapsed'] < budget, 'original subprocess missed its budget')
        expected_cwd = recorded / ('key-bulk/fixture' if name == 'original-key' else 'empty-cwd')
        exact(row['cwd'], str(expected_cwd), 'original subprocess cwd changed')
        for channel in ('stdout', 'stderr'):
            path = directory / (name + '.' + channel)
            exact(file_record(path), row[channel], 'actual original stdout/stderr changed')
            files[path.name] = file_record(path)
        if name == 'original-state':
            expected_input = dict(zip(('bytes', 'sha256'), STATE_INPUT))
        elif name == 'original-key':
            expected_input = file_record(directory / 'key-bulk/requests.bin')
        else:
            expected_input = {'bytes': 0, 'sha256': sha(b'')}
        exact(row['input'], expected_input, 'actual original stdin changed')
    require(read(directory / 'rustc-version.stdout').startswith(b'rustc ')
        and b'host: x86_64-unknown-linux-gnu\n' in read(directory / 'rustc-version.stdout'), 'actual original compiler target differs')
    exact(read(directory / 'rustc-version.stderr'), b'', 'actual compiler version query failed')
    exact(read(directory / 'format-check.stdout'), b'', 'rustfmt check did not complete cleanly')
    exact(read(directory / 'format-check.stderr'), b'', 'rustfmt check emitted a diagnostic')
    exact(file_record(directory / 'state-input.bin'), dict(zip(('bytes', 'sha256'), STATE_INPUT)), 'complete actual original state input differs')
    for name in ('state-native.bin', 'original-state.stdout'):
        exact(file_record(directory / name), dict(zip(('bytes', 'sha256'), STATE_OUTPUT)), 'complete actual state output differs')
    exact(obj(directory / 'original-state.stderr'), STATE_SUMMARY, 'retained actual original state summary changed')
    exact(obj(directory / 'original-key.stderr'), KEY_SUMMARY, 'retained actual original key summary changed')
    original = read(root / 'src/mcp/fs/text_editing.rs')
    start = original.index(b'// Thread-safe file locking infrastructure')
    end = original.index(b'/// Test-only visibility', start)
    remote = read(root / 'src/mcp/fs/remote.rs')
    at = remote.index(b'#[derive(Debug, Clone)]\npub enum PathSource {')
    until = remote.index(b'\nimpl PathSource {', at)
    key_at = remote.index(b'\tpub fn lock_key(&self) -> String {')
    key_end = remote.index(b'\n\t/// Human-readable path', key_at)
    bodies = {'file_lock_original.rs': original[start:end], 'path_source_original.rs': remote[at:until],
        'path_key_original.rs': b'impl PathSource {\n' + remote[key_at:key_end] + b'\n}\n'}
    exact(set(value['compiled_original_sources']), set(bodies), 'compiled original owner closure omitted')
    for name, expected in bodies.items():
        exact(read(directory / name), expected, 'retained actual compiled original body differs')
        recorded_body = value['compiled_original_sources'][name]
        exact(file_record(directory / name), {key: recorded_body[key] for key in ('bytes', 'sha256')}, 'compiled original body digest differs')
        build_relative = Path(recorded_body['build_path']).relative_to(recorded)
        exact(read(directory / build_relative), expected, 'actual Cargo OUT_DIR body differs')
        files[name] = file_record(directory / name)
    bulk = bulk_evidence(directory / 'key-bulk', artifact['executables']['key']['inspection']['sha256'])
    exact(value['fresh_native_key_bulk'], obj(directory / 'key-bulk/result.json'), 'actual native side of original comparison differs')
    exact(file_record(directory / 'original-key.stdout'), file_record(directory / 'key-bulk/native.stdout'), 'complete original/native canonical bytes differ')
    fixture = value['key_fixture']
    exact(fixture['retired'], True, 'original bulk fixture retirement omitted')
    require(not (directory / 'key-bulk/fixture').exists(), 'original bulk fixture still occupies evidence directory')
    exact(file_record(directory / 'key-bulk' / fixture['file']), {key: fixture[key] for key in ('bytes', 'sha256')}, 'original bulk full fixture changed')
    exact(gzip_record(directory / 'key-bulk' / fixture['file']), {'bytes': fixture['raw_bytes'], 'sha256': fixture['raw_sha256']}, 'original bulk full fixture truncated')
    kernel = kernel_evidence(directory / 'kernel', artifact['executables']['key']['inspection']['sha256'], binaries['key']['sha256'], source_root=root)
    exact(value['kernel_evidence'], kernel, 'actual paired kernel evidence changed')
    exact(value['kernel_summary'], {key: entry for key, entry in obj(directory / 'kernel/result.json').items() if key != 'observations'}, 'actual kernel summary omitted a field')
    exact(pins(root), before, 'sources changed during original evidence inspection')
    return {'schema': 'hepta.runtime.file-lock-original-evidence.v1', 'status': 'PASS',
        'result': file_record(directory / 'result.json'), 'completed_stdout': completed(value, stdout),
        'source_files': before, 'files': files, 'state_reference_rows': 51829, 'state_original_owner_rows': 51783,
        'state_fixture_lifecycle_rows': 46, 'key_reference_rows': 89715, 'key_original_owner_calls': 91227,
        'kernel_reference_pairs': 112, 'bulk': bulk, 'kernel': kernel,
        'evidence_kind': 'retained_completed_original_execution', 'actual_new_native_calls': 0, 'actual_new_original_calls': 0}

def controls_evidence(directory, accepted, *, source_root=ROOT, stdout):
    directory = Path(directory)
    value = obj(directory / 'result.json')
    for key, expected in {'schema': 'hepta.runtime.file-lock-evidence-controls.v1', 'status': 'PASS',
        'groups': 3, 'source_files': pins(source_root), 'actual_native_calls': 0, 'actual_original_calls': 0}.items():
        exact(value.get(key), expected, 'file-lock evidence control receipt differs')
    duration(value['elapsed'], 'file-lock evidence controls missed unchanged budget')
    exact(obj(directory / 'accepted-native-evidence.json'), accepted, 'evidence controls did not inspect the current complete execution')
    exact(file_record(directory / 'accepted-native-evidence.json'), value['accepted_native_evidence'], 'accepted evidence record changed')
    expected = {'artifact-' + name.replace('/', '-') for name in (
        'state.image.bin', 'key.image.bin', 'state-packer.image.bin', 'key-packer.image.bin',
        'file-lock-state.elf', 'file-lock-key.elf', 'state-build/module.output.bin',
        'key-build/module.stdout.log', 'state-pack/pack.input.bin', 'key-pack/pack.output.bin',
        'state-pack/pack.stdout.log', 'key-pack/pack.receipt.json')}
    expected.update(('false-production-activation', 'wrong-compiler-commit', 'complete-state-input-corrupt',
        'complete-state-output-corrupt', 'actual-state-elf-output-corrupt', 'missing-growth-refusal',
        'complete-key-input-corrupt', 'actual-key-output-corrupt', 'omitted-key-admission',
        'omitted-dirty-return-control', 'stale-native-key-source', 'fabricated-native-completion', 'missing-native-completion'))
    exact(len(value['refusals']), 25, 'evidence refusal control omitted')
    exact({row['name'] for row in value['refusals']}, expected, 'evidence refusal domain changed')
    require(all(row['reason'] and row['message'] for row in value['refusals']), 'evidence refusal reason missing')
    require(not (directory / 'owned-mutation-fixture').exists(), 'restored private mutation copies were not retired')
    return {'status': 'PASS', 'result': file_record(directory / 'result.json'), 'refused': 25,
        'completed_stdout': completed(value, stdout), 'actual_new_native_calls': 0, 'actual_new_original_calls': 0}
