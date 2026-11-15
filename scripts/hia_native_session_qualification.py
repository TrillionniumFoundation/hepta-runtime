"""Admit actual session execution, its complete corpus and original replay."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

from hia_native_build import HEPTA_COMMIT, check_dependency, json_bytes
from hia_native_entropy_qualification import inspect_elf, read
from hia_native_scope_qualification import embedded_images
from hia_native_view_cache_qualification import _compiled

FOLDER = 'session-workdir'
SOURCE = '1dedf337f8dc5e59c363ee5ade616a9f494f97a264617f91d2d634a0280fa218'
IMAGE = '687ae923d53c39b261b1d6095cf6a544d649fce51dc3ac15bb496c299a9da750'
ELF = 'f391cc53a8cf45b7cae2569b5121a9e7b8cbeced5dea619fd76a2177f229fe98'
PROOF = '821f622ba622bc803c5fe6e121325466e3c5feab1b7f3e692a9e23c5b9d68fb5'
WORK_BYTES = (16 << 20) + 64
OWNER = ('native/session_workdir.hepta', 'native/session_workdir_composition.json',
    'native/session_workdir_abi.md', 'scripts/hia_native_session_build.py',
    'tests/hia_native/session_workdir_cases.py', 'tests/hia_native/test_session_workdir.py',
    'tests/hia_native/session_workdir_original.py', 'tests/hia_native/compare_session_workdir_original.py')
REFERENCES = ('scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
    'scripts/hia_native_composition_build.py', 'native/composition_packer.hepta',
    'tests/hia_native/view_cache_hex_transport.hepta', 'native/text_budget.hepta', 'src/mcp/server.rs')
COUNTS = {'native_image_calls': 5043, 'reference_rows': 4914, 'frame_refusals': 44,
    'capacity_refusals': 5, 'state_refusals': 10, 'actual_elf_processes': 8,
    'actual_elf_frames': 320, 'serialized_latch_calls': 64}
STREAMS = {
    'input.bin.gz': (17128264, 'a184bc8f231bd85a0f6c2d0c324f3bde76edf5b6815f76f913dd07866c80808b'),
    'native-output.bin.gz': (33914293, '4620a2c534dc3dab565c8feb9068b81b8fd42f771fdde8b9df1e54d7f8fcadbe'),
    'rows.jsonl.gz': (1084887, 'f1fe434d5d6f4cab547844dacd130020ebbc9bbb0930d82b898e00e646fea577')}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError('session evidence: ' + message)


def exact(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), message)


def object_at(path):
    def unique(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    result = json.loads(read(path), object_pairs_hook=unique)
    require(type(result) is dict, 'expected object')
    return result


def relative(root, name):
    require(type(name) is str, 'artifact path is not a string')
    path = Path(name)
    require(bool(path.parts) and not path.is_absolute() and '..' not in path.parts
            and path.as_posix() == name, 'artifact escaped owner')
    return root / path


def source_pins(root, reference_root=None):
    ref = root if reference_root is None else reference_root
    result = {'owner': {name: sha(read(root / name)) for name in OWNER},
              'reference': {name: sha(read(ref / name)) for name in REFERENCES}}
    require(result['owner']['native/session_workdir.hepta'] == SOURCE, 'state source changed')
    require(result['owner']['native/session_workdir_composition.json'] == PROOF, 'source proof changed')
    return result


def driver(root, name):
    path = root / 'tests/hia_native' / name
    read(path)
    spec = importlib.util.spec_from_file_location('session_admission_' + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_evidence(root, bundle_path, hepta, *, reference_root=None):
    ref = root if reference_root is None else reference_root
    pins = source_pins(root, ref)
    bundle_path = bundle_path.absolute()
    build = bundle_path.parents[2]; output = build.parent
    artifacts = {}
    def artifact(path):
        raw = read(path); artifacts[path.relative_to(output).as_posix()] = sha(raw)
        return raw
    bundle = object_at(bundle_path)
    require(artifact(bundle_path) == json_bytes(bundle), 'bundle encoding differs')
    expected = {'schema': 'hepta.runtime.session-workdir-bundle.v1', 'source_sha256': SOURCE,
        'proof_sha256': PROOF, 'image_sha256': IMAGE, 'compiler_commit': HEPTA_COMMIT,
        'full_raw_path_bytes': 8 << 20, 'workspace_bytes': WORK_BYTES,
        'fixture_is_complete_wide_domain': False, 'whole_runtime_replaced': False,
        'production_activated': False}
    exact({key: bundle.get(key) for key in expected}, expected, 'bundle scope changed')
    compiler = artifact(build / 'bootstrap/B3.image.bin')
    bootstrap = object_at(build / 'bootstrap/bootstrap.json'); artifact(build / 'bootstrap/bootstrap.json')
    require(bundle['compiler_sha256'] == sha(compiler), 'compiler image differs')
    exact(bootstrap['dependency'], check_dependency(hepta), 'compiler source closure differs')
    source = read(root / 'native/session_workdir.hepta')
    proof = object_at(root / 'native/session_workdir_composition.json')
    for item in proof['imports']:
        require(sha(read(relative(ref, item['path']))) == item['sha256'], 'import source differs')
    original = read(ref / 'src/mcp/server.rs')
    exact(proof['original_sources'], {'src/mcp/server.rs': {'sha256': sha(original),
        'git_blob': hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()}},
        'original owner source differs')
    driver(root, 'session_workdir_original.py').original_parts(ref)
    module_path = relative(build, bundle['module']); module = object_at(module_path)
    require(sha(artifact(module_path)) == bundle['module_sha256'], 'direct manifest changed')
    module_source = artifact(relative(module_path.parent, module['source']))
    image = artifact(relative(module_path.parent, module['image']))
    contract = {'schema': 'hepta.runtime.native-module.v1',
        'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'target': 'linux-x86_64',
        'compiler_commit': HEPTA_COMMIT, 'compiler_sha256': sha(compiler),
        'source_sha256': SOURCE, 'image_sha256': IMAGE, 'buffer_profile': 'history.v1',
        'input_capacity': 128 << 20, 'output_capacity': 128 << 20,
        'workspace_capacity': 256 << 20, 'standalone': None}
    exact({key: module.get(key) for key in contract}, contract, 'direct profile changed')
    require(module_source == source and sha(image) == IMAGE, 'direct source/image changed')
    _compiled(output, module_path.parent, source, image, compiler, artifacts)
    for name in ('module.request.json', 'module.stdout.log', 'module.stderr.log'):
        artifact(module_path.parent / name)
    fixture_path = relative(build, bundle['fixture']); fixture = object_at(fixture_path)
    require(sha(artifact(fixture_path)) == bundle['fixture_sha256'], 'fixture manifest changed')
    transport = read(ref / 'tests/hia_native/view_cache_hex_transport.hepta')
    packer = read(ref / 'native/composition_packer.hepta')
    profile = [dict(id=0, name='session-hex-fixture', flags=1, call_mask=2,
        input_capacity=8 << 20, output_capacity=8 << 20, workspace_capacity=16 << 20,
        source_sha256=sha(transport)), dict(id=1, name='session-workdir', flags=0, call_mask=0,
        input_capacity=8 << 20, output_capacity=8 << 20, workspace_capacity=WORK_BYTES,
        source_sha256=SOURCE)]
    require(fixture.get('schema') == 'hepta.runtime.native-composition.v1'
        and fixture.get('compiler_commit') == HEPTA_COMMIT
        and fixture.get('compiler_sha256') == sha(compiler), 'fixture compiler differs')
    exact(fixture.get('profile'), profile, 'fixture call table differs')
    require(len(fixture.get('members', [])) == 2, 'fixture member inventory differs')
    frame = bytearray(b'HIABND01' + struct.pack('<3Q', 2, 0, 0)); images = []
    rows = [('packer', packer, fixture['packer']), ('module_00', transport, fixture['members'][0]),
            ('module_01', source, fixture['members'][1])]
    for index, (stem, original_source, row) in enumerate(rows):
        require(row.get('manifest') == stem + '.json', 'child manifest path changed')
        path = fixture_path.parent / (stem + '.json'); child_raw = artifact(path); child = object_at(path)
        child_source = artifact(path.parent / (stem + '.hepta'))
        child_image = artifact(path.parent / (stem + '.image.bin'))
        require(sha(child_raw) == row['manifest_sha256'] and child_source == original_source
            and sha(child_source) == row['source_sha256'] and sha(child_image) == row['image_sha256'],
            'fixture child bytes changed')
        wanted = {**contract, 'source': stem + '.hepta', 'image': stem + '.image.bin',
            'source_sha256': sha(child_source), 'image_sha256': sha(child_image),
            'input_capacity': 8 << 20, 'output_capacity': 8 << 20, 'workspace_capacity': 32 << 20}
        wanted.pop('buffer_profile')
        exact({key: child.get(key) for key in wanted}, wanted, 'fixture child ABI differs')
        require(child.get('buffer_profile', 'standard') == 'standard', 'fixture child profile differs')
        compiled = build / 'modules' / ('composition-' + sha(child_source)[:24])
        _compiled(output, compiled, child_source, child_image, compiler, artifacts)
        for name in ('module.request.json', 'module.stdout.log', 'module.stderr.log'):
            artifact(compiled / name)
        if index:
            images.append(child_image); item = profile[index - 1]
            frame.extend(struct.pack('<8Q', len(child_image), item['input_capacity'], item['output_capacity'],
                item['workspace_capacity'], item['flags'], item['call_mask'], 0, 0))
            frame.extend(bytes.fromhex(sha(child_source)) + bytes.fromhex(sha(child_image)) + child_image)
    require(images[1] == image, 'fixture uses a different state image')
    require(fixture.get('executable') == 'native-local-read.elf', 'fixture executable path differs')
    elf = artifact(fixture_path.parent / fixture['executable']); layout = embedded_images(elf, profile, images)
    require(sha(elf) == ELF and fixture['executable_sha256'] == ELF, 'fixture ELF differs')
    exact(fixture['inspection'], inspect_elf(elf), 'fixture ELF inspection differs')
    exact(fixture['packing'], {'owner': 'HIA', 'input_unchanged': True,
        'buffer_canaries_unchanged': True, 'packer_image_sha256': fixture['packer']['image_sha256']},
        'fixture packing differs')
    key = sha(json_bytes({'compiler': sha(compiler), 'members': profile, 'packer': sha(packer)}))
    require(fixture['key'] == key and fixture['frame_bytes'] == len(frame)
        and fixture['frame_sha256'] == sha(frame), 'fixture construction frame differs')
    for name in ('runtime_python_required', 'runtime_libc_required', 'whole_runtime_replaced'):
        require(fixture.get(name) is False, 'fixture dependencies or scope changed')
    return {'schema': 'hepta.runtime.session-build-evidence.v1', 'source_pins': pins,
        'bundle_sha256': sha(read(bundle_path)), 'source_sha256': SOURCE, 'image_sha256': IMAGE,
        'executable_sha256': ELF, 'compiler_sha256': sha(compiler), 'source_profile': profile,
        'embedded_table': layout, 'artifact_sha256': artifacts, 'production_activated': False}


def stream(path, expected=None):
    compressed = read(path); raw = gzip.decompress(compressed)
    identity = {'gzip_bytes': len(compressed), 'gzip_sha256': sha(compressed),
                'raw_bytes': len(raw), 'raw_sha256': sha(raw)}
    if expected is not None:
        exact(identity, expected, 'retained stream identity differs: ' + path.name)
    return raw, identity


def checked_native(root, bundle_path, folder, hepta, stdout, *, reference_root=None,
                   recorded_output=None):
    ref = root if reference_root is None else reference_root
    built = build_evidence(root, bundle_path, hepta, reference_root=ref)
    result = object_at(folder / 'result.json')
    require(len(read(stdout).decode().splitlines()) == 1, 'actual suite stdout incomplete')
    exact(json.loads(read(stdout)), result, 'actual suite stdout differs')
    expected = {'schema': 'hepta.runtime.session-workdir-native-tests.v1', 'status': 'PASS',
        'counts': COUNTS, 'test_groups': 6, 'source_pins': source_pins(root, ref),
        'source_unchanged': True, 'bundle_sha256': sha(read(bundle_path)),
        'actual_original_comparison_completed': False, 'public_workdir_handler_complete': False,
        'first_capabilities_policy_and_os_checks_complete': False, 'production_activated': False,
        'static_wire_domain_is_full_state_corpus': False, 'whole_runtime_replaced': False}
    exact({key: result.get(key) for key in expected}, expected, 'native coverage or scope differs')
    require(type(result.get('elapsed_seconds')) in (int, float) and 0 < result['elapsed_seconds'] < 180,
            'native deadline differs')
    names = set(STREAMS) | {f'elf-{i}.{channel}.gz' for i in range(8)
                           for channel in ('stdin', 'stdout', 'stderr')}
    require(set(result['streams']) == names, 'complete stream inventory differs')
    artifacts = dict(built['artifact_sha256']); output = bundle_path.absolute().parents[3]
    raw_streams = {}
    for name in sorted(names):
        raw, _ = stream(folder / name, result['streams'][name])
        if name in STREAMS:
            require((len(raw), sha(raw)) == STREAMS[name], 'complete fixed state domain differs')
        raw_streams[name] = raw
        artifacts[(folder / name).relative_to(output).as_posix()] = sha(read(folder / name))
    cases = driver(root, 'session_workdir_cases.py')
    raw = raw_streams['input.bin.gz']; answer = raw_streams['native-output.bin.gz']
    rows = raw_streams['rows.jsonl.gz'].splitlines()
    require(len(rows) == COUNTS['reference_rows'], 'complete row inventory differs')
    at = written = 0
    for ordinal, row in enumerate(rows, 1):
        sid, size = struct.unpack_from('<II', raw, at); at += 8
        request = raw[at:at + size]; at += size
        size = struct.unpack_from('<I', answer, written)[0]; written += 4
        response = answer[written:written + size]; written += size
        exact(json.loads(row), {'ordinal': ordinal, 'session': sid,
            'operation': struct.unpack_from('<Q', request, 8)[0],
            'request_sha256': sha(request), 'response_sha256': sha(response)},
            'state row no longer binds complete request/result')
    require(at == len(raw) and written == len(answer), 'state corpus has trailing or missing bytes')
    fixture_path = relative(bundle_path.parents[2], object_at(bundle_path)['fixture'])
    fixture = object_at(fixture_path); elf = fixture_path.parent / fixture['executable']
    # Read-only relocation preserves the recorded command. The live aggregate
    # uses its own output path; corruption tests supply the original receipt root.
    if recorded_output is not None:
        elf = recorded_output / elf.relative_to(output)
    records = []
    for sid in range(8):
        name = f'elf-{sid}'; requests = list(cases.transport_cases(sid))
        wire = b'\n'.join(raw.hex().encode() for raw in requests) + b'\n'
        observed = raw_streams[name + '.stdout.gz']
        require(raw_streams[name + '.stdin.gz'] == wire and raw_streams[name + '.stderr.gz'] == b'',
                'actual fixture streams differ')
        lines = observed.splitlines(); require(len(lines) == 40, 'fixture session incomplete')
        model = cases.Reference()
        for request, line in zip(requests, lines, strict=True):
            code, encoded = line.split(b':', 1); response = bytes.fromhex(encoded.decode())
            require(int(code, 16) == len(response) and response == model.apply(sid, request),
                    'actual fixture response differs')
        record = {'session': sid, 'exit_code': 0, 'frames': 40, 'stdin_sha256': sha(wire),
                  'stdout_sha256': sha(observed), 'stderr_sha256': sha(b'')}
        records.append(record)
        process_path = folder / (name + '.process.json'); process = object_at(process_path)
        require(process.get('command') == [str(elf), '--local-read-profile', '/session-fixture']
            and type(process.get('timeout_seconds')) is int and process['timeout_seconds'] == 30
            and type(process.get('exit_code')) is int and process['exit_code'] == 0,
            'actual fixture invocation differs')
        exact({key: process.get(key) for key in ('stdin_sha256', 'stdout_sha256', 'stderr_sha256')},
            {key: record[key] for key in ('stdin_sha256', 'stdout_sha256', 'stderr_sha256')},
            'actual fixture process streams differ')
        artifacts[process_path.relative_to(output).as_posix()] = sha(read(process_path))
    exact(result['elf_records'], records, 'actual fixture process inventory differs')
    for path in (folder / 'result.json', stdout):
        artifacts[path.relative_to(output).as_posix()] = sha(read(path))
    return {'schema': 'hepta.runtime.session-native-evidence.v1', 'status': 'PASS',
        'build': built, 'counts': COUNTS, 'source_pins': source_pins(root, ref),
        'corpus_streams': {name: {'bytes': size, 'sha256': value} for name, (size, value) in STREAMS.items()},
        'native_result_sha256': sha(read(folder / 'result.json')), 'artifact_sha256': artifacts,
        'native_calls_added_by_evidence_admission': 0, 'actual_original_comparison_completed': False,
        'first_capabilities_policy_and_os_checks_complete': False, 'public_workdir_handler_complete': False,
        'production_activated': False, 'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}


def original_evidence(root, native_folder, folder, rustc, stdout, *, reference_root=None):
    ref = root if reference_root is None else reference_root
    result = object_at(folder / 'report.json')
    expected = {'schema': 'hepta.runtime.session-workdir-original.v1', 'status': 'PASS',
        'native_result_sha256': sha(read(native_folder / 'result.json')), 'original_rows': 4914,
        'actual_sessions': 9, 'actual_poison_events': 9, 'actual_latch_threads': 64,
        'complete_output_bytes': STREAMS['native-output.bin.gz'][0],
        'complete_output_sha256': STREAMS['native-output.bin.gz'][1], 'source_unchanged': True,
        'public_workdir_handler_complete': False, 'production_activated': False,
        'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}
    exact({key: result.get(key) for key in expected}, expected, 'original domain differs')
    require(len(read(stdout).decode().splitlines()) == 1, 'original wrapper stdout incomplete')
    exact(json.loads(read(stdout)), {k: v for k, v in result.items() if k not in ('inputs', 'processes')},
          'actual original wrapper stdout differs')
    generated = driver(root, 'session_workdir_original.py').oracle_source(ref).encode()
    require(read(folder / 'original.rs') == generated and result['original_source_sha256'] == sha(generated),
            'fresh original source differs')
    require(result['original_executable_sha256'] == sha(read(folder / 'original')),
            'fresh original executable changed')
    inputs = [root / 'tests/hia_native/compare_session_workdir_original.py',
        root / 'tests/hia_native/session_workdir_original.py', ref / 'src/mcp/server.rs',
        native_folder / 'result.json']
    exact(result['inputs'], {str(path): sha(read(path)) for path in inputs}, 'original input closure changed')
    commands = {'rust-version': [str(rustc), '--version'],
        'build': [str(rustc), '--edition=2024', '-O', str(folder / 'original.rs'), '-o', str(folder / 'original')],
        'replay': [str(folder / 'original')], 'latch': [str(folder / 'original'), '--latch-test']}
    processes = json.loads(read(folder / 'processes.json'))
    exact(result['processes'], processes, 'retained actual original processes differ')
    require([row.get('name') for row in processes] == list(commands), 'original subprocess inventory differs')
    for row in processes:
        name = row['name']
        require(row.get('command') == commands[name] and type(row.get('exit_code')) is int
            and row['exit_code'] == 0 and type(row.get('timeout_seconds')) is int
            and row['timeout_seconds'] == 180 and type(row.get('elapsed_seconds')) in (int, float)
            and 0 <= row['elapsed_seconds'] < 180, 'actual original subprocess failed or changed')
        for channel in ('stdout', 'stderr'):
            raw = stream(folder / 'replay.stdout.gz')[0] if name == 'replay' and channel == 'stdout' else read(folder / (name + '.' + channel))
            require(type(row.get(channel + '_bytes')) is int and row[channel + '_bytes'] == len(raw)
                and row.get(channel + '_sha256') == sha(raw), 'actual original stream differs')
    require(read(folder / 'rust-version.stdout').startswith(b'rustc 1.95.0 '), 'original compiler version differs')
    for name in ('rust-version.stderr', 'build.stdout', 'build.stderr', 'latch.stderr'):
        require(read(folder / name) == b'', 'unexpected original diagnostics')
    raw = stream(folder / 'replay.stdout.gz')[0]; native = stream(native_folder / 'native-output.bin.gz')[0]
    require(raw == native and (len(raw), sha(raw)) == STREAMS['native-output.bin.gz'],
            'complete original replay bytes differ')
    exact(json.loads(read(folder / 'replay.stderr')), {'status': 'PASS', 'rows': 4914,
        'sessions': 9, 'actual_poison_events': 9}, 'original poison/session coverage incomplete')
    exact(json.loads(read(folder / 'latch.stdout')), {'status': 'PASS', 'actual_threads': 64,
        'first': 1, 'later': 63}, 'actual original latch concurrency differs')
    return {'schema': 'hepta.runtime.session-original-evidence.v1', 'status': 'PASS',
        'report_sha256': sha(read(folder / 'report.json')), 'report': result,
        'stdout_sha256': sha(read(stdout)), 'native_calls_added_by_evidence_admission': 0,
        'production_activated': False, 'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}


def test_commands(root, output, report):
    bundle = relative(output, report['modules']['session_workdir']['manifest'])
    folder = output / FOLDER
    arguments = {
        'test_session_workdir.py': ['--bundle', bundle, '--output', folder / 'native'],
        'test_session_evidence.py': ['--runtime', root, '--reference', root,
            '--hepta', report['compiler_checkout'], '--bundle', bundle,
            '--corpus', folder / 'native', '--stdout', output / 'test_session_workdir.py.stdout',
            '--output', folder / 'controls']}
    return {name: [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name),
                   *map(str, args)] for name, args in arguments.items()}


def completed_process(root, output, report, completed, name, command):
    check, summary = completed(output, report, name)
    require(check.get('command') == command and type(check.get('exit_code')) is int
        and check['exit_code'] == 0 and check.get('timed_out') is False
        and type(check.get('timeout_seconds')) is int and check['timeout_seconds'] == 180
        and type(check.get('elapsed_seconds')) in (int, float) and 0 < check['elapsed_seconds'] < 180
        and type(check.get('stdout_bytes')) is int
        and check['stdout_bytes'] == len(read(output / (name + '.stdout')))
        and check.get('stderr_bytes') == 0 and read(output / (name + '.stderr')) == b'',
        'actual completed process differs: ' + name)
    return {key: check[key] for key in ('command', 'exit_code', 'timed_out', 'timeout_seconds',
            'stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256')}, summary


def qualification_evidence(root, output, report, completed):
    owner = report['modules']['session_workdir']
    require(owner.get('builder') == 'session_workdir'
        and owner.get('source') == 'native/session_workdir.hepta', 'owner registry differs')
    bundle = relative(output, owner['manifest'])
    require(sha(read(bundle)) == owner['sha256'], 'registered bundle changed')
    folder = output / FOLDER
    native = checked_native(root, bundle, folder / 'native', Path(report['compiler_checkout']),
                            output / 'test_session_workdir.py.stdout')
    processes = {}; summaries = {}
    for name, command in test_commands(root, output, report).items():
        processes[name], summaries[name] = completed_process(root, output, report, completed, name, command)
    exact(summaries['test_session_workdir.py'], object_at(folder / 'native/result.json'),
          'actual native summary differs')
    controls = object_at(folder / 'controls/result.json')
    exact(summaries['test_session_evidence.py'], controls, 'actual controls summary differs')
    expected = {'schema': 'hepta.runtime.session-evidence-controls.v1', 'status': 'PASS',
        'accepted': 2, 'refusals': 15, 'source_pins': source_pins(root),
        'baseline_sha256': sha(json_bytes(native)), 'native_calls_added': 0, 'rust_calls_added': 0,
        'production_activated': False, 'whole_runtime_replaced': False}
    exact({key: controls.get(key) for key in expected}, expected, 'complete controls differ')
    labels = ['source', 'proof', 'image', 'compile-receipt', 'elf', 'call-table', 'workspace',
        'bundle-scope', 'native-scope', 'missing-wide-response', 'missing-row', 'duplicate-stdout',
        'elf-argument', 'missing-elf-stream', 'native-count']
    require(type(controls.get('controls')) is list and
        [row.get('label') for row in controls['controls']] == labels and
        all(row.get('refused') is True and type(row.get('reason')) is str and row['reason']
            for row in controls['controls']), 'physical refusal inventory differs')
    require(type(controls.get('elapsed_seconds')) in (int, float) and
            0 < controls['elapsed_seconds'] < 180, 'controls deadline differs')
    artifacts = dict(native['artifact_sha256'])
    for path in (folder / 'controls/result.json', output / 'test_session_evidence.py.stdout'):
        artifacts[path.relative_to(output).as_posix()] = sha(read(path))
    return {'schema': 'hepta.runtime.session-completed-evidence.v1', 'status': 'PASS',
        'native': native, 'controls': controls, 'completed_processes': processes,
        'artifact_sha256': artifacts, 'production_activated': False,
        'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}


def original_command(root, output, rustc):
    return [sys.executable, '-I', '-B', str(root / 'tests/hia_native/compare_session_workdir_original.py'),
        '--runtime', str(root), '--corpus', str(output / FOLDER / 'native'),
        '--output', str(output / FOLDER / 'original'), '--rustc', str(rustc)]


def retained_original(root, output, report, rustc, completed):
    process, _ = completed_process(root, output, report, completed, 'session-workdir-rust-compare',
                                   original_command(root, output, rustc))
    result = original_evidence(root, output / FOLDER / 'native', output / FOLDER / 'original', rustc,
                               output / 'session-workdir-rust-compare.stdout')
    return {**result, 'completed_process': process, 'compiled_by_qualification_recipe': True}


def compare_original(root, output, report, rustc, completed, record_check, env):
    before = qualification_evidence(root, output, report, completed)
    exact(before, report['session_evidence'], 'native session evidence changed before reference')
    record_check(output, report, name='session-workdir-rust-compare',
        command=original_command(root, output, rustc), env=env, timeout=180)
    result = retained_original(root, output, report, rustc, completed)
    exact(qualification_evidence(root, output, report, completed), before,
          'native session evidence changed during reference')
    return result
