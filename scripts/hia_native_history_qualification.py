"""Bind complete HistoryStore execution to its native images and original owner."""
from __future__ import annotations
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

from hia_native_build import HEPTA_COMMIT, json_bytes
from hia_native_entropy_qualification import digest, inspect_elf, object_at, read
from hia_native_scope_qualification import embedded_images
from hia_native_view_cache_qualification import _compiled

FOLDER = 'history-rust-oracle'
CORPUS_FILES = ('native-corpus.json', 'input.bin.gz', 'native-output.bin.gz', 'rows.jsonl.gz')
IMPORTS = {'f2': 'f8', 'f14': 'f9', 'f15': 'f10', 'f16': 'f11'}
PACKER = '60c081c08f4f1be4a2585f49ce3f6dffa1a50707df9e0b8383a0396b61589f63'
TRANSPORT = '30779bf4c9315135a8a7ce6df86d4a1f84bffbe7cacfbf083c1980512851e54a'


def require(condition, message):
    if not condition:
        raise ValueError('history evidence: ' + message)


def exact(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), message)


def relative(root, name):
    value = Path(name)
    require(not value.is_absolute() and value.parts and '..' not in value.parts, 'artifact escaped output')
    return root / value


def driver(root):
    path = root / 'tests/hia_native/compare_history_original.py'
    read(path)
    spec = importlib.util.spec_from_file_location('history_original_replay', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_composition(root, reference, hepta):
    replay = driver(root)
    pins = replay.source_bindings(root, reference)
    proof = object_at(root / 'native/history_composition.json')
    require(len(proof['imports']) == 1, 'imported source set changed')
    imported = proof['imports'][0]
    require(imported['path'] == 'native/text_budget.hepta', 'imported owner changed')
    exact(imported['function_relocation'], IMPORTS, 'import relocation changed')
    raw = read(reference / imported['path'])
    require(digest(raw) == imported['sha256'], 'imported source bytes changed')
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    originals = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
    actual = {f['name']: f for f in assemble_program(read(root / 'native/history.hepta')).as_dict()['functions']}
    require(len(actual) == 12, 'native function inventory changed')
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    exact(imported['functions'], {old: digest(canonical(originals[old])) for old in IMPORTS},
          'imported function hashes changed')
    reverse = {new: old for old, new in IMPORTS.items()}
    for old, new in IMPORTS.items():
        function = copy.deepcopy(actual[new])
        function['name'] = old
        for block in function['blocks']:
            for op in block['ops']:
                if op['op'] == 'call':
                    require(op['attrs']['function'] in reverse, 'imported call escaped owner closure')
                    op['attrs']['function'] = reverse[op['attrs']['function']]
        exact(function, originals[old], 'imported function body changed')
    return {'source_pins': pins, 'imported_functions': 4, 'functions': 12,
            'composition_sha256': digest(read(root / 'native/history_composition.json')),
            'source_sha256': replay.SOURCE_SHA, 'original_sources': proof['original_sources']}


def build_evidence(root, reference, output, report, summary):
    artifacts = {}
    def artifact(path):
        raw = read(path)
        artifacts[path.relative_to(output).as_posix()] = digest(raw)
        return raw
    owner = report['modules']['history']
    require(owner['builder'] == 'history' and owner['source'] == 'native/history.hepta', 'builder changed')
    bundle_path = relative(output, owner['manifest'])
    bundle_raw = artifact(bundle_path)
    bundle = json.loads(bundle_raw)
    require(digest(bundle_raw) == owner['sha256'] == summary['bundle_sha256'] == bundle_path.parent.name,
            'tested bundle identity changed')
    require(bundle_raw == json_bytes(bundle), 'bundle encoding changed')
    compiler = artifact(output / 'build/bootstrap/B3.image.bin')
    artifact(output / 'build/bootstrap/bootstrap.json')
    require(report['compiler_commit'] == HEPTA_COMMIT and digest(compiler) == report['compiler_image_sha256'],
            'compiler identity changed')
    source = read(root / 'native/history.hepta')
    contract = {'schema': 'hepta.runtime.history-bundle.v1', 'source_sha256': digest(source),
                'proof_sha256': digest(read(root / 'native/history_composition.json')),
                'compiler_commit': HEPTA_COMMIT, 'compiler_sha256': digest(compiler),
                'wide_profile': 'history.v1', 'wide_capacities': [128 << 20, 128 << 20, 256 << 20],
                'fixture_is_complete_wide_domain': False, 'production_activated': False,
                'whole_runtime_replaced': False}
    exact({k: bundle[k] for k in contract}, contract, 'wide bundle contract changed')
    manifest_path = relative(output / 'build', bundle['module'])
    manifest_raw = artifact(manifest_path)
    module = json.loads(manifest_raw)
    require(digest(manifest_raw) == bundle['module_sha256'], 'wide module manifest changed')
    module_contract = {'schema': 'hepta.runtime.native-module.v1',
                       'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'target': 'linux-x86_64',
                       'compiler_commit': HEPTA_COMMIT, 'compiler_sha256': digest(compiler),
                       'source_sha256': digest(source), 'buffer_profile': 'history.v1',
                       'input_capacity': 128 << 20, 'output_capacity': 128 << 20,
                       'workspace_capacity': 256 << 20, 'standalone': None}
    exact({k: module[k] for k in module_contract}, module_contract, 'wide native profile changed')
    for key in ('source', 'image'):
        name = Path(module[key])
        require(not name.is_absolute() and len(name.parts) == 1, 'module child path changed')
        raw = artifact(manifest_path.parent / name)
        require(digest(raw) == module[key + '_sha256'], 'compiled child changed')
        if key == 'source':
            require(raw == source, 'compiled source changed')
        else:
            image = raw
    require(digest(image) == bundle['image_sha256'], 'wide image changed')
    _compiled(output, manifest_path.parent, source, image, compiler, artifacts)
    fixture_path = relative(output / 'build', bundle['fixture'])
    fixture_raw = artifact(fixture_path)
    fixture = json.loads(fixture_raw)
    require(digest(fixture_raw) == bundle['fixture_sha256'], 'static fixture changed')
    profile = [
        {'id': 0, 'name': 'history-hex-fixture', 'flags': 1, 'call_mask': 2,
         'input_capacity': 8 << 20, 'output_capacity': 8 << 20, 'workspace_capacity': 16 << 20,
         'source_sha256': TRANSPORT},
        {'id': 1, 'name': 'history', 'flags': 0, 'call_mask': 0, 'input_capacity': 8 << 20,
         'output_capacity': (1 << 20) + 32, 'workspace_capacity': 8 << 20,
         'source_sha256': digest(source)},
    ]
    exact(fixture['profile'], profile, 'static fixture privilege/capacity profile changed')
    require(fixture['schema'] == 'hepta.runtime.native-composition.v1' and
            fixture['compiler_commit'] == HEPTA_COMMIT and fixture['compiler_sha256'] == digest(compiler)
            and len(fixture['members']) == 2, 'composition identity changed')
    rows = [('packer', reference / 'native/composition_packer.hepta', fixture['packer']),
            ('module_00', reference / 'tests/hia_native/view_cache_hex_transport.hepta', fixture['members'][0]),
            ('module_01', root / 'native/history.hepta', fixture['members'][1])]
    require(digest(read(rows[0][1])) == PACKER and digest(read(rows[1][1])) == TRANSPORT,
            'fixed packer or transport changed')
    images = []
    frame = bytearray(b'HIABND01' + struct.pack('<3Q', 2, 0, 0))
    for index, (stem, original, row) in enumerate(rows):
        require(row['manifest'] == stem + '.json', 'composition member path changed')
        child_raw = artifact(fixture_path.parent / row['manifest'])
        child = json.loads(child_raw)
        child_source = artifact(fixture_path.parent / (stem + '.hepta'))
        child_image = artifact(fixture_path.parent / (stem + '.image.bin'))
        contract = {'schema': 'hepta.runtime.native-module.v1',
                    'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'target': 'linux-x86_64',
                    'compiler_commit': HEPTA_COMMIT, 'compiler_sha256': digest(compiler),
                    'source': stem + '.hepta', 'image': stem + '.image.bin',
                    'input_capacity': 8 << 20, 'output_capacity': 8 << 20,
                    'workspace_capacity': 32 << 20, 'standalone': None,
                    'source_sha256': digest(child_source), 'image_sha256': digest(child_image)}
        exact({k: child[k] for k in contract}, contract, 'static child contract changed')
        require(digest(child_raw) == row['manifest_sha256'] and child_source == read(original)
                and digest(child_source) == row['source_sha256']
                and digest(child_image) == row['image_sha256'], 'static child identity changed')
        compiled = output / 'build/modules' / ('composition-' + digest(child_source)[:24])
        _compiled(output, compiled, child_source, child_image, compiler, artifacts)
        if index:
            images.append(child_image)
            p = profile[index - 1]
            frame.extend(struct.pack('<8Q', len(child_image), p['input_capacity'], p['output_capacity'],
                                     p['workspace_capacity'], p['flags'], p['call_mask'], 0, 0))
            frame.extend(bytes.fromhex(digest(child_source)) + bytes.fromhex(digest(child_image)) + child_image)
    require(images[1] == image, 'static and wide native history owners differ')
    require(fixture['executable'] == 'native-local-read.elf', 'static executable path changed')
    executable = artifact(fixture_path.parent / fixture['executable'])
    layout = embedded_images(executable, profile, images)
    require(fixture['key'] == digest(json_bytes({'compiler': digest(compiler), 'members': profile, 'packer': PACKER}))
            and fixture['frame_sha256'] == digest(frame) and fixture['frame_bytes'] == len(frame)
            and fixture['executable_sha256'] == digest(executable)
            and fixture['inspection'] == inspect_elf(executable), 'native packing/ELF binding changed')
    exact(fixture['packing'], {'owner': 'HIA', 'input_unchanged': True, 'buffer_canaries_unchanged': True,
          'packer_image_sha256': fixture['packer']['image_sha256']}, 'HIA packing receipt changed')
    return {'artifact_sha256': artifacts, 'image_sha256': digest(image),
            'executable_sha256': digest(executable), 'source_profile': profile, 'elf_embedding': layout}


def elf_observations(folder, summary, executable_sha):
    observed = summary['elf_observations']
    require(len(observed) == 4, 'actual static process count changed')
    sessions = {}
    with gzip.open(folder / 'rows.jsonl.gz', 'rb') as rows, \
            gzip.open(folder / 'input.bin.gz', 'rb') as inputs, \
            gzip.open(folder / 'native-output.bin.gz', 'rb') as outputs:
        count = 0
        for line in rows:
            row = json.loads(line)
            count += 1
            require(row['ordinal'] == count, 'original row order changed')
            header = inputs.read(8)
            require(len(header) == 8, 'missing original input frame')
            sid, size = struct.unpack('<II', header)
            require(sid == row['session'] and 64 <= size <= 128 << 20, 'input frame identity changed')
            response = outputs.read(4)
            require(len(response) == 4, 'missing original output frame')
            length = struct.unpack('<I', response)[0]
            require(64 <= length <= 128 << 20, 'output frame identity changed')
            if row['execution'] == 'static-native-elf':
                request, answer = inputs.read(size), outputs.read(length)
                require(len(request) == size and len(answer) == length, 'static frame truncated')
                session = sessions.setdefault(sid, {'input': bytearray(), 'output': bytearray(), 'requests': 0})
                session['input'].extend(request.hex().encode() + b'\n')
                session['output'].extend(f'{length:08x}:'.encode() + answer.hex().encode() + b'\n')
                session['requests'] += 1
            else:
                require(row['execution'] == 'native-image', 'unknown original execution owner')
                for stream, remaining in ((inputs, size), (outputs, length)):
                    while remaining:
                        chunk = stream.read(min(remaining, 1 << 20))
                        require(bool(chunk), 'native frame truncated')
                        remaining -= len(chunk)
        require(count == 6198 and not inputs.read(1) and not outputs.read(1), 'original corpus trailing/truncated')
    require(list(sessions) == [11, 12, 13, 14], 'static session ownership changed')
    require([v['requests'] for v in sessions.values()] == [7, 10, 7, 10], 'static sequence domain changed')
    for observed_row, (sid, session) in zip(observed, sessions.items(), strict=True):
        expected = {'session': sid, 'executable_sha256': executable_sha, 'returncode': 0,
                    'stdin_hex': bytes(session['input']).hex(), 'stdout_hex': bytes(session['output']).hex(),
                    'stderr_hex': '', 'requests': session['requests']}
        exact(observed_row, expected, 'actual static process bytes differ from retained original rows')
    return {'processes': 4, 'requests': 34, 'complete_bytes_bound': True}


def native_evidence(root, output, report, completed, *, reference_root=None):
    reference = root if reference_root is None else reference_root
    check, summary = completed(output, report, 'test_history.py')
    stderr = read(output / 'test_history.py.stderr').decode()
    command = check.get('command', [])
    require(len(command) == 4 and command[1:] == ['-I', '-B', str(root / 'tests/hia_native/test_history.py')]
            and len(re.findall(r'\.\.\. ok\n', stderr)) == 7
            and re.search(r'\nRan 7 tests in [0-9.]+s\n\nOK\n\Z', stderr),
            'actual native invocation did not finish every test group')
    replay = driver(root)
    folder = output / FOLDER
    corpus = replay.checked_corpus(root, reference, folder)
    exact(corpus['report'], summary, 'corpus does not match actual native test stdout')
    source = source_composition(root, reference, Path(report['compiler_checkout']))
    built = build_evidence(root, reference, output, report, summary)
    elf = elf_observations(folder, summary, built['executable_sha256'])
    require(summary['source_sha256'] == source['source_sha256'] and
            summary['source_proof_sha256'] == source['composition_sha256'], 'tested source proof changed')
    return {'status': 'PASS', 'counts': replay.COUNTS, 'captured_native_cases': 6198,
            'native_cases_added_by_replay': 0, 'original_operations': 6167,
            **source, **built, 'static_execution': elf,
            'corpus_sha256': {(folder / name).relative_to(output).as_posix(): digest(read(folder / name))
                              for name in CORPUS_FILES},
            'corpus_metadata_sha256': digest(read(folder / 'native-corpus.json')),
            'streams': {name: {'bytes': value[0], 'sha256': value[1]} for name, value in replay.STREAMS.items()},
            'test_stdout_sha256': check['stdout_sha256'], 'test_stderr_sha256': check['stderr_sha256'],
            'oracle_sources_sha256': {name: digest(read(root / name)) for name in
                ('tests/hia_native/oracle_history.rs', 'tests/hia_native/history_oracle_source.py',
                 'tests/hia_native/compare_history_original.py')},
            'production_activated': False, 'whole_runtime_replaced': False,
            'complete_original_tool_parity': False, 'unbounded_storage_qualified': False,
            'shared_concurrency_qualified': False, 'filesystem_effects_qualified': False}


def qualification_evidence(root, output, report, completed, *, reference_root=None):
    evidence = native_evidence(root, output, report, completed, reference_root=reference_root)
    check, summary = completed(output, report, 'test_history_evidence.py')
    stderr = read(output / 'test_history_evidence.py.stderr').decode()
    expected = {'schema': 'hepta.runtime.history-evidence-tests.v1', 'status': 'PASS', 'test_groups': 4,
                'refusal_controls': 16, 'native_calls_added': 0,
                'test_sha256': digest(read(root / 'tests/hia_native/test_history_evidence.py'))}
    exact(summary, expected, 'actual evidence-control report changed')
    require(check.get('command', [None])[1:] == ['-I', '-B', str(root / 'tests/hia_native/test_history_evidence.py')]
            and len(re.findall(r'\.\.\. ok\n', stderr)) == 4
            and re.search(r'\nRan 4 tests in [0-9.]+s\n\nOK\n\Z', stderr), 'evidence controls incomplete')
    return {**evidence, 'evidence_controls': {**summary, 'stdout_sha256': check['stdout_sha256'],
                                            'stderr_sha256': check['stderr_sha256']}}


def compare_original(root, output, report, rustc, completed, record_check, env):
    evidence = qualification_evidence(root, output, report, completed)
    exact(evidence, report['history_evidence'], 'native history evidence changed before Rust comparison')
    folder = output / FOLDER
    binary = folder / 'original-history.elf'
    result_folder = folder / 'original-replay'
    require(not binary.exists() and not result_folder.exists(), 'original replay output already exists')
    record_check(output, report, name='history-rust-compile', command=[str(rustc), '--edition=2021',
                 '-O', '-C', 'overflow-checks=off', str(root / 'tests/hia_native/oracle_history.rs'),
                 '-o', str(binary)], env=env, timeout=180)
    binary_sha = digest(read(binary))
    row = record_check(output, report, name='history-rust-compare', command=[sys.executable, '-I', '-B',
        str(root / 'tests/hia_native/compare_history_original.py'), '--root', str(root),
        '--reference-root', str(root), '--corpus', str(folder), '--output', str(result_folder),
        '--binary', str(binary)], env=env, timeout=180)
    observed = json.loads(row.stdout)
    require(not row.stderr and observed == object_at(result_folder / 'result.json') and
            observed['status'] == 'PASS' and observed['output_bytes_compared'] == 321300328 and
            observed['executable']['sha256'] == binary_sha == digest(read(binary)) and
            observed['corpus']['native-corpus.json']['sha256'] == evidence['corpus_metadata_sha256'] and
            observed['comparator']['sha256'] == digest(read(root / 'tests/hia_native/compare_history_original.py')),
            'actual original Rust execution did not match native capture')
    exact(qualification_evidence(root, output, report, completed), evidence,
          'native evidence changed during original replay')
    return {**observed, 'compiled_by_qualification_recipe': True, 'native_cases_added_by_replay': 0,
            'complete_original_tool_parity': False}
