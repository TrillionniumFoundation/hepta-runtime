"""Admit native and original filesystem executions from their full records.

This qualifies the fixed Linux filesystem owner. Public SDK, session/cache
wrappers and production replacement remain open. Readers run no HIA or Rust.
"""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import stat
import struct
import sys

FOLDER = 'filesystem-parity'
HELPERS = 'tests/hia_native/filesystem_parity'
SUITES = ('test_filesystem_parity_state.py', 'test_filesystem_parity_build.py', 'test_filesystem_parity_kernel.py')
RECIPE = 'scripts/hia_native_filesystem_parity_reference.py'
THIS = 'scripts/hia_native_filesystem_parity_qualification.py'
ORIGINAL_CHECK = 'filesystem-parity-rust-compare'
PRODUCER_PINS = {'scripts/hia_native_filesystem_parity_reference.py': {'bytes': 9223, 'sha256': 'df68517a95162bb8ad4ecfcd588c1619ac3310874d28fb3e22c13112121a2263'}, 'tests/hia_native/filesystem_parity/qualify_state.py': {'bytes': 14866, 'sha256': '6ecf755df00f121fd7d39f51ba9782036df71c03cd359356b7facb506af4247d'}, 'tests/hia_native/filesystem_parity/qualify_build.py': {'bytes': 6274, 'sha256': '2daab558678f65f5f2b83a120a0dd14b95e4ed25237c81251722647b6e76e1bd'}, 'tests/hia_native/test_filesystem_parity_state.py': {'bytes': 295, 'sha256': '792c90260e867de73d44bf2292c63cfb3ead5732987df931f91a3ac8ee4272bf'}, 'tests/hia_native/test_filesystem_parity_build.py': {'bytes': 292, 'sha256': '130729dd6a4b9c9e73b22fa9aa4fafba2b368ddbb084590af7180860a8aa619a'}, 'tests/hia_native/test_filesystem_parity_kernel.py': {'bytes': 380, 'sha256': '39ece0c1e29ab11c7a2dd126ea95dd09a32d0e365cc5868a18e238cbb4a1ff70'}}
BUILD_REFUSALS = ('complete-source', 'compiler-generation', 'compiler-input', 'compiler-output-tail',
    'compiler-stderr', 'packer-output-tail', 'packed-elf', 'mismatched-actual-stdout',
    'mismatched-complete-receipt', 'false-production-claim', 'production-boolean-type',
    'compile-scope-boolean-type', 'duplicate-manifest-field')
LARGE_PROOF_FIELDS = {'artifact_sha256', 'artifact_bytes', 'normalized_syscalls', 'native_calls', 'effect_completions'}


def need(value, message):
    if not value:
        raise ValueError('filesystem parity qualification: ' + message)


def canonical(value):
    def extra(item):
        if isinstance(item, Path): return str(item)
        if isinstance(item, set): return sorted(item)
        raise TypeError('unexpected canonical object: ' + type(item).__name__)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False, default=extra).encode()


def same(actual, expected, message):
    need(canonical(actual) == canonical(expected), message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('filesystem parity qualification: nonfinite JSON ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def relative(value):
    need(type(value) is str, 'artifact path type')
    path = Path(value)
    need(bool(path.parts) and not path.is_absolute() and '..' not in path.parts
         and path.as_posix() == value, 'artifact path escapes owner')
    return path


def owned(root, name):
    path = Path(root).absolute() / relative(name)
    need(path.resolve(strict=True) == path.absolute(), 'symlink in artifact path: ' + name)
    info = path.lstat()
    # Cargo may publish its regular release output as a hard link. Admission
    # reads and rechecks complete bytes; it never mutates these artifacts.
    need(stat.S_ISREG(info.st_mode), 'artifact is not a regular owned file: ' + name)
    return path


def pin(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(root, name):
    return decode(owned(root, name).read_bytes())


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def add_file(artifacts, output, path, expected=None):
    name = str(Path(path).absolute().relative_to(Path(output).absolute()))
    actual = pin(owned(output, name))
    if expected is not None:
        same(actual, expected, 'changed artifact: ' + name)
    if name in artifacts:
        same(actual, artifacts[name], 'artifact changed during admission: ' + name)
    artifacts[name] = actual
    return actual


def add_tree(artifacts, output, folder):
    need(folder.is_dir() and not folder.is_symlink(), 'missing owned evidence directory')
    for parent, directories, files in os.walk(folder, followlinks=False):
        for name in directories:
            need(not (Path(parent)/name).is_symlink(), 'symlink evidence directory')
        for name in files:
            add_file(artifacts, output, Path(parent)/name)


def artifact_fields(artifacts):
    return {'artifact_sha256': {name: value['sha256'] for name, value in sorted(artifacts.items())},
            'artifact_bytes': {name: value['bytes'] for name, value in sorted(artifacts.items())}}


def check_source(root, report):
    need(bool(PRODUCER_PINS), 'final producer pin set missing')
    strict = load(owned(root, HELPERS+'/strict_native.py'), '_fs_pipeline_strict')
    required = {**strict.NATIVE_FILES,
                **{HELPERS+'/'+name: value for name, value in strict.HELPER_FILES.items()}, **PRODUCER_PINS}
    recipe = load(owned(root, RECIPE), '_fs_pipeline_recipe')
    required.update(recipe.REFERENCE_INPUTS)
    result = {}
    for name, expected in required.items():
        actual = pin(owned(root, name))
        same(actual, expected, 'fixed source changed: ' + name)
        result[name] = actual['sha256']
    for name in (THIS, HELPERS+'/strict_native.py'):
        result[name] = pin(owned(root, name))['sha256']
    for name, digest in result.items():
        same(report['source_sha256'].get(name), digest, 'qualification source seal: ' + name)
    return strict, recipe, result


def module_manifest(output, report):
    module = report['modules']['filesystem_parity']
    same(set(module), {'manifest', 'sha256', 'source', 'builder'}, 'module descriptor fields')
    same(module['source'], 'native/filesystem_parity.hepta', 'module source')
    same(module['builder'], 'filesystem_parity', 'module builder')
    path = owned(output, module['manifest'])
    same(pin(path)['sha256'], module['sha256'], 'sealed bundle manifest')
    return path


def cross_root(output, kind, uid=None):
    need(kind in ('native', 'original'), 'cross-device fixture kind')
    uid = os.getuid() if uid is None else uid
    return Path('/dev/shm') / ('hepta-filesystem-parity-' + str(uid) + '-'
        + sha(os.fsencode(Path(output).absolute()))[:20] + '-' + kind)


def test_commands(root, output, report):
    root, output = Path(root).absolute(), Path(output).absolute()
    manifest = output / relative(report['modules']['filesystem_parity']['manifest'])
    prefix = [sys.executable, '-I', '-B']
    return {
        SUITES[0]: prefix + [str(root/'tests/hia_native'/SUITES[0]), '--runtime', str(root),
            '--manifest', str(manifest.parent/'owner/manifest.json'), '--output', str(output/FOLDER/'state')],
        SUITES[1]: prefix + [str(root/'tests/hia_native'/SUITES[1]), '--source-root', str(root),
            '--manifest', str(manifest), '--output', str(output/FOLDER/'build-controls')],
        SUITES[2]: prefix + [str(root/'tests/hia_native'/SUITES[2]), '--manifest', str(manifest),
            '--output', str(output/FOLDER/'native/captures-v1'), '--cross-root', str(cross_root(output, 'native'))],
    }


def completed(output, report, name, command, phase, callback, artifacts):
    check, summary = callback(output, report, name)
    same(check.get('command'), command, 'actual suite command: ' + name)
    same(check.get('phase'), phase, 'actual suite phase: ' + name)
    need(type(check.get('exit_code')) is int and check['exit_code'] == 0
         and check.get('timed_out') is False and 'start_error' not in check, 'suite did not complete: ' + name)
    same(check.get('timeout_seconds'), 180, 'suite deadline: ' + name)
    elapsed = check.get('elapsed_seconds')
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 180,
         'suite elapsed bound: ' + name)
    for stream in ('stdout', 'stderr'):
        add_file(artifacts, output, output/(name+'.'+stream),
                 {'bytes': check[stream+'_bytes'], 'sha256': check[stream+'_sha256']})
    same(decode(owned(output, name+'.stdout').read_bytes()), summary, 'complete suite stdout: ' + name)
    need(not owned(output, name+'.stderr').read_bytes(), 'unexpected suite stderr: ' + name)
    same(check.get('summary'), summary, 'recorded suite summary: ' + name)
    need(summary.get('status') == 'PASS', 'suite did not report PASS: ' + name)
    return summary


def private_state(output, manifest, summary, artifacts):
    folder = output/FOLDER/'state'
    same(read_json(folder, 'RESULT.json'), summary, 'private state result')
    for name, expected in {'groups': 11, 'actual_native_calls': 338,
        'original_semantic_cases': 0, 'actual_filesystem_effects': 0,
        'synthetic_private_completion_controls': True,
        'public_filesystem_handlers_complete': False, 'whole_runtime_replaced': False}.items():
        same(summary.get(name), expected, 'private state ' + name)
    same(summary['manifest_sha256'], pin(manifest.parent/'owner/manifest.json')['sha256'], 'private state module')
    same(summary['source_sha256'], '1afb3046366a16a346a21345f3710efefdd312a1f9b35878bd7aec5118ddd454', 'private state owner')
    for name in ('calls.bin.gz', 'calls.jsonl'):
        add_file(artifacts, output, folder/name, summary['captures'][name])
    raw = owned(folder, 'calls.jsonl').read_bytes()
    need(raw.endswith(b'\n'), 'incomplete private call index')
    rows = [decode(line) for line in raw.split(b'\n')[:-1]]
    same(len(rows), 338, 'complete private call count')
    groups = set()
    uncompressed = hashlib.sha256()
    with gzip.open(owned(folder, 'calls.bin.gz'), 'rb') as stream:
        for row in rows:
            start = stream.tell()
            same(row['stream_offset'], start, 'private stream offset')
            spans = []
            for _ in range(5):
                header = stream.read(8)
                need(len(header) == 8, 'truncated private span length')
                length, = struct.unpack('<Q', header)
                need(length <= 1 << 20, 'private state span outside executed domain')
                data = stream.read(length)
                need(len(data) == length, 'truncated private span')
                uncompressed.update(header); uncompressed.update(data); spans.append(data)
            wire, before, output_before, after_output, after = spans
            same(row['stream_bytes'], stream.tell()-start, 'private stream extent')
            for name, actual in {'input_bytes': len(wire), 'input_sha256': sha(wire),
                    'workspace_capacity': len(before), 'output_capacity': len(output_before),
                    'before_sha256': sha(before), 'after_sha256': sha(after),
                    'output_sha256': sha(after_output)}.items():
                same(row[name], actual, 'private complete span ' + name)
            need(len(after) == len(before) and len(after_output) == len(output_before)
                 and output_before == b'\xa5'*len(output_before), 'private span capacities/initial bytes')
            need(type(row['native_code']) is int and 0 <= row['native_code'] < 1 << 32, 'private result code')
            if row['expected_code'] is not None:
                same(row['native_code'], row['expected_code'], 'actual private expected result')
            if row['native_code'] in (0xffffffff, 0xfffffffe, 0xfffffff9):
                need(after == before and after_output == output_before,
                     'private refusal changed buffers')
            need(type(row['group']) is str and type(row['name']) is str, 'private group/name type')
            # Repeated labels are intentional in the fixed private controls;
            # the checked, contiguous stream offset identifies each call.
            groups.add(row['group'])
        need(stream.read(1) == b'', 'unconsumed private native stream')
    same(sorted(groups), summary['group_names'], 'private group coverage')
    add_tree(artifacts, output, folder)
    return {'groups': 11, 'actual_native_calls': 338, 'actual_filesystem_effects': 0,
            'synthetic_private_completion_controls': True, 'complete_call_stream_sha256': uncompressed.hexdigest()}


def build_controls(output, manifest, root, summary, artifacts):
    folder = output/FOLDER/'build-controls'
    same(read_json(folder, 'RESULT.json'), summary, 'build control result')
    for name, expected in {'refusals': 13, 'positive_reads': 16, 'new_native_calls': 0,
        'new_rust_processes': 0, 'relocated_without_reading_producer_paths': True,
        'source_files_unchanged': 9, 'build_files_unchanged': 33,
        'public_filesystem_handlers_complete': False, 'whole_runtime_replaced': False}.items():
        same(summary.get(name), expected, 'build controls ' + name)
    builder = load(owned(root, 'scripts/hia_native_filesystem_parity_build.py'), '_fs_pipeline_build')
    actual = builder.inspect_bundle(manifest, source_root=root)
    same(read_json(folder, 'EVIDENCE.json'), actual, 'full build evidence')
    controls = read_json(folder, 'CONTROLS.json')
    same([row['name'] for row in controls], list(BUILD_REFUSALS), 'all build refusals')
    for row in controls:
        need(row['rejected'] in ('ValueError', 'OSError', 'KeyError', 'TypeError')
             and type(row['message']) is str and row['message'], 'unexecuted build refusal')
    same(builder.inspect_bundle(folder/'relocated-bundle/manifest.json',
                                source_root=folder/'relocated-source'), actual, 'retained relocated build')
    for name, descriptor in (('EVIDENCE.json', summary['evidence']), ('CONTROLS.json', summary['controls'])):
        add_file(artifacts, output, folder/name, descriptor)
    add_tree(artifacts, output, folder)
    return {'refusals': 13, 'positive_reads': 16, 'source_files_unchanged': 9,
            'build_files_unchanged': 33, 'new_native_calls': 0, 'new_rust_processes': 0}


def mapped_artifacts(proof, output, namespaces, artifacts):
    for name, digest in proof['artifact_sha256'].items():
        namespace, rest = name.split('/', 1)
        if namespace in namespaces:
            add_file(artifacts, output, namespaces[namespace]/relative(rest),
                     {'bytes': proof['artifact_bytes'][name], 'sha256': digest})


def native_evidence(root, output, report, completed_test_summary):
    root, output = Path(root).absolute(), Path(output).absolute()
    strict, _, source_pins = check_source(root, report)
    manifest = module_manifest(output, report)
    capture = output/FOLDER/'native/captures-v1'
    proof = strict.native_evidence(root, manifest, capture)
    source = read_json(capture, 'SOURCE.json')
    old_capture = Path(source['fixture_home'])
    old_output = old_capture.parents[2]
    same(old_capture, old_output/FOLDER/'native/captures-v1', 'native capture owner layout')
    same(source['bundle_manifest'], str(old_output/relative(report['modules']['filesystem_parity']['manifest'])),
         'actual native bundle command')
    same(source['cross_root'], str(cross_root(old_output, 'native', source['uid'])), 'native cross-device owner')
    commands = test_commands(Path(source['source_root']), old_output, report)
    commands[SUITES[2]][-1] = source['cross_root']
    artifacts = {}
    summaries = {name: completed(output, report, name, commands[name], 'native_components',
                                 completed_test_summary, artifacts) for name in SUITES}
    same(summaries[SUITES[2]], read_json(capture, 'NATIVE.json'), 'native full capture stdout')
    state = private_state(output, manifest, summaries[SUITES[0]], artifacts)
    controls = build_controls(output, manifest, root, summaries[SUITES[1]], artifacts)
    mapped_artifacts(proof, output, {'bundle': manifest.parent, 'native': capture}, artifacts)
    result = {key: value for key, value in proof.items() if key not in LARGE_PROOF_FIELDS}
    result.update(schema='hepta.runtime.filesystem-parity-native-qualification.v1',
        complete_native_evidence_sha256=sha(canonical(proof)), source_sha256=source_pins,
        private_state_controls=state, build_evidence_controls=controls,
        complete_suite_names=list(SUITES), retirement_receipt_included=False,
        production_activated=False, old_stack_removal_qualified=False, **artifact_fields(artifacts))
    return result


def fixture_plan(root, capture):
    source = read_json(capture, 'SOURCE.json')
    generator = load(owned(root, HELPERS+'/cases.py'), '_fs_pipeline_fixture_cases')
    groups = generator.groups(source['fixture_home'], source['cross_root'])
    old = Path(source['fixture_home'])
    plans = []
    for group, value in groups.items():
        for raw in value['roots']:
            path = Path(os.fsdecode(raw))
            if path == Path(source['cross_root'])/'files':
                name = None
            else:
                name = str(path.relative_to(old))
                same(name, group+'/files', 'private fixture owner')
            plans.append({'group': group, 'recorded_root_hex': raw.hex(), 'relative_path': name})
    return source, groups, plans


def retirement(root, output, capture, proof, kind, *, create):
    source, groups, plans = fixture_plan(root, capture)
    old_capture = Path(source['fixture_home'])
    old_output = old_capture.parents[2]
    same(old_capture, old_output/FOLDER/kind/'captures-v1', 'retirement fixture layout')
    uid = source['uid'] if kind == 'native' else read_json(output/FOLDER/'native/captures-v1', 'SOURCE.json')['uid']
    same(source['cross_root'], str(cross_root(old_output, kind, uid)), 'retirement cross-device owner')
    receipt_path = output/FOLDER/(kind+'-fixture-retirement.json')
    expected = {'schema': 'hepta.runtime.filesystem-parity-fixture-retirement.v1',
        'status': 'PASS', 'kind': kind, 'qualification_sha256': sha(canonical(proof)),
        'fixture_roots': plans, 'retained_full_snapshots': 267,
        'all_final_trees_verified_before_deletion': True,
        'all_owned_fixture_roots_absent': True, 'retained_evidence_unchanged': True,
        'cross_device_parent_removed': True,
        'new_native_calls': 0, 'new_rust_processes': 0, 'live_fixture_dependencies': [],
        'public_filesystem_handlers_complete': False, 'whole_runtime_replaced': False}
    if receipt_path.exists():
        same(read_json(receipt_path.parent, receipt_path.name), expected, 'fixture retirement receipt')
    else:
        need(create, 'fixture retirement receipt missing')
        same(capture, old_capture, 'retirement cannot operate on a relocated producer path')
        same(uid, os.getuid(), 'fixture owner uid')
        need(os.getuid() != 0, 'fixture retirement requires unprivileged producer')
        support = load(owned(root, HELPERS+'/replay_original.py'), '_fs_pipeline_retire_support')
        cross_parent = Path(source['cross_root'])
        need(cross_parent.resolve(strict=True) == cross_parent.absolute(), 'cross-device owner symlink')
        cross_info = cross_parent.lstat()
        need(stat.S_ISDIR(cross_info.st_mode) and cross_info.st_uid == uid
             and sorted(os.listdir(cross_parent)) == ['files'], 'cross-device parent changed owner/contents')
        roots = []
        for name, group in groups.items():
            for raw in group['roots']:
                path = Path(os.fsdecode(raw))
                need(path.resolve(strict=True) == path.absolute(), 'fixture root/ancestor symlink')
                info = path.lstat()
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid, 'fixture root changed owner/type')
                roots.append(path)
            same(support.snapshot(group['roots'], capture), read_json(capture, name+'/restored-state.json'),
                 'live final fixture tree differs: ' + name)
        need(len(roots) == len(set(roots)), 'duplicate cleanup root')
        for path in roots:
            shutil.rmtree(path)
        for path in roots:
            need(not os.path.lexists(path), 'fixture root remains')
        cross_parent.rmdir()
        for name, digest in proof['artifact_sha256'].items():
            same(pin(owned(output, name))['sha256'], digest, 'evidence changed during fixture retirement')
        write_new(receipt_path, expected)
    for plan in plans:
        if plan['relative_path'] is not None:
            need(not os.path.lexists(capture/relative(plan['relative_path'])), 'live fixture copied into evidence')
    if capture == old_capture:
        need(not os.path.lexists(source['cross_root']), 'local cross-device fixture remains')
    artifacts = {}
    add_file(artifacts, output, receipt_path)
    return {**expected, **artifact_fields(artifacts)}


def retire_fixtures(root, output, report, completed_test_summary, create=True):
    root, output = Path(root).absolute(), Path(output).absolute()
    proof = native_evidence(root, output, report, completed_test_summary)
    return retirement(root, output, output/FOLDER/'native/captures-v1', proof, 'native', create=create)


def original_command(root, output):
    return [sys.executable, '-I', '-B', str(root/RECIPE), '--source-root', str(root),
        '--native-capture', str(output/FOLDER/'native/captures-v1'), '--output', str(output/FOLDER/'original'),
        '--cross-root', str(cross_root(output, 'original'))]


def original_evidence(root, output, report, rustc, completed_test_summary):
    root, output = Path(root).absolute(), Path(output).absolute()
    strict, recipe, source_pins = check_source(root, report)
    manifest = module_manifest(output, report)
    native = native_evidence(root, output, report, completed_test_summary)
    same(report.get('filesystem_parity_evidence'), native, 'sealed native phase changed')
    retired = retirement(root, output, output/FOLDER/'native/captures-v1', native, 'native', create=False)
    same(report.get('filesystem_parity_fixture_retirement'), retired, 'sealed native retirement changed')
    need('release: 1.95.0' in report['rust_compiler']['version'].splitlines(), 'fixed original Rust release')
    same(str(rustc), report['rust_compiler']['invocation_path'], 'original compiler invocation identity')
    original = output/FOLDER/'original'
    source = read_json(output/FOLDER/'native/captures-v1', 'SOURCE.json')
    old_output = Path(source['fixture_home']).parents[2]
    old_root = Path(source['source_root'])
    old_original = old_output/FOLDER/'original'
    command = original_command(old_root, old_output)
    command[-1] = str(cross_root(old_output, 'original', source['uid']))
    artifacts = {}
    result = completed(output, report, ORIGINAL_CHECK, command, 'original_rust_comparison',
                       completed_test_summary, artifacts)
    same(read_json(original, 'RESULT.json'), result, 'complete original recipe result')
    for name, expected in {'schema': 'hepta.runtime.filesystem-parity-original-recipe.v2',
        'source_manifest': None, 'required_source_files': recipe.REFERENCE_INPUTS,
        'source_files_unchanged': True, 'native_captured_before_original': True,
        'actual_python_processes': 3, 'actual_rust_processes': 11, 'fixed_rust_version': '1.95.0',
        'fresh_locked_original_builds': 1, 'original_cases': 123, 'new_native_calls': 0,
        'original_comparison_pending': True, 'public_filesystem_handlers_complete': False,
        'whole_runtime_replaced': False}.items():
        same(result.get(name), expected, 'original recipe ' + name)
    same(result['recipe'], {'path': str(old_root/RECIPE), **pin(owned(root, RECIPE))}, 'original recipe bytes')
    same(result['native_capture'], {'path': str(old_output/FOLDER/'native/captures-v1/NATIVE.json'),
         **pin(output/FOLDER/'native/captures-v1/NATIVE.json')}, 'native input bound before original')
    processes = read_json(original, 'processes.json')
    expected_children = [
        ('fresh-original-build', [sys.executable, '-B', str(old_original/'build_original_v2.py'),
            '--source', str(old_original/'source'), '--output', str(old_original/'build')]),
        ('original-capture', [sys.executable, '-B', str(old_original/'replay_original.py'),
            '--build', str(old_original/'build'), '--cases', str(old_original/'cases.py'),
            '--output', str(old_original/'captures-v1'), '--cross-root', command[-1]]),
        ('original-admission', [sys.executable, '-B', str(old_root/HELPERS/'strict_reference.py'),
            '--reference', str(old_original), '--capture', str(old_original/'captures-v1'),
            '--output', str(old_original/'ORIGINAL-EVIDENCE.json')])]
    same(len(processes), len(expected_children), 'original child count')
    summaries = []
    for row, (name, child_command) in zip(processes, expected_children):
        same(row['name'], name, 'original child name')
        strict.q.process_gate(row, child_command, str(old_original))
        for stream in ('stdout', 'stderr'):
            descriptor = row[stream]
            same(descriptor['path'], name+'.'+stream, 'original child stream owner')
            add_file(artifacts, output, original/descriptor['path'],
                     {key: descriptor[key] for key in ('bytes', 'sha256')})
        need(not owned(original, name+'.stderr').read_bytes(), 'original child stderr')
        summaries.append(read_json(original, name+'.stdout'))
    for name, value in zip(('original_build', 'original_capture', 'original_evidence_summary'), summaries):
        same(result[name], value, 'complete original child summary: ' + name)
    copied = {'source/'+name.removeprefix(HELPERS+'/oracle/'): value
              for name, value in recipe.REFERENCE_INPUTS.items() if name.startswith(HELPERS+'/oracle/')}
    copied.update({target: recipe.REFERENCE_INPUTS[HELPERS+'/'+name] for name, target in
        (('build_original.py', 'build_original_v2.py'), ('cases.py', 'cases.py'), ('replay_original.py', 'replay_original.py'))})
    same(result['original_source_files'], copied, 'complete copied original source closure')
    for name, expected in result['original_source_files'].items():
        add_file(artifacts, output, original/relative(name), expected)
    original_proof = strict.q.reference_evidence(original, original/'captures-v1')
    build_processes = read_json(original, 'build/processes.json')
    same(build_processes[0]['command'][0], str(rustc), 'actual original compiler invocation')
    for row in build_processes:
        same(row['controlled_env']['RUSTC'], str(rustc), 'actual original build compiler selection')
    same(owned(original, 'build/rustc-version.stdout').read_bytes().decode(),
         report['rust_compiler']['version'], 'complete actual original compiler version')
    same(read_json(original, 'ORIGINAL-EVIDENCE.json'), original_proof, 'retained original admission')
    same(result['original_evidence_summary'], {key: value for key, value in original_proof.items()
        if key not in ('artifact_sha256', 'artifact_bytes', 'normalized_syscalls')}, 'full original proof summary')
    same(result['original_build'], read_json(original, 'build/RESULT.json'), 'actual fresh original build')
    same(result['original_capture'], read_json(original, 'captures-v1/ORIGINAL.json'), 'actual original replay')
    same(result['original_evidence']['path'], 'ORIGINAL-EVIDENCE.json', 'original proof artifact owner')
    add_file(artifacts, output, original/'ORIGINAL-EVIDENCE.json',
             {key: result['original_evidence'][key] for key in ('bytes', 'sha256')})
    for name in ('RESULT.json', 'processes.json', 'remote-process.json'):
        add_file(artifacts, output, original/name)
    proof = strict.native_evidence(root, manifest, output/FOLDER/'native/captures-v1', original)
    mapped_artifacts(proof, output, {'bundle': manifest.parent, 'native': output/FOLDER/'native/captures-v1',
                                    'original': original}, artifacts)
    result = {key: value for key, value in proof.items() if key not in LARGE_PROOF_FIELDS}
    result.update(schema='hepta.runtime.filesystem-parity-original-qualification.v1',
        complete_comparison_evidence_sha256=sha(canonical(proof)), source_sha256=source_pins,
        original_comparison_pending=False, production_activated=False, old_stack_removal_qualified=False,
        **artifact_fields(artifacts))
    return result


def retained_original(root, output, report, rustc, completed_test_summary):
    root, output = Path(root).absolute(), Path(output).absolute()
    proof = original_evidence(root, output, report, rustc, completed_test_summary)
    retired = retirement(root, output, output/FOLDER/'original/captures-v1', proof, 'original', create=False)
    return {**proof, 'fixture_retirement': retired,
            'artifact_sha256': {**proof['artifact_sha256'], **retired['artifact_sha256']},
            'artifact_bytes': {**proof['artifact_bytes'], **retired['artifact_bytes']}}


def compare_original(root, output, report, rustc, record_check, completed_test_summary):
    root, output = Path(root).absolute(), Path(output).absolute()
    native = native_evidence(root, output, report, completed_test_summary)
    same(report.get('filesystem_parity_evidence'), native, 'native phase seal before original execution')
    retire_fixtures(root, output, report, completed_test_summary, create=False)
    source = read_json(output/FOLDER/'native/captures-v1', 'SOURCE.json')
    same(source['source_root'], str(root), 'new original execution requires the native source origin')
    same(source['fixture_home'], str(output/FOLDER/'native/captures-v1'), 'new original execution requires the native output origin')
    env = {key: value for key, value in os.environ.items() if not key.startswith('HIA_')}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    record_check(output, report, name=ORIGINAL_CHECK, command=original_command(root, output), timeout=180, env=env)
    proof = original_evidence(root, output, report, rustc, completed_test_summary)
    retirement(root, output, output/FOLDER/'original/captures-v1', proof, 'original', create=True)
    return retained_original(root, output, report, rustc, completed_test_summary)
