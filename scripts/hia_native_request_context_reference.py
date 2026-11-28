"""Fresh original Rust/Tokio comparisons and complete retained-byte admission."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
from types import SimpleNamespace

from hia_native_request_context_qualification import (CONTEXT_FOLDER, RESPONSE_FOLDER,
    decode, owned, qualification_evidence, sha)

ORACLE = 'tests/hia_native/request_context_oracle'
FOLDER = 'request-context-rust-reference'
SOURCE_FILES = ('Cargo.toml', 'Cargo.lock', 'src/main.rs', 'source_manifest.json',
                'cases.py', 'verify_sources.py', 'replay_original.py', 'run.py')
CHECKS = ('request-context-rust-compile', 'request-context-rust-compare', 'response-hints-rust-compare')
BUILD_VARIABLES = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET',
                   'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')
CONTEXT_COMPARISON = {'sessions': 18, 'compared_rows': 6595, 'compared_response_bytes': 13062060,
    'every_response_byte_equal': True, 'semantic_rows': 6595, 'original_accessor_rows': 5701,
    'private_peek_observations': 272, 'lifecycle_adapter_rows': 622,
    'native_boundary_rows_without_rust_semantics': 58}


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def oracle(root):
    # Give this runner its own package namespace. Other reference harnesses may
    # also have files named cases.py or run.py in the same qualifier process.
    name = '_hia_request_context_original'
    path = root / ORACLE
    spec = importlib.util.spec_from_file_location(name, path / 'run.py', submodule_search_locations=[str(path)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source_inputs(root):
    paths = {ORACLE + '/' + name for name in SOURCE_FILES}
    paths.update(decode((root / ORACLE / 'source_manifest.json').read_bytes())['files'])
    paths.update(('scripts/hia_native_request_context_reference.py',
                  'scripts/hia_native_request_context_qualification.py'))
    return {name: file_sha(root / name) for name in sorted(paths)}


def commands(output, cargo):
    folder = output / FOLDER
    binary = folder / 'cargo-target/debug/hepta-request-context-original-oracle'
    return {
        CHECKS[0]: ([cargo, 'build', '--locked', '--manifest-path', str(folder / 'crate/Cargo.toml'),
                    '--target-dir', str(folder / 'cargo-target')], 180, 'build'),
        CHECKS[1]: ([str(binary)], 120, 'combined-original'),
        CHECKS[2]: ([str(binary), '--append-corpus', str(folder / 'response-input.bin'),
                    str(folder / 'response-original.bin')], 60, 'response-original'),
    }


def artifact_names():
    names = ['RESULT.json', 'crate/Cargo.toml', 'crate/Cargo.lock', 'crate/src/main.rs',
        'crate/fixtures/original_request_ctx.rs', 'crate/fixtures/original_append_hints.rs', 'crate/fixtures/original_view_cache.rs',
        'cargo-target/debug/hepta-request-context-original-oracle', 'original-controls.jsonl', 'context-input.jsonl',
        'combined-input.jsonl', 'native-boundaries-not-a-rust-domain.json', 'original-controls.stdout', 'context-original.stdout',
        'response-input.bin', 'response-original.bin', 'original-to-native/RESULT.json', 'original-to-native/native-output.jsonl.gz']
    names += [prefix + '.' + suffix for prefix in ('build', 'combined-original', 'response-original')
              for suffix in ('stdout', 'stderr')]
    return ([FOLDER + '/' + name for name in names]
            + [name + '.' + suffix for name in CHECKS for suffix in ('stdout', 'stderr')])


def process_receipts(output, report, build):
    receipts = {}
    for name, (command, timeout, duplicate) in commands(output, build['cargo']).items():
        rows = [row for row in report['checks'] if row.get('name') == name]
        if len(rows) != 1:
            raise ValueError('original request-context process is missing or duplicated')
        row = rows[0]
        if (row.get('command') != command or type(row.get('exit_code')) is not int or row['exit_code'] != 0
                or row.get('timed_out') is not False or row.get('start_error')
                or type(row.get('timeout_seconds')) is not int or row['timeout_seconds'] != timeout
                or type(row.get('elapsed_seconds')) not in (int, float)
                or not math.isfinite(row['elapsed_seconds']) or row['elapsed_seconds'] < 0):
            raise ValueError('original request-context process did not complete its fixed invocation')
        for suffix in ('stdout', 'stderr'):
            raw = owned(output, name + '.' + suffix).read_bytes()
            if (type(row.get(suffix + '_bytes')) is not int or row[suffix + '_bytes'] != len(raw)
                    or row.get(suffix + '_sha256') != sha(raw)
                    or raw != owned(output, FOLDER + '/' + duplicate + '.' + suffix).read_bytes()):
                raise ValueError('original request-context raw process stream changed')
            receipts[name + '.' + suffix] = sha(raw)
        stdin = owned(output, FOLDER + '/combined-input.jsonl').read_bytes() if name == CHECKS[1] else b''
        if (type(row.get('stdin_bytes')) is not int or row['stdin_bytes'] != len(stdin)
                or row.get('stdin_sha256') != sha(stdin)):
            raise ValueError('original request-context complete input receipt differs')
    return receipts


def check_bundle(root, output, report, completed):
    bundle = report.get('request_context_reference')
    if not isinstance(bundle, dict) or bundle.get('schema') != 'hepta.runtime.request-context-reference.v1':
        raise ValueError('fresh request-context original reference is missing')
    if bundle.get('source_sha256') != source_inputs(root):
        raise ValueError('original request-context source inputs changed')
    if set(bundle['artifact_sha256']) != set(artifact_names()):
        raise ValueError('original request-context artifact inventory differs')
    for relative, expected in bundle['artifact_sha256'].items():
        if file_sha(owned(output, relative)) != expected:
            raise ValueError('original request-context retained artifact changed')
    build = bundle['build']
    if (build['executable'] != FOLDER + '/cargo-target/debug/hepta-request-context-original-oracle'
            or file_sha(owned(output, build['executable'])) != build['executable_sha256']
            or file_sha(Path(build['cargo']).resolve(strict=True)) != build['cargo_sha256']
            or file_sha(Path(build['rustc']).resolve(strict=True)) != build['rustc_sha256']
            or build.get('build_environment_policy') != list(BUILD_VARIABLES)
            or build.get('ignored_inherited_build_variables') != [
                name for name in BUILD_VARIABLES if name in build.get('ignored_inherited_build_variables', [])]):
        raise ValueError('fresh original Cargo build or executable custody differs')
    processes = process_receipts(output, report, build)
    if any(bundle['artifact_sha256'].get(name) != digest for name, digest in processes.items()):
        raise ValueError('original request-context process inventory differs')
    result = decode(owned(output, FOLDER + '/RESULT.json').read_bytes())
    if result != bundle['result']:
        raise ValueError('original request-context comparison report changed')
    source_check = {'current_frozen_original_files_match': True, 'original_function_bodies_unchanged': True,
        'source_commit': '2173a00ec314ebc0c5ada21e4cb60d8efdccb99a', 'original_git_history_required': False,
        'original_dependency_lock_match': True, 'registry_dependency_count': 14}
    if (result.get('schema') != 'hepta.runtime.request-context.fresh-original-replay.v1'
            or result.get('status') != 'PASS' or result.get('source_check') != source_check
            or result.get('fresh_locked_build') is not True or result.get('original_dependency_lock_match') is not True
            or result.get('top_level_subprocesses') != 3
            or result.get('rust_executable_sha256') != build['executable_sha256']
            or result.get('driver_sha256') != file_sha(root / ORACLE / 'src/main.rs')
            or result.get('cargo_lock_sha256') != file_sha(root / ORACLE / 'Cargo.lock')
            or any(result.get(key) is not False for key in (
                'native_scheduler_qualified', 'unbounded_api_equivalence_proved', 'production_cutover_qualified'))):
        raise ValueError('original request-context scope or completed build differs')
    runner = oracle(root)
    folder = output / FOLDER
    # Compare the materialized sources to their current immutable source pins.
    for name in ('Cargo.toml', 'Cargo.lock', 'src/main.rs'):
        if (folder / 'crate' / name).read_bytes() != (root / ORACLE / name).read_bytes():
            raise ValueError('original request-context generated crate input differs')
    original = decode((root / ORACLE / 'source_manifest.json').read_bytes())
    for name, pin in (
        ('original_request_ctx.rs', original['files']['src/mcp/request_ctx.rs']),
        ('original_append_hints.rs', original['extractions']['append_hints']),
        ('original_view_cache.rs', original['extractions']['ViewCache']),
    ):
        raw = owned(output, FOLDER + '/crate/fixtures/' + name).read_bytes()
        if len(raw) != pin['bytes'] or sha(raw) != pin['sha256']:
            raise ValueError('original Rust function body changed')
    context_raw = gzip.decompress(owned(output, CONTEXT_FOLDER + '/native-events.jsonl.gz').read_bytes())
    groups, boundaries = {}, []
    import base64
    for line in context_raw.splitlines():
        row = decode(line)
        if row['classification'] == 'independent-model-native-state':
            groups.setdefault(row['session'], []).append((base64.b64decode(row['input_base64'], validate=True),
                base64.b64decode(row['output_base64'], validate=True), row['ordinal']))
        else:
            boundaries.append(row)
    if decode(owned(output, FOLDER + '/native-boundaries-not-a-rust-domain.json').read_bytes()) != boundaries:
        raise ValueError('native boundary refusals were changed or promoted to original semantics')
    context = runner.compare_context(folder / 'context-original.stdout', groups)
    if (context != {key: CONTEXT_COMPARISON[key] for key in context}
            or result['native_context_to_original'] != CONTEXT_COMPARISON
            or result['native_context_corpus_sha256'] != file_sha(output / CONTEXT_FOLDER / 'native-events.jsonl.gz')):
        raise ValueError('complete original request-context response bytes differ')
    controls = runner.cases()
    expected_controls = ''.join(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n' for row in controls).encode()
    if owned(output, FOLDER + '/original-controls.jsonl').read_bytes() != expected_controls:
        raise ValueError('original request-context scenario input changed')
    expected_context = ''.join(json.dumps({'op': 'trace', 'id': session,
        'events': [runner.event_for(row[0]) for row in rows]}, ensure_ascii=False, separators=(',', ':')) + '\n'
        for session, rows in groups.items()).encode()
    if (owned(output, FOLDER + '/context-input.jsonl').read_bytes() != expected_context
            or owned(output, FOLDER + '/combined-input.jsonl').read_bytes() != expected_controls + expected_context):
        raise ValueError('original request-context native corpus framing changed')
    original_controls = owned(output, FOLDER + '/original-controls.stdout').read_bytes()
    actual_context = owned(output, FOLDER + '/context-original.stdout').read_bytes()
    if (len(original_controls.splitlines()) != len(controls)
            or original_controls + actual_context != owned(output, FOLDER + '/combined-original.stdout').read_bytes()):
        raise ValueError('original request-context stdout partition changed')
    scenarios = decode(original_controls.splitlines()[0])
    if (scenarios != result['tokio_scenarios'] or scenarios.get('ok') is not True
            or scenarios.get('case_count') != 13 or len(scenarios.get('cases', [])) != 13
            or len({row['case'] for row in scenarios['cases']}) != 13
            or any(row.get('ok') is not True for row in scenarios['cases'])):
        raise ValueError('actual original Tokio scenarios did not complete')
    response = runner.compare_response(output / RESPONSE_FOLDER, folder / 'response-original.bin')
    native_response = decode(owned(output, RESPONSE_FOLDER + '/native-corpus.json').read_bytes())
    if (response != result['native_response_to_original'] or response['cases'] != 553
            or response['framed_bytes'] != 33998849
            or response['output_sha256'] != native_response['corpus']['native-output.bin.gz']['raw_sha256']
            or result['native_response_input_sha256'] != file_sha(output / RESPONSE_FOLDER / 'input.bin.gz')
            or result['native_response_output_sha256'] != file_sha(output / RESPONSE_FOLDER / 'native-output.bin.gz')
            or (folder / 'response-input.bin').read_bytes() != gzip.decompress((output / RESPONSE_FOLDER / 'input.bin.gz').read_bytes())):
        raise ValueError('complete original append_hints response bytes differ')
    extra = decode(owned(output, FOLDER + '/original-to-native/RESULT.json').read_bytes())
    if (extra != result['original_to_native_extra'] or extra.get('ok') is not True
            or any(extra.get(key) != value for key, value in {
                'traces': 68, 'calls': 7489, 'expected_bytes': 547471, 'matched_bytes': 547471}.items())
            or extra.get('native_scheduler_executed') is not False
            or extra.get('production_cutover_qualified') is not False
            or extra['manifest_sha256'] != report['modules']['request_context']['sha256']
            or extra['original_sha256'] != sha(original_controls)
            or extra['native_output_archive_sha256'] != file_sha(folder / 'original-to-native/native-output.jsonl.gz')):
        raise ValueError('separate original-to-native differential evidence differs')
    expected_rows = []
    for line in original_controls.splitlines():
        row = decode(line)
        if row.get('schema') == 'hepta.runtime.request-context.original-trace.v1':
            expected_rows.extend({'trace': row['id'], 'index': step['index'], 'operation': step['operation'],
                'input_hex': step['input_hex'], 'output_hex': step['output_hex']} for step in row['steps'])
    with gzip.open(folder / 'original-to-native/native-output.jsonl.gz', 'rb') as stream:
        actual_rows = [decode(line) for line in stream]
    if actual_rows != expected_rows or len(actual_rows) != 7489:
        raise ValueError('separate native differential lost original ordered bytes')
    if qualification_evidence(root, output, report, completed) != report['request_context_evidence']:
        raise ValueError('native request-context captures changed during original replay')
    return bundle


def compare_original(root, output, report, rustc, cargo, component, *, completed, record_check, environment):
    if component not in ('request_context', 'response_hints'):
        raise ValueError('unknown original request-context reference component')
    if 'request_context_reference' not in report:
        if qualification_evidence(root, output, report, completed) != report['request_context_evidence']:
            raise ValueError('native request-context evidence changed before original replay')
        env = environment()
        ignored = [name for name in BUILD_VARIABLES if name in env]
        for name in BUILD_VARIABLES:
            env.pop(name, None)
        env['RUSTC'] = str(rustc)
        source_pins = source_inputs(root)
        invoked = []
        def capture(**kwargs):
            name = kwargs['name']
            if name != CHECKS[len(invoked)]:
                raise ValueError('original request-context process order differs')
            expected_command, expected_timeout, _ = commands(output, str(cargo))[name]
            if kwargs['command'] != expected_command or kwargs['timeout'] != expected_timeout:
                raise ValueError('unexpected original request-context process')
            result = record_check(output, report, **kwargs)
            stdin = kwargs.get('input_bytes') or b''
            report['checks'][-1].update(stdin_bytes=len(stdin), stdin_sha256=sha(stdin))
            invoked.append(name)
            return result
        runner = oracle(root)
        result = runner.run(SimpleNamespace(output=output / FOLDER, runtime_root=root, cargo=str(cargo), offline=False,
            context_corpus=output / CONTEXT_FOLDER, response_corpus=output / RESPONSE_FOLDER,
            context_manifest=output / report['modules']['request_context']['manifest']),
            execute_callback=capture, environment=env)
        if invoked != list(CHECKS) or source_inputs(root) != source_pins:
            raise ValueError('original request-context build/replay source or process set changed')
        binary = FOLDER + '/cargo-target/debug/hepta-request-context-original-oracle'
        artifacts = {name: file_sha(owned(output, name)) for name in artifact_names()}
        report['request_context_reference'] = {'schema': 'hepta.runtime.request-context-reference.v1',
            'source_sha256': source_pins, 'artifact_sha256': artifacts, 'result': result,
            'build': {'cargo': str(cargo), 'rustc': str(rustc), 'cargo_sha256': file_sha(cargo.resolve()),
                'rustc_sha256': file_sha(rustc.resolve()), 'executable': binary,
                'executable_sha256': file_sha(owned(output, binary)), 'build_environment_policy': list(BUILD_VARIABLES),
                'ignored_inherited_build_variables': ignored}}
    bundle = check_bundle(root, output, report, completed)
    data = bundle['result']
    return {'schema': 'hepta.runtime.request-context-original-comparison.v1', 'status': 'PASS', 'component': component,
        'comparison': data['native_context_to_original' if component == 'request_context' else 'native_response_to_original'],
        'tokio_scenarios': 13 if component == 'request_context' else 0,
        'shared_fresh_reference': FOLDER + '/RESULT.json',
        'shared_fresh_reference_sha256': bundle['artifact_sha256'][FOLDER + '/RESULT.json'],
        'native_cases_added_by_corpus_replay': 0,
        'separate_original_to_native_calls': 7489 if component == 'request_context' else 0,
        'native_scheduler_qualified': False, 'production_activated': False, 'whole_runtime_replaced': False}


def check_original_receipts(root, output, report, completed):
    results = report.get('original_rust_comparisons', {})
    selected = [key for key in ('request_context', 'response_hints') if key in results]
    if not selected:
        if report.get('request_context_reference') is not None:
            raise ValueError('original request-context build has no completed recipe')
        return
    bundle = check_bundle(root, output, report, completed)
    for component in selected:
        value = results[component]
        expected = bundle['result']['native_context_to_original' if component == 'request_context' else 'native_response_to_original']
        if (value.get('schema') != 'hepta.runtime.request-context-original-comparison.v1'
                or value.get('status') != 'PASS' or value.get('component') != component
                or value.get('comparison') != expected or value.get('native_cases_added_by_corpus_replay') != 0
                or value.get('shared_fresh_reference') != FOLDER + '/RESULT.json'
                or value.get('shared_fresh_reference_sha256') != bundle['artifact_sha256'][FOLDER + '/RESULT.json']
                or value.get('tokio_scenarios') != (13 if component == 'request_context' else 0)
                or value.get('separate_original_to_native_calls') != (7489 if component == 'request_context' else 0)
                or any(value.get(key) is not False for key in (
                    'native_scheduler_qualified', 'production_activated', 'whole_runtime_replaced'))):
            raise ValueError('original request-context recipe lost its complete comparison')
