"""Strict, portable qualification of the fixed native directory caller profile.

The Python processes in this file are build and observation drivers. Directory,
session, path-policy, fence and filesystem decisions execute in native HIA or,
for the separate comparison, in the locked unchanged original Rust owners.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_directory_service_build as native
import hia_native_canonical_target as canonical_target

REFERENCE = 'tests/hia_native/directory_service_oracle'
REFERENCE_MANIFEST = 'native/directory_reference_sources.json'
REFERENCE_SHA256 = '82573f093ba7dc33913a993cc9a6858e880e26cf705b2d79405e766de52c0570'
TESTS = ('directory_service_support.py', 'test_directory_service.py', 'directory_service_kernel.py',
    'directory_service_faults.py', 'test_directory_service_transport.py', 'test_directory_service_build.py',
    'test_directory_service_evidence.py', 'test_directory_service_regex.py')
NATIVE_SUITE_GROUPS = {'functional': 5, 'faults': 2, 'transport': 4, 'builder': 4, 'regex': 3}
REGEX_CASES = ('syntax', 'unicode-size', 'size-bound-refused', 'invalid-byte',
    'regex-before-later-action', 'earlier-action-before-regex', 'literal', 'character-class',
    'unicode-property', 'anchored-wrapper-alternation', 'size-bound-accepted', 'ordered-multiple')
KERNEL_CASES = ('soft-cancel', 'outer-drop', 'eof-drain', 'parent-death', 'pending-drop', 'pending-soft')
FAULT_CASES = ('wake-pipe', 'fence-input-pipe', 'fence-output-pipe', 'fence-exec-error-pipe',
    'embedded-memfd', 'fence-fork', 'fence-exec', 'fence-parent-death-setup',
    'mkdir-result-pipe', 'mkdir-fork', 'actual-broken-fence-pipe', 'actual-mkdir-worker-death')
FUNCTIONAL_CASES = ('safe-paths', 'modern-meta', 'legacy-fallback', 'modern-no-fallback',
    'invalid-modern-capabilities', 'outside-workdir', 'unknown-meta', 'duplicate-meta', 'legacy-meta-fallback',
    'absent', 'absent-required', 'fenced', 'wrong-owner', 'preflight', 'no-roots', 'relative-root', 'remote-root',
    'raw-root', 'closed-stderr', 'blocked-child-signal', 'missing-user', 'empty-user')
TRANSPORT_CASES = dict(startup=('magic', 'mode', 'presence', 'absent-length', 'oversize',
    'short-header', 'short-payload', 'trailing', 'regular-fd', 'write-only-fd'),
    wire=('zero-length', 'short-length', 'over-limit', 'short-prefix', 'short-body',
    'magic', 'zero-command', 'unknown-command', 'zero-id', 'payload-length'),
    typed=('old-magic', 'reserved', 'presence', 'path-length', 'absent-metadata', 'path-over-limit'),
    boundary=('fragmented', 'exact-max-frame'))
BUILD_CASES = ('source-image', 'source-profile', 'selected-build-driver', 'compiler-commit-missing',
    'compiler-commit-wrong', 'consistently-rehashed-native-image', 'empty-compiler-stdout',
    'empty-packer-stdout', 'packer-manifest', 'packer-not-reaped', 'packer-nonzero-exit',
    'consistently-rehashed-final-elf', 'embedded-fence', 'packing-frame', 'artifact-symlink',
    'cached-bootstrap-commit-missing', 'cached-bootstrap-commit-wrong')
SUMMARY = dict(failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0)
sha = lambda raw: hashlib.sha256(raw).hexdigest()
require = native.require


def record(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=sha(raw))


def source_inventory(root=ROOT):
    _, _, _, material, _ = native.load_sources(root)
    source = dict(material)
    for name, expected in canonical_target.source_pins(root).items():
        data = native.file(root, name).read_bytes()
        require(record(native.file(root, name)) == expected, 'current policy source input differs')
        source[name] = data
    raw = native.file(root, REFERENCE_MANIFEST).read_bytes()
    require(sha(raw) == REFERENCE_SHA256, 'directory reference manifest differs')
    source[REFERENCE_MANIFEST] = raw
    reference = json.loads(raw)
    require(reference.get('schema') == 'hepta.directory.reference-source-manifest.v1'
            and reference.get('original_body_changes') is False and len(reference['files']) == 25
            and reference.get('canonical_policy_target') == canonical_target.source_evidence(root)
            and reference.get('other_historical_config_bytes_unchanged') is True,
            'directory reference source contract differs')
    for name, expected in reference['files'].items():
        full = REFERENCE + '/' + name; data = native.file(root, full).read_bytes()
        require(dict(bytes=len(data), sha256=sha(data)) == expected, 'directory actual reference source differs: ' + name)
        source[full] = data
    for name in (*TESTS,):
        full = 'tests/hia_native/' + name; source[full] = native.file(root, full).read_bytes()
    source['scripts/hia_native_directory_qualification.py'] = native.file(root, 'scripts/hia_native_directory_qualification.py').read_bytes()
    require(source['scripts/hia_native_directory_qualification.py'] == Path(__file__).read_bytes(),
            'directory selected qualification driver differs')
    return {name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in sorted(source.items())}


def original_source(root, runtime):
    project = Path(root) / REFERENCE
    extraction = json.loads((project / 'extraction.json').read_bytes())
    require(extraction.get('schema') == 'hepta.directory-service.original-source-extraction.v1'
            and len(extraction['original_inputs']) == 8 and len(extraction['slices']) == 11,
            'directory original extraction domain differs')
    require(extraction.get('config_full_module_unchanged') is False
            and extraction.get('other_historical_config_bytes_unchanged') is True
            and extraction.get('canonical_policy_target') == canonical_target.source_evidence(root),
            'directory current-target policy projection differs')
    original = {}
    for name, expected in extraction['original_inputs'].items():
        raw = native.file(runtime, name).read_bytes()
        require(dict(bytes=len(raw), sha256=sha(raw)) == expected, 'directory original runtime input differs: ' + name)
        original[name] = raw
    for target, source in [('owner/mcp/runtime/config.rs', 'src/mcp/runtime/config.rs'),
            ('owner/mcp/runtime/effect_owner_fence.rs', 'src/mcp/runtime/effect_owner_fence.rs'),
            ('owner/mcp/request_ctx.rs', 'src/mcp/request_ctx.rs')]:
        if source == 'src/mcp/runtime/config.rs':
            canonical_target.verify_compiled_config(original[source], (project / target).read_bytes(), root)
        else:
            require((project / target).read_bytes() == original[source], 'directory complete original module differs')
    spec = {
        'path_source_enum': ('src/mcp/fs/remote.rs', '#[derive(Debug, Clone)]\npub enum PathSource', '\nimpl PathSource', 'owner/mcp/fs/remote.rs'),
        'parse_path_source': ('src/mcp/fs/remote.rs', 'pub fn parse_path_source(', '\n/// Resolve a path string', 'owner/mcp/fs/remote.rs'),
        'resolve_path_source': ('src/mcp/fs/remote.rs', 'pub fn resolve_path_source(', '\n// ── SFTP connection pool', 'owner/mcp/fs/remote.rs'),
        'scoped_local': ('src/mcp/fs/parity_ops.rs', 'fn scoped_local(', '\n/// mkdir -p semantics', 'owner/mcp/fs/parity_ops.rs'),
        'execute_directory_create': ('src/mcp/fs/parity_ops.rs', 'pub async fn execute_directory_create(', '\n/// Rename an existing ordinary file', 'owner/mcp/fs/parity_ops.rs'),
        'local_linux': ('src/mcp/fs/parity_ops.rs', '#[cfg(target_os = "linux")]\nmod local_linux {', '\n#[cfg(test)]', 'owner/mcp/fs/parity_ops.rs'),
        'enforce_runtime_path_spec': ('src/mcp/server.rs', 'fn enforce_runtime_path_spec(', '\n#[tool_router]', 'owner/generated_directory_owner.rs'),
        'directory_create': ('src/mcp/server.rs', '\tasync fn directory_create(', '\n\t#[tool(', 'owner/generated_directory_owner.rs'),
        'append_hints': ('src/mcp/server.rs', 'fn append_hints(', '\n// ── Tool parameter schemas', 'owner/generated_directory_owner.rs'),
        'DirectoryCreateParams': ('src/mcp/server.rs', '#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct DirectoryCreateParams', '\n#[derive(', 'owner/generated_directory_owner.rs'),
        'McpToolCall': ('src/mcp/mod.rs', '#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct McpToolCall', '\nimpl McpToolCall', 'owner/mcp.rs')}
    for name, (path, first, following, generated) in spec.items():
        text = original[path].decode(); start = text.index(first); end = text.index(following, start)
        raw = (text[start:end].rstrip() + '\n').encode()
        require(dict(bytes=len(raw), sha256=sha(raw)) == extraction['slices'][name]
                and (project / generated).read_bytes().count(raw) == 1,
                'directory compiled original slice differs: ' + name)
    session = (project / 'owner/generated_session_owner.rs').read_bytes()
    marker = b'// Qualification-only reference carrier; original extracted bodies remain unchanged.\n'
    require(session.count(marker) == 1 and sha(session.split(marker, 1)[1]) == extraction['session_owner_sha256'],
            'directory original Session extraction changed')
    production = {(p['name'], p['version']): p for p in tomllib.loads(original['Cargo.lock'].decode())['package']}
    dependencies = [p for p in tomllib.loads((project / 'Cargo.lock').read_text())['package'] if 'source' in p]
    require(len(dependencies) == 100 and (project / 'original-runtime.lock').read_bytes() == original['Cargo.lock'],
            'directory original locked dependency domain differs')
    for dependency in dependencies:
        old = production[(dependency['name'], dependency['version'])]
        require(dependency['source'] == old['source'] and dependency['checksum'] == old['checksum'],
                'directory original dependency pin differs')
    return dict(original_inputs=extraction['original_inputs'], exact_slices=extraction['slices'],
        dependencies=100, complete_original_modules=2, copyright_only_additions=8,
        canonical_policy_target=canonical_target.source_evidence(root),
        other_historical_config_bytes_unchanged=True,
        session_body_sha256=extraction['session_owner_sha256'])


def strict_summary(report, groups):
    require(report.get('status') == 'PASS' and report.get('test_summary') == dict(tests_run=groups, **SUMMARY)
            and report.get('production_activated') is False and report.get('whole_runtime_replaced') is False,
            'directory actual suite did not complete its exact domain')


def check_test_sources(report, root, expected):
    pins = report.get('source_sha256', {})
    require(type(pins) is dict and len(pins) == len(expected)
            and {Path(k).name for k in pins} == set(expected), 'directory actual observer source domain differs')
    for path, expected_sha in pins.items():
        require(sha(native.file(root, 'tests/hia_native/' + Path(path).name).read_bytes()) == expected_sha,
                'directory actual observer source changed')


def decode_events(raw):
    rows = []; at = 0
    while at < len(raw):
        require(len(raw) - at >= 8, 'directory output prefix incomplete')
        n, = struct.unpack_from('<Q', raw, at); at += 8
        require(40 <= n <= len(raw) - at, 'directory output record incomplete')
        data = raw[at:at + n]; at += n
        require(data[:8] == b'HMDCTR01', 'directory output magic differs')
        kind, identifier, code, count = struct.unpack_from('<4Q', data, 8)
        require(kind in (1, 2, 3, 4) and code <= 0xffffffff and count == len(data) - 40,
                'directory output envelope differs')
        rows.append(dict(kind=kind, id=identifier, code=code, payload_hex=data[40:].hex()))
    return rows


def functional_evidence(directory, root, original_sha=None):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 5)
    check_test_sources(report, root, ('directory_service_support.py', 'test_directory_service.py'))
    require(report.get('source_unchanged') is True, 'directory functional source changed')
    want = dict(native_processes=22, native_requests=67, original_processes=22 if original_sha else 0,
                original_requests=67 if original_sha else 0)
    require(report.get('expected_counts') == want and all(report.get(k) == v for k, v in want.items())
            and len(report['cases']) == want['native_processes'] + want['original_processes'],
            'directory functional process/request count differs')
    variants = ('native', 'original') if original_sha else ('native',)
    require([(c['name'], c['variant']) for c in report['cases']] ==
            [(name, variant) for name in FUNCTIONAL_CASES for variant in variants],
            'directory functional fixed case domain differs')
    names = set(); by_name = {}; counts = {'native': 0, 'original': 0}
    for case in report['cases']:
        variant = case['variant']; process = case['process']
        require(variant in counts and (variant == 'native' or original_sha is not None)
                and process.get('variant') == variant and process.get('reaped') is True
                and process.get('exit_code') == 0
                and process.get('elf_sha256') == (native.ELF if variant == 'native' else original_sha),
                'directory functional actual process differs')
        pair = (case['name'], variant); require(pair not in names, 'duplicate directory functional case'); names.add(pair)
        replies = decode_events(bytes.fromhex(process['output_hex']))
        require(replies == process['events'] and len(replies) == 2 * len(case['results']),
                'directory functional full stream differs')
        for result, accepted, completed in zip(case['results'], replies[::2], replies[1::2], strict=True):
            require(accepted == dict(kind=1, id=result['id'], code=0, payload_hex='')
                    and completed['kind'] == 2 and completed['id'] == result['id'],
                    'directory functional event ordering differs')
            body = bytes.fromhex(completed['payload_hex'])
            require(completed['code'] == len(body) and body[:8] == b'HMDCRS01' and len(body) >= 32,
                    'directory functional raw result differs')
            tag, reserved, length = struct.unpack_from('<3Q', body, 8)
            require(reserved == 0 and length == len(body) - 32
                    and result == dict(id=result['id'], tag=tag, text_hex=body[32:].hex()),
                    'directory functional parsed result differs from retained bytes')
        stderr = bytes.fromhex(process['stderr_hex'])
        if variant == 'native': require(not stderr, 'native directory emitted stderr')
        elif stderr:
            lines = [json.loads(x) for x in stderr.splitlines()]
            require(len(lines) == 2 and lines[0]['schema'] == 'hepta.directory.actual-sdk-bootstrap.v1'
                    and lines[1]['schema'] == 'hepta.directory.original-driver.v1', 'original directory SDK receipt differs')
        counts[variant] += len(case['results']); by_name[pair] = case
    require(counts == {'native': 67, 'original': 67 if original_sha else 0}, 'directory replay row count differs')
    if original_sha:
        for name, variant in names:
            if variant != 'native': continue
            left, right = by_name[(name, 'native')], by_name[(name, 'original')]
            require(all(left[key] == right[key] for key in ('before', 'results', 'after')),
                    'actual original directory result or complete filesystem snapshot differs')
    return want


def regex_evidence(directory, root, original_sha=None):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 3)
    check_test_sources(report, root, ('directory_service_support.py', 'test_directory_service.py',
                                     'test_directory_service_regex.py'))
    want = dict(native_processes=12, native_requests=18, native_startup_refusals=6,
                original_processes=12 if original_sha else 0, original_requests=18 if original_sha else 0,
                original_startup_refusals=6 if original_sha else 0)
    require(report.get('source_unchanged') is True and report.get('expected_domains') == list(REGEX_CASES)
            and report.get('expected_counts') == want and all(report.get(k) == v for k, v in want.items()),
            'directory actual regex process domain differs')
    variants = ('native', 'original') if original_sha else ('native',)
    require([(case['name'], case['variant']) for case in report['cases']] ==
            [(name, variant) for name in REGEX_CASES for variant in variants],
            'directory actual regex case ordering differs')
    by_name = {}; counts = {key: 0 for key in want}
    for case in report['cases']:
        name, variant = case['name'], case['variant']; process = case['process']
        failed = REGEX_CASES.index(name) < 6
        require(process.get('variant') == variant and type(process.get('pid')) is int and process['pid'] > 0
                and process.get('reaped') is True and process.get('exit_code') == (78 if failed else 0)
                and process.get('elf_sha256') == (native.ELF if variant == 'native' else original_sha)
                and bytes.fromhex(process['snapshot_hex']) == b'HMDINIT1' + bytes(24),
                'directory actual regex process or trusted startup differs')
        replies = decode_events(bytes.fromhex(process['output_hex']))
        require(replies == process['events'] and len(replies) == (0 if failed else 6),
                'directory regex complete response stream differs')
        stderr = bytes.fromhex(process['stderr_hex'])
        if failed:
            error = (b'host `h` privileged action `inspect` has invalid argument regex'
                     if REGEX_CASES.index(name) < 4 else
                     b'host `h` privileged action `middle` has invalid argument regex'
                     if name == 'regex-before-later-action' else b'host `h` has invalid privileged action `afirst`')
            require(case['startup_error_hex'] == error.hex() and stderr == error + b'\n'
                    and not bytes.fromhex(process['input_hex']) and case['results'] == []
                    and case['before'] == case['after'],
                    'directory regex startup failure or pre-installation effects differ')
            counts[variant + '_startup_refusals'] += 1
        else:
            require(case['startup_error_hex'] is None and len(case['results']) == 3,
                    'directory valid regex request count differs')
            for index, (result, accepted, completed) in enumerate(zip(
                    case['results'], replies[::2], replies[1::2], strict=True), 1):
                require(accepted == dict(kind=1, id=index, code=0, payload_hex='')
                        and completed['kind'] == 2 and completed['id'] == index,
                        'directory regex accepted/completed ordering differs')
                raw = bytes.fromhex(completed['payload_hex'])
                require(completed['code'] == len(raw) and len(raw) >= 32 and raw[:8] == b'HMDCRS01',
                        'directory regex result envelope differs')
                tag, reserved, n = struct.unpack_from('<3Q', raw, 8)
                require((tag, reserved, n) == (0 if index < 3 else 1, 0, len(raw) - 32)
                        and result == dict(id=index, tag=tag, text_hex=raw[32:].hex()),
                        'directory regex result projection differs from actual bytes')
            if variant == 'native':
                require(stderr == b'', 'native regex-profile caller emitted stderr')
            else:
                lines = [json.loads(line) for line in stderr.splitlines()]
                require(len(lines) == 2 and lines[0]['schema'] == 'hepta.directory.actual-sdk-bootstrap.v1'
                        and lines[1]['schema'] == 'hepta.directory.original-driver.v1',
                        'directory original regex-profile SDK bootstrap differs')
        counts[variant + '_processes'] += 1
        counts[variant + '_requests'] += len(case['results'])
        by_name[(name, variant)] = case
    require(counts == want, 'directory retained regex process/request count differs')
    if original_sha:
        for name in REGEX_CASES:
            left, right = by_name[(name, 'native')], by_name[(name, 'original')]
            require(all(left[key] == right[key] for key in ('before', 'after', 'results', 'startup_error_hex'))
                    and all(left['process'][key] == right['process'][key]
                            for key in ('input_hex', 'output_hex', 'snapshot_hex')),
                    'directory actual original regex result, byte stream or filesystem effects differ')
    return want


def retained_streams(directory, prefix, case, *, fault=False):
    for suffix, stem in [('stdin', 'stdin' if fault else 'input'), ('stdout', 'stdout' if fault else 'output'), ('stderr', 'stderr')]:
        raw = native.file(directory, prefix + '.' + suffix).read_bytes()
        require(len(raw) == case[stem + '_bytes'] and sha(raw) == case[stem + '_sha256'],
                'directory complete raw process stream differs')
        if suffix == 'stdout':
            decoded = decode_events(raw)
            if fault:
                decoded = [dict(event=x['kind'], id=x['id'], code=x['code'], payload_hex=x['payload_hex']) for x in decoded]
            require(decoded == case['replies'], 'directory full stdout/reply projection differs')
    require(json.loads(native.file(directory, prefix + '.events.json').read_bytes()) == case['events'],
            'directory full kernel observation differs')
    require(case.get('status') == 'PASS' and case.get('all_owned_tasks_reaped') is True
            and type(case.get('exit_statuses')) is dict and case['exit_statuses']
            and all(str(int(pid)) == pid and int(pid) > 0 for pid in case['exit_statuses']),
            'directory actual task cleanup evidence differs')


def kernel_evidence(directory, root, original_sha):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 6)
    check_test_sources(report, root, ('directory_service_kernel.py', 'directory_service_support.py'))
    require(report.get('expected_cases') == list(KERNEL_CASES) and report.get('syscall_mutations') == 0
            and report.get('native_processes') == report.get('original_processes') == 6
            and len(report['cases']) == 12, 'directory kernel paired domain differs')
    require([(c['case'], c['variant']) for c in report['cases']] == [(c, v) for c in KERNEL_CASES for v in ('native', 'original')],
            'directory kernel case order/domain differs')
    for case in report['cases']:
        retained_streams(directory, case['variant'] + '-' + case['case'], case)
        require(case.get('syscall_mutations') == 0 and case.get('binary_sha256') ==
                (native.ELF if case['variant'] == 'native' else original_sha), 'directory kernel binary or mutation domain differs')
        if case['case'] == 'pending-drop':
            require(case['kernel_blocked_fence'] and case['record_validation_after_cancel'] and not case['mkdir_returned'],
                    'cancelled submitted fence worker did not finish validation')
        elif case['case'] == 'parent-death':
            require(-9 in case['exit_statuses'].values() and not case['mkdir_returned'], 'directory parent-death domain differs')
        else:
            require(case['mkdir_returned'] and set(case['exit_statuses'].values()) == {0},
                    'directory submitted effect or cleanup did not complete')
        if case['case'] in ('soft-cancel', 'outer-drop'):
            observations = [x for x in case['events'] if x['kind'] == 'after_cancel_before_actual_mkdir']
            require(len(observations) == 1 and observations[0]['directory_exists'] is False
                    and observations[0]['exclusive_available'] is (case['case'] == 'outer-drop'),
                    'original outer-drop/soft-cancel permit lifetime differs')
    return dict(native_processes=6, original_processes=6, paired_cases=6, syscall_mutations=0)


def faults_evidence(directory, root):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 2)
    check_test_sources(report, root, ('directory_service_faults.py', 'directory_service_kernel.py', 'directory_service_support.py'))
    require(report.get('source_unchanged') is True and report.get('original_executions') == 0
            and report.get('native_elf_sha256') == native.ELF and report.get('expected_cases') == list(FAULT_CASES)
            and [c['case'] for c in report['cases']] == list(FAULT_CASES), 'directory fixed fault domain differs')
    for index, case in enumerate(report['cases']):
        retained_streams(directory, case['case'], case, fault=True)
        require(case.get('original_executions') == 0 and case.get('actual_processes') == 1
                and case.get('synthetic_errno_injections') == int(index < 10)
                and case.get('actual_broken_pipe') is (index == 10)
                and case.get('actual_worker_sigkill') is (index == 11), 'directory synthetic/actual fault domains mixed')
        suppressed = [x for x in case['events'] if x['kind'] == 'qualification_syscall_suppressed']
        require(len(suppressed) == int(index < 10), 'directory fault intervention count differs')
        killed = {x['target'] for x in case['events'] if x['kind'] == 'adapter_sigkill_success'}
        killed.update(x['reader'] for x in case['events'] if x['kind'] == 'actual_pipe_reader_killed')
        killed.update(x['tid'] for x in case['events'] if x['kind'] == 'actual_submitted_worker_sigkill')
        races = [x['tid'] for x in case['events'] if x['kind'] in
                 ('observation_raced_with_terminal_task', 'resume_raced_with_terminal_task')]
        require(all(tid in killed and case['exit_statuses'].get(str(tid)) == -9 for tid in races),
                'directory terminal observation lacks actual owned kill and fatal wait')
    return dict(native_processes=12, synthetic_errno_injections=10, actual_broken_pipes=1,
                actual_worker_kills=1, original_executions=0)


def transport_evidence(directory, root):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 4)
    check_test_sources(report, root, ('test_directory_service_transport.py', 'directory_service_support.py'))
    require(report.get('source_unchanged') is True and report.get('elf_sha256') == native.ELF
            and report.get('native_processes') == 28 and report.get('original_executions') == 0,
            'directory transport domain differs')
    require(report['expected_domains'] == {k: list(v) for k, v in TRANSPORT_CASES.items()},
            'directory transport declared domain differs')
    expected = [(group, name) for group, names in TRANSPORT_CASES.items() for name in names]
    require(len(expected) == 28 and {(c['group'], c['case']) for c in report['cases']} == set(expected)
            and len(report['cases']) == 28, 'directory transport case coverage differs')
    for case in report['cases']:
        compressed = native.file(directory, case['stdin_gzip']).read_bytes(); raw = gzip.decompress(compressed)
        require(sha(compressed) == case['stdin_gzip_sha256'] and len(raw) == case['stdin_bytes']
                and sha(raw) == case['stdin_sha256'] and case['reaped'] is True and case['status'] == 'PASS'
                and case['exit_code'] == (111 if case['group'] in ('startup', 'wire') else 0)
                and not bytes.fromhex(case['stderr_hex'])
                and len(decode_events(bytes.fromhex(case['stdout_hex']))) == case['actual_events'],
                'directory transport retained process differs')
    maximum = next(c for c in report['cases'] if c['case'] == 'exact-max-frame')
    require(maximum['stdin_bytes'] == 16777296 and maximum['workspace_entries_hex'] == [],
            'directory exact maximum private frame was not exercised')
    return dict(native_processes=28, startup_refusals=10, wire_refusals=10, typed_recovery_processes=6,
                exact_maximum_frame_bytes=16777288, original_executions=0)


def builder_evidence(directory, root):
    report = json.loads(native.file(directory, 'report.json').read_bytes()); strict_summary(report, 4)
    pins = report['source_sha256']
    require(len(pins) == 2 and {Path(p).name for p in pins} ==
            {'test_directory_service_build.py', 'hia_native_directory_service_build.py'}, 'directory build control source domain differs')
    for name, value in pins.items():
        relative = ('scripts/' if Path(name).name.startswith('hia_native_') else 'tests/hia_native/') + Path(name).name
        require(sha(native.file(root, relative).read_bytes()) == value, 'directory build control source changed')
    require(report.get('source_unchanged') is True and len(report['accepted']) == 2
            and report['accepted'] == ['complete-native-compile-and-pack-receipts', 'actual-cached-builder']
            and len(report['refused']) == 17 and [x['name'] for x in report['refused']] == list(BUILD_CASES)
            and report['expected_refusals'] == list(BUILD_CASES)
            and report.get('native_semantic_cases_added') == report.get('original_executions') == 0,
            'directory actual builder refusal domain differs')
    return dict(accepted=2, refused=17, native_semantic_cases_added=0, original_executions=0)


def run_process(output, name, argv, environment, root=ROOT, *, cwd=None):
    before = source_inventory(root); started = time.monotonic()
    process = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=environment,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = process.communicate(b'', timeout=180)
    except subprocess.TimeoutExpired:
        timed_out = True; process.kill(); stdout, stderr = process.communicate()
    for suffix, raw in [('stdout', stdout), ('stderr', stderr)]:
        with (output / (name + '.' + suffix)).open('xb') as handle: handle.write(raw)
    after = source_inventory(root)
    value = dict(schema='hepta.directory.actual-process.v1', argv=[str(x) for x in argv], pid=process.pid,
        exit_code=process.returncode, process_reaped=True, inherits_outer_process_group=True,
        timeout_seconds=180, timed_out=timed_out, elapsed_seconds=time.monotonic() - started,
        stdin_bytes=0, stdin_sha256=sha(b''), stdout_bytes=len(stdout), stdout_sha256=sha(stdout),
        stderr_bytes=len(stderr), stderr_sha256=sha(stderr), source_before=before, source_after=after,
        source_unchanged=before == after)
    with (output / (name + '.process.json')).open('xb') as handle: handle.write(native.json_bytes(value))
    require(not timed_out and process.returncode == 0 and before == after,
            'directory actual process failed: ' + name)
    return stdout


def process_evidence(output, name, root):
    value = json.loads(native.file(output, name + '.process.json').read_bytes())
    require(value.get('schema') == 'hepta.directory.actual-process.v1'
            and type(value.get('pid')) is int and value['pid'] > 0 and value.get('exit_code') == 0
            and value.get('process_reaped') is True and value.get('inherits_outer_process_group') is True
            and value.get('timeout_seconds') == 180 and value.get('timed_out') is False
            and value.get('stdin_bytes') == 0 and value.get('stdin_sha256') == sha(b'')
            and value.get('source_unchanged') is True
            and value.get('source_before') == value.get('source_after') == source_inventory(root),
            'directory actual process completion/source evidence differs')
    for suffix in ('stdout', 'stderr'):
        raw = native.file(output, name + '.' + suffix).read_bytes()
        require(len(raw) == value[suffix + '_bytes'] and sha(raw) == value[suffix + '_sha256'],
                'directory full outer process log differs')
    if name in ('functional', 'faults', 'transport', 'builder', 'kernel', 'regex', 'evidence-controls'):
        scripts = dict(functional='test_directory_service.py', faults='directory_service_faults.py',
            transport='test_directory_service_transport.py', builder='test_directory_service_build.py',
            kernel='directory_service_kernel.py', regex='test_directory_service_regex.py',
            **{'evidence-controls': 'test_directory_service_evidence.py'})
        argv = value['argv']
        require(len(argv) >= 8 and argv[1:3] == ['-I', '-B']
                and Path(argv[3]).name == scripts[name] and Path(argv[3]).is_absolute(),
                'directory actual suite invocation differs')
        actual = json.loads(native.file(output, name + '/report.json').read_bytes())
        stdout = json.loads(native.file(output, name + '.stdout').read_bytes())
        if name == 'functional':
            keys = {'status', 'test_summary', 'native_processes', 'original_processes',
                    'native_requests', 'original_requests', 'elapsed_seconds'}
        else:
            excluded = {'cases', 'source_sha256'}
            if name == 'transport': excluded.add('expected_domains')
            if name == 'builder': excluded |= {'accepted', 'refused', 'expected_refusals'}
            if name == 'evidence-controls': excluded |= {'accepted', 'refused', 'expected_refusals', 'source_inventory'}
            keys = set(actual) - excluded
        require(type(stdout) is dict and set(stdout) == keys and stdout == {k: actual[k] for k in keys},
                'directory actual suite complete stdout differs')
    return value


def native_phase(args):
    out = args.output; out.mkdir(parents=True, exist_ok=False)
    native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    tests = ROOT / 'tests/hia_native'
    report = dict(schema='hepta.directory.native-phase.v1', status='FAIL', source_inventory=source_inventory(), results={})
    try:
        for name, script in [('functional', 'test_directory_service.py'), ('faults', 'directory_service_faults.py'),
                ('transport', 'test_directory_service_transport.py'), ('builder', 'test_directory_service_build.py'),
                ('regex', 'test_directory_service_regex.py')]:
            command = [sys.executable, '-I', '-B', tests / script, '--manifest', args.manifest, '--output', out / name]
            if name == 'builder': command += ['--hepta', args.hepta, '--build-root', args.build_root]
            run_process(out, name, command, env)
        report['results'] = dict(functional=functional_evidence(out / 'functional', ROOT),
            faults=faults_evidence(out / 'faults', ROOT), transport=transport_evidence(out / 'transport', ROOT),
            builder=builder_evidence(out / 'builder', ROOT), regex=regex_evidence(out / 'regex', ROOT))
        for name in NATIVE_SUITE_GROUPS: process_evidence(out, name, ROOT)
        native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
        report.update(status='PASS', completed_suites=5, total_groups=18, native_processes=74,
                      original_executions=0, whole_runtime_replaced=False, production_activated=False)
    finally:
        (out / 'phase.json').write_bytes(native.json_bytes(report))
    print(json.dumps({k: v for k, v in report.items() if k not in ('results', 'source_inventory')}))


def original_phase(args):
    out = args.output; out.mkdir(parents=True, exist_ok=False)
    native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
    source = original_source(ROOT, args.runtime)
    project = out / 'project'; shutil.copytree(ROOT / REFERENCE, project)
    env = dict(os.environ)
    for name in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP', 'RUSTFLAGS',
                 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'RUST_TARGET_PATH'):
        env.pop(name, None)
    tool = args.rust_bin.resolve(strict=True)
    env.update(RUSTC=str(tool / 'rustc'), RUSTFMT=str(tool / 'rustfmt'), PYTHONDONTWRITEBYTECODE='1')
    report = dict(schema='hepta.directory.actual-original-phase.v1', status='FAIL', original_source=source,
                  source_inventory=source_inventory(), expected_processes=8, current_original_replay=True)
    offline = ['--offline'] if args.offline else []
    try:
        version = run_process(out, 'rust-version', [tool / 'rustc', '-vV'], env).decode()
        require(version.startswith('rustc 1.95.0 '), 'directory comparison requires explicit Rust 1.95.0')
        report['rust_version'] = version
        run_process(out, 'format-check', [tool / 'rustfmt', '--check', '--edition', '2021', '--config',
            'hard_tabs=true,skip_children=true', project / 'owner/oracle_directory_service.rs'], env)
        with tempfile.TemporaryDirectory(prefix='directory-original-target-', dir=out.parent) as target:
            env['CARGO_TARGET_DIR'] = target
            metadata = json.loads(run_process(out, 'metadata', [tool / 'cargo', 'metadata', '--locked', *offline,
                '--format-version', '1', '--manifest-path', project / 'Cargo.toml'], env, cwd=project))
            sdk = [p for p in metadata['packages'] if p['name'] == 'rmcp' and p['version'] == '3.4.1']
            require(len(sdk) == 1, 'directory actual SDK crate differs')
            installed = Path(sdk[0]['manifest_path']).parent
            crate_path = installed.parents[2] / 'cache' / installed.parent.name / 'rmcp-3.4.1.crate'
            crate = crate_path.read_bytes()
            require(sha(crate) == '5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898',
                    'directory actual SDK package checksum differs')
            sdk_files = {}
            with tarfile.open(fileobj=io.BytesIO(crate), mode='r:gz') as archive:
                for member in archive.getmembers():
                    if member.isdir(): continue
                    require(member.isfile() and member.name.startswith('rmcp-3.4.1/')
                            and '..' not in Path(member.name).parts, 'directory SDK archive member differs')
                    name = member.name[len('rmcp-3.4.1/'):]; raw = archive.extractfile(member).read()
                    require((installed / name).read_bytes() == raw, 'directory installed SDK source differs')
                    sdk_files[name] = dict(bytes=len(raw), sha256=sha(raw))
            require(len(sdk_files) == 175, 'directory installed SDK full file count differs')
            report.update(sdk_crate_sha256=sha(crate), sdk_installed_files=sdk_files)
            run_process(out, 'build', [tool / 'cargo', 'build', '--release', '--locked', *offline,
                '--manifest-path', project / 'Cargo.toml', '--bin', 'hia-directory-service-reference'], env, cwd=project)
            binary = out / 'original-reference.elf'
            shutil.copy2(Path(target) / 'release/hia-directory-service-reference', binary); binary.chmod(0o500)
        report['cargo_intermediates_retired_after_copy'] = True
        reference_sha = sha(binary.read_bytes()); report['original_binary'] = record(binary)
        m = json.loads(args.manifest.read_bytes()); executable = args.manifest.parent / m['executable']
        tests = ROOT / 'tests/hia_native'
        run_process(out, 'functional', [sys.executable, '-I', '-B', tests / 'test_directory_service.py',
            '--manifest', args.manifest, '--output', out / 'functional', '--reference', binary,
            '--reference-sha256', reference_sha], env)
        run_process(out, 'kernel', [sys.executable, '-I', '-B', tests / 'directory_service_kernel.py',
            '--native', executable, '--native-sha256', m['elf_sha256'], '--original', binary,
            '--original-sha256', reference_sha, '--output', out / 'kernel'], env)
        run_process(out, 'regex', [sys.executable, '-I', '-B', tests / 'test_directory_service_regex.py',
            '--manifest', args.manifest, '--output', out / 'regex', '--reference', binary,
            '--reference-sha256', reference_sha], env)
        report['functional'] = functional_evidence(out / 'functional', ROOT, reference_sha)
        report['kernel'] = kernel_evidence(out / 'kernel', ROOT, reference_sha)
        report['regex'] = regex_evidence(out / 'regex', ROOT, reference_sha)
        for name in ('rust-version', 'format-check', 'metadata', 'build', 'functional', 'kernel', 'regex'):
            process_evidence(out, name, ROOT)
        require(original_source(ROOT, args.runtime) == source, 'directory original inputs changed')
        expected = json.loads((ROOT / REFERENCE_MANIFEST).read_bytes())['files']
        require({name: record(project / name) for name in expected} == expected, 'compiled directory reference source changed')
        require(args.native_results is not None, 'directory evidence controls require the completed native phase')
        run_process(out, 'evidence-controls', [sys.executable, '-I', '-B', tests / 'test_directory_service_evidence.py',
            '--native-results', args.native_results, '--original-results', out, '--output', out / 'evidence-controls'], env)
        controls = json.loads((out / 'evidence-controls/report.json').read_bytes())
        strict_summary(controls, 6)
        require(len(controls['accepted']) == 10 and len(controls['refused']) == 31,
                'directory final evidence negative-control count differs')
        process_evidence(out, 'evidence-controls', ROOT)
        report['evidence_controls'] = dict(accepted=10, refused=31, groups=6, semantic_cases_added=0)
        native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
        report.update(status='PASS', completed_processes=8, original_processes=40,
            native_processes=40, original_functional_requests=67, original_regex_requests=18, paired_kernel_cases=6,
            production_activated=False, whole_runtime_replaced=False)
    finally:
        (out / 'phase.json').write_bytes(native.json_bytes(report))
    print(json.dumps({k: report[k] for k in ('schema', 'status', 'completed_processes', 'original_processes',
        'native_processes', 'original_functional_requests', 'paired_kernel_cases')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('native', 'original'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=ROOT)
    parser.add_argument('--rust-bin', type=Path)
    parser.add_argument('--native-results', type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    args.manifest = args.manifest.resolve(strict=True); args.output = args.output.resolve()
    if args.phase == 'original':
        require(args.rust_bin is not None, 'explicit Rust 1.95 toolchain directory required')
        original_phase(args)
    else:
        native_phase(args)


if __name__ == '__main__':
    main()
