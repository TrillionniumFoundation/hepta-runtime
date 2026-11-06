#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Static source and fixed-byte checks only; no target module is imported."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD_ROOT = "/home/qian/hepta-runtime-validation-cost-20261106-d2"
ROOT = "/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02"

def body(source, name):
    nodes = [node for node in ast.walk(ast.parse(source))
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    assert len(nodes) == 1, name
    lines = source.splitlines(keepends=True)
    return ''.join(lines[nodes[0].lineno - 1:nodes[0].end_lineno])

def node(source, name):
    nodes = [value.value for value in ast.parse(source).body
             if isinstance(value, ast.Assign) and len(value.targets) == 1
             and isinstance(value.targets[0], ast.Name) and value.targets[0].id == name]
    assert len(nodes) == 1, name
    return nodes[0]

def const(source, name):
    return ast.literal_eval(node(source, name))

def ns(source):
    return source.replace(OLD_ROOT, ROOT).replace('hepta-d2-', 'hepta-r36-').replace('D2', 'R36 cold02')

def ident(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def save(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)

def main():
    old = (HERE / 'reference/archive_d2_ci.unsealed.py').read_text()
    old_seal = (HERE / 'reference/seal_d2_archive.py').read_text()
    current = (HERE / 'archive_r36_ci.unsealed.py').read_text()
    sealer = (HERE / 'seal_archive.py').read_text()
    config = json.loads((HERE / 'derivation.json').read_bytes())
    for raw, reference in ((old.encode(), config['reference_collector']),
                           (old_seal.encode(), config['reference_sealer'])):
        assert ident(raw) == {key: reference[key] for key in ('bytes', 'sha256')}
    for source in (old, old_seal, current, sealer):
        ast.parse(source)
    exact = ('need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal',
             'native_stream_pages', 'file', 'directory')
    for name in exact:
        assert body(current, name) == body(old, name), name
    namespace_only = ('require_sealed', 'collect', 'create_archive', 'verify_archive', 'main')
    for name in namespace_only:
        assert body(current, name) == ns(body(old, name)), name
    for name in ('MAX_TOTAL', 'MAX_FILE', 'MAX_MANIFEST', 'MAX_FILES', 'MAX_TAR',
                 'SKIP_DIRS', 'SKIP_FILES', 'FUTURE_PATHS', 'COUNT_KEYS', 'CI_COMMANDS'):
        assert ast.dump(node(current, name)) == ast.dump(node(old, name)), name
    assert const(current, 'ACTUAL') is None
    expected_env = const(old, 'CI_ENVIRONMENT').copy()
    expected_env['CARGO_HOME'] = '/home/qian/.cargo'
    expected_env['CARGO_TARGET_DIR'] = ROOT + '/target-build'
    assert const(current, 'CI_ENVIRONMENT') == expected_env
    assert sealer == ns(old_seal).replace('archive_d2_ci.py', 'archive_r36_ci.py').replace(
        "len(plan['source_files']) == 222", "len(plan['source_files']) == 220")
    fixed = const(current, 'PINNED')
    assert len(fixed) == 19 and fixed == config['fixed']
    fixed_rows = {}
    bodies = {}
    for name, pin in fixed.items():
        raw = Path(config['fixed_local_source_paths'][name]).read_bytes()
        assert ident(raw) == pin, name
        assert b'PRIVATE KEY-----' not in raw and b'openssh-key-v1\x00' not in raw, name
        fixed_rows[name] = pin
        bodies[name] = raw
    deployment = json.loads(bodies['rust-ci-deployment-manifest-01.json'])
    assert deployment['file_count_excluding_manifest'] == 10 and len(deployment['files']) == 10
    for row in deployment['files']:
        assert fixed[row['path']] == {key: row[key] for key in ('bytes', 'sha256')}
    assert deployment['external_parent'] == {'path': ROOT + '/tools-01/r36_campaign.py',
                                             **fixed['tools-01/r36_campaign.py']}
    tools = json.loads(bodies['rust-ci-tools-01/package-manifest-01.json'])
    bindings = json.loads(bodies['rust-ci-qualification-bindings-01.json'])
    q = json.loads(bodies['qualification-01/report.json'])
    summary = json.loads(bodies['qualification-01/isolated-tests/summary.json'])
    qmap = json.loads(bodies['qualification-01/source-map.json'])
    assert q['qualified'] is True and q['source_tested'] == q['source_after'] == qmap and len(qmap) == 220
    assert tools['qualification_counts'] == {key: summary[key] for key in const(current, 'COUNT_KEYS')}
    assert tools['actual_qualification_job_id'] == bindings['qualification_terminal_status']['job_id']
    assert set(bindings) == {'qualification_launcher', 'qualification_input', 'candidate_patch',
                             'qualification_preparation', 'qualification_terminal_status', 'qualification_reports'}
    patch = ''.join(difflib.unified_diff(old.splitlines(True), current.splitlines(True),
                                       fromfile='a/archive_d2_ci.unsealed.py', tofile='b/archive_r36_ci.unsealed.py'))
    patch += ''.join(difflib.unified_diff(old_seal.splitlines(True), sealer.splitlines(True),
                                        fromfile='a/seal_d2_archive.py', tofile='b/seal_archive.py'))
    save(HERE / 'reference-to-cold02.patch', patch.encode())
    result = {'schema': 'hepta-r36-cold02-ci-archive-static-check/v1',
              'collector': ident(current.encode()), 'sealer': ident(sealer.encode()),
              'fixed_member_count': len(fixed), 'fixed_originals_rehashed': fixed_rows,
              'exact_reference_functions': list(exact), 'namespace_only_functions': list(namespace_only),
              'sealer_full_source_expected_delta': True, 'four_sources_ast_parse_only': True,
              'private_scanner_applied_to_fixed_raw_bytes_only': True,
              'target_module_imports': 0, 'collector_or_sealer_or_binder_or_auditor_execution': False,
              'host_calls': 0, 'actual_ci_outcome': None, 'actual_ci_counts': None,
              'patch': ident(patch.encode())}
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    save(HERE / 'static-check.json', raw)
    print(json.dumps({'passed': True, 'fixed_count': len(fixed), 'patch': ident(patch.encode()),
                      'report': ident(raw)}, sort_keys=True))

if __name__ == '__main__':
    main()
