import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import time

ROOT = pathlib.Path('/home/qian-qi/hepta-runtime-rea-next-javascript-20261104-r1')
EVIDENCE = pathlib.Path('/home/qian-qi/work/hepta-rea-next-javascript-evidence-20261104-r1')
BINARY = pathlib.Path('/home/qian-qi/work/hepta-rea-next-javascript-20261104-target/debug/hepta-runtime')
CARGO = '/home/qian-qi/.cargo/bin/cargo'
ORACLE = '/home/qian-qi/work/hepta-rea-next-javascript-oracle-20261104'


def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def manifest():
    selected = subprocess.check_output(
        ['/usr/bin/git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT
    ).decode().split('\0')
    return {p: sha(ROOT / p) for p in sorted(set(selected)) if p and (ROOT / p).is_file()}


receipt = {
    'schema': 'hepta.javascript-native-qualification.v1',
    'status': 'running',
    'host': 'desktop',
    'platform': platform.platform(),
    'base_head': subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
    'scope': 'Owned finite AST fixtures, isolated native worker and actual stdio MCP; not full REA parity or observed Electron runtime',
    'steps': [],
}


def save():
    (EVIDENCE / 'qualification-v5.json').write_text(json.dumps(receipt, indent=2) + '\n')


def run(name, command, timeout=900):
    print(json.dumps({'step': name, 'command': command}), flush=True)
    logfile = EVIDENCE / (name + '.log')
    started = time.monotonic()
    with logfile.open('wb') as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    step = {'name': name, 'command': command, 'exit_code': result.returncode,
            'duration_seconds': round(time.monotonic() - started, 3),
            'log_file': logfile.name, 'log_sha256': sha(logfile)}
    receipt['steps'].append(step)
    save()
    print(json.dumps(step), flush=True)
    print(logfile.read_text(errors='replace')[-3500:], flush=True)
    if result.returncode:
        raise RuntimeError('qualification step failed: ' + name)
    return logfile.read_text(errors='replace')


try:
    frozen_path = EVIDENCE / 'source-prequalification-v5.json'
    frozen = json.loads(frozen_path.read_text())
    before = manifest()
    if before != frozen:
        raise RuntimeError('source files changed after test build freeze')
    old = json.loads((EVIDENCE / 'source-prebuild-v3.json').read_text())
    changed = sorted(p for p in set(old) | set(before) if old.get(p) != before.get(p))
    production_changed = [p for p in changed if p.startswith('src/') or p in ('Cargo.toml', 'Cargo.lock')]
    if production_changed != ['src/mcp/rea_javascript_graph_worker.rs']:
        raise RuntimeError('unexpected production delta beyond the explicit stdin ownership fix: ' + repr(production_changed))
    receipt['source'] = {
        'manifest_file': frozen_path.name,
        'manifest_file_sha256': sha(frozen_path),
        'entries': len(frozen),
        'changed_paths_since_original_build': changed,
        'production_changed_paths_since_original_build': production_changed,
        'test_build_manifest_verified_before_execution': True,
    }
    artifacts = json.loads((EVIDENCE / 'test-artifacts-v5.json').read_text())
    library = next(a for a in artifacts if a['name'] == 'hepta_runtime')
    external = next(a for a in artifacts if a['name'] == 'rea_javascript_graph_external')
    for artifact in [library, external]:
        if sha(artifact['executable']) != artifact['sha256']:
            raise RuntimeError('test executable changed since build')
    receipt['test_artifacts'] = [library, external]
    unit_log = run('unit-tests-v5', [library['executable'], 'mcp::rea_javascript_graph::tests::', '--test-threads=1'])
    if '7 passed; 0 failed' not in unit_log:
        raise RuntimeError('unit test selection did not execute all seven owned tests')
    # Test builds unify the rmcp client dev feature. Restore the normal binary
    # build before the integration executable invokes CARGO_BIN_EXE_hepta-runtime.
    run('production-build-v5', [CARGO, 'build', '--locked', '--all-features', '--bin', 'hepta-runtime', '-j4'])
    binary_sha = sha(BINARY)
    receipt['candidate'] = {'path': str(BINARY), 'sha256': binary_sha,
                            'profile': 'dev optimized + debuginfo; all production features',
                            'original_worker_build_sha256': json.loads((EVIDENCE / 'binary-v3.json').read_text())['sha256']}
    save()
    mcp_log = run('mcp-integration-v5', [external['executable'], '--test-threads=1'], timeout=300)
    if '1 passed; 0 failed' not in mcp_log:
        raise RuntimeError('actual MCP integration test did not execute')
    run('babel-final-v5', ['/usr/bin/node', 'scripts/rea-javascript-ast-reference.mjs',
        'tests/fixtures/rea_javascript', ORACLE, str(BINARY), str(EVIDENCE / 'reference-final-v5.json')], timeout=180)
    run('format-check-v5', [CARGO, 'fmt', '--all', '--check'])
    run('clippy-v5', [CARGO, 'clippy', '--locked', '--all-features', '--all-targets', '-j4', '--', '-D', 'warnings'])
    after = manifest()
    if after != before:
        raise RuntimeError('source files changed during qualification')
    if sha(BINARY) != binary_sha:
        raise RuntimeError('runtime executable changed during qualification')
    reference = json.loads((EVIDENCE / 'reference-final-v5.json').read_text())
    if reference['status'] != 'pass' or reference['candidate']['executable_sha256'] != binary_sha:
        raise RuntimeError('Babel report does not qualify this runtime executable')
    receipt['source']['unchanged_after_qualification'] = True
    receipt['candidate']['unchanged_after_qualification'] = True
    receipt['reference'] = {'file': 'reference-final-v5.json', 'sha256': sha(EVIDENCE / 'reference-final-v5.json'),
                            'comparisons': reference['comparisons'], 'manual_golden': reference['manual_golden']}
    receipt['status'] = 'pass'
    save()
    print(json.dumps(receipt), flush=True)
except Exception as error:
    receipt['status'] = 'fail'
    receipt['error'] = str(error)
    save()
    print(json.dumps({'status': 'fail', 'error': str(error)}), flush=True)
    raise
