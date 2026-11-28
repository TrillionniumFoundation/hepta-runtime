"""Static source/dependency checks for the five fixed SDK CI fixtures.

This deliberately bounded Rust module scanner covers the literal mod/include
forms present in these frozen fixtures. It is not a general Rust parser.
No compiler, native image, request, or fixture generator is executed here.
"""
from pathlib import Path
from collections import Counter
import argparse
import ast
import hashlib
import json
import re
import tomllib


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_relative(root, relative):
    rel = Path(relative)
    assert not rel.is_absolute() and '..' not in rel.parts, relative
    path = root / rel
    assert path.is_file() and not path.is_symlink(), relative
    return path


def verify_lock_subset(target_raw, fixture_raw, binary):
    target = {(p['name'], p['version'], p.get('source')): p.get('checksum')
              for p in tomllib.loads(target_raw.decode())['package'] if p.get('source')}
    retained = []
    local = []
    for package in tomllib.loads(fixture_raw.decode())['package']:
        if not package.get('source'):
            local.append(package['name'])
            continue
        key = package['name'], package['version'], package['source']
        assert key in target and package['checksum'] == target[key], key
        assert package['source'].startswith('registry+'), key
        retained.append({k: package[k] for k in ('name', 'version', 'source', 'checksum')})
    assert local == [binary], local
    return retained


def rust_closure(project):
    pending = [project / 'main.rs']
    visited = set()
    while pending:
        path = pending.pop()
        assert path.is_relative_to(project) and path.is_file() and not path.is_symlink(), path
        if path in visited:
            continue
        visited.add(path)
        source = path.read_text()
        assert not re.search(r'#\s*\[\s*path\s*=', source), path
        for name in re.findall(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;', source):
            base = path.parent if path.name in ('main.rs', 'lib.rs', 'mod.rs') else path.parent / path.stem
            choices = [base / (name + '.rs'), base / name / 'mod.rs']
            present = [p for p in choices if p.is_file()]
            assert len(present) == 1, (path, name, choices)
            pending.append(present[0])
        for relative in re.findall(r'\binclude!\s*\(\s*"([^"\n]+)"\s*\)', source):
            rel = Path(relative)
            assert not rel.is_absolute() and '..' not in rel.parts, (path, relative)
            pending.append(path.parent / rel)
    return sorted(str(p.relative_to(project)) for p in visited)


def verify(source):
    source = Path(source).resolve(strict=True)
    manifest = json.loads((source / 'source-manifest.json').read_bytes())
    assert manifest['schema'] == 'hepta.g5.public-source-rebuild-bundle.v1'
    python_files = 0
    for relative, row in manifest['files'].items():
        path = checked_relative(source, relative)
        raw = path.read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256'], relative
        if path.suffix == '.py':
            ast.parse(raw, filename=relative)
            python_files += 1
    deps = json.loads((source / 'ci/dependencies.json').read_bytes())
    assert deps['schema'] == 'hepta.sdk-five-originals.ci-dependencies.v1'
    base_raw = (source / 'ci/frozen-v2-source-manifest.json').read_bytes()
    assert sha(base_raw) == deps['base_recovery_manifest_sha256']
    base = json.loads(base_raw)
    assert len(base['files']) == 185
    for relative, row in base['files'].items():
        assert manifest['files'][relative] == row, relative
    target = (source / 'g5/target/Cargo.lock').read_bytes()
    assert sha(target) == deps['original_target']['cargo_lock_sha256']
    assert sha((source / 'g5/target/src/mcp/server.rs').read_bytes()) == deps['original_target']['server_source_sha256']
    assert [p['id'] for p in deps['rust_projects']] == ['catalog', 'context', 'response', 'transport', 'connection']
    fixtures = []
    for spec in deps['rust_projects']:
        stage = source / spec['root']
        project = stage / spec['project']
        assert not (project / 'Cargo.lock').exists(), 'fixture lock must be derived afresh at execution'
        assert (stage / 'target/Cargo.lock').read_bytes() == target
        cargo = tomllib.loads((project / 'Cargo.toml').read_text())
        assert cargo['package']['name'] == spec['binary']
        assert cargo['bin'] == [{'name': spec['binary'], 'path': 'main.rs'}]
        for name, declaration in cargo['dependencies'].items():
            version = declaration if isinstance(declaration, str) else declaration['version']
            assert version.startswith('=') and (name, version[1:]) in {
                (p['name'], p['version']) for p in tomllib.loads(target.decode())['package']
            }, (spec['id'], name, version)
        closure = rust_closure(project)
        assert closure == sorted(spec['rust_sources']), (spec['id'], closure)
        seed = checked_relative(source, spec['seed_lock']).read_bytes()
        retained = verify_lock_subset(target, seed, spec['binary'])
        fixtures.append({'id': spec['id'], 'binary': spec['binary'], 'rust_sources': closure,
                         'retained_registry_packages': len(retained), 'seed_lock_sha256': sha(seed)})
    pins = json.loads((source / 'source-pins/retained-modules.json').read_bytes())
    for group in ('g4', 'g3'):
        stage = source / pins[group]['root']
        for name, row in pins[group]['members'].items():
            assert sha((stage / row['source']).read_bytes()) == row['source_sha256'], (group, name)
    generated = deps['generated_inputs']
    g3 = source / generated['root']
    assert sha((g3 / generated['generator']).read_bytes()) == generated['generator_sha256']
    case_manifest_raw = (g3 / generated['manifest']).read_bytes()
    assert sha(case_manifest_raw) == generated['manifest_sha256']
    cases = json.loads(case_manifest_raw)
    raw = (g3 / 'cases/normal.jsonl').read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    assert sha(raw) == cases['sha256'] and len(rows) == cases['cases'] == 228
    assert Counter(r['mode'] for r in rows) == cases['modes']
    assert {r['input_file'] for r in rows if 'input_file' in r} == set(cases['files'])
    for relative in cases['files']:
        rel = Path(relative)
        assert not rel.is_absolute() and '..' not in rel.parts and rel.parts[:2] == ('cases', 'inputs')
    assert not (g3 / 'cases/inputs').exists(), 'large inputs are generated only in the execution output'
    g2 = g3 / 'joined-g2'
    session_raw = (g2 / 'cases/normal.jsonl').read_bytes()
    sessions = [json.loads(line) for line in session_raw.splitlines()]
    sessions_manifest = json.loads((g2 / 'cases/manifest.json').read_bytes())
    assert sha(session_raw) == sessions_manifest['sha256'] and len(sessions) == sessions_manifest['sessions'] == 67
    assert sum(len(s['events']) for s in sessions) == sessions_manifest['events']
    for case in sessions:
        for event in case['events']:
            request = json.loads(event['wire'])
            assert request['method'] in {'server/discover', 'initialize', 'ping', 'notifications/initialized', 'completion/complete'}
            assert '\n' not in event['wire']
    return {'status': 'SOURCE_DEPENDENCY_CHECK_PASS', 'files': len(manifest['files']),
            'python_ast_files': python_files, 'rust_projects': fixtures,
            'generated_input_files': len(cases['files']),
            'generated_input_bytes': sum(r['bytes'] for r in cases['files'].values()),
            'base_185_files_unchanged': True, 'native_or_rust_executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), sort_keys=True))


if __name__ == '__main__':
    main()
