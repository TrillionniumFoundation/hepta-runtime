#!/usr/bin/env python3
"""Read-only identity and source-closure checks; no Rust or HIA execution."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import tomllib


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(root):
    root = Path(root).resolve(strict=True)
    manifest = json.loads((root / 'source-manifest.json').read_bytes())
    assert manifest['schema'] == 'hepta.g5.ninth-catalog-source-recipe.v2'
    expected = set(manifest['files']) | {'source-manifest.json'}
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    assert actual == expected, (sorted(expected - actual), sorted(actual - expected))
    python_count = 0
    for relative, row in manifest['files'].items():
        rel = Path(relative)
        assert not rel.is_absolute() and '..' not in rel.parts
        path = root / rel
        assert path.is_file() and not path.is_symlink(), relative
        raw = path.read_bytes()
        assert row['bytes'] == len(raw) and row['sha256'] == sha(raw), relative
        if path.suffix == '.py':
            ast.parse(raw, filename=relative)
            python_count += 1
    deps = json.loads((root / 'ci/dependencies.json').read_bytes())
    assert deps['original_target']['commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    for relative, row in deps['original_target']['files'].items():
        raw = (root / 'target' / relative).read_bytes()
        assert row == {'bytes': len(raw), 'sha256': sha(raw)}, relative
    assert deps['original_target']['files']['Cargo.lock']['sha256'] == '1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
    fragment_proof = json.loads((root / 'source-pins/metadata-fragments.json').read_bytes())
    original = (root / 'target/src/mcp/server.rs').read_bytes()
    fixture = (root / 'oracle/original_metadata.rs').read_bytes()
    assert sha(original) == fragment_proof['source_sha256']
    assert sha(fixture) == fragment_proof['metadata_fixture_sha256']
    for row in fragment_proof['fragments']:
        raw = (root / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
        assert original.count(raw) == 1 and fixture.count(raw) == 1, row['name']
        assert original[row['original_byte_start']:row['original_byte_end']] == raw
    assert b'panic!("metadata-only fixture: original filesystem method must never execute")' in fixture
    main = (root / 'oracle/main.rs').read_text()
    includes = re.findall(r'include!\("([^"\n]+)"\)', main)
    assert includes == ['original_metadata.rs']
    for relative in includes:
        assert (root / 'oracle' / relative).is_file()
    assert 'MetadataOnlyServer::text_editor_tool_attr()' in main
    assert '.text_editor(' not in main
    assert 'schema_for_input::<TextEditorParams>()?' in main
    assert 'strip_result_type_for_legacy_peer()' in main
    assert 'fill_missing_cache_hints()' in main
    project = tomllib.loads((root / 'oracle/Cargo.toml').read_text())
    assert project['package']['name'] == 'g5-target-text-editor-catalog-oracle'
    assert project['dependencies']['rmcp']['version'] == '=3.9.0'
    assert set(project['dependencies']['rmcp']['features']) == {'server', 'macros'}
    assert project['dependencies']['schemars'] == '=1.2.2'
    assert not (root / 'oracle/Cargo.lock').exists()
    sdk = json.loads((root / 'source-pins/sdk-source.json').read_bytes())
    for row in sdk['files']:
        raw = (root / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
        assert row['commit'] == '5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc'
    common = (root / 'sdk-source/rmcp-common.rs').read_text()
    assert 'pub fn schema_for_input<T: JsonSchema + std::any::Any>() -> Result<Arc<JsonObject>, String>' in common
    for row in deps['native_modules']:
        raw = (root / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['source_sha256']
    for relative, row in json.loads((root / 'source-pins/reused-sources.json').read_bytes()).items():
        raw = (root / relative).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256'], relative
    tools = json.loads((root / 'cases/public-eight-tools.json').read_bytes())
    assert len(tools) == 8
    assert [tool['name'] for tool in tools] == [
        'host_list', 'effective_config', 'execution_shadow_admit', 'view',
        'workdir', 'directory_create', 'file_move', 'directory_move']
    assert all(tool['name'] != 'text_editor' for tool in tools)
    return {'status': 'SOURCE_CHECK_PASS', 'source_files': len(manifest['files']),
            'python_ast_checked': python_count, 'original_fragments_checked': 3,
            'rust_literal_include_edges_checked': len(includes),
            'rust_type_check_executed': False, 'rust_or_hia_executed': False,
            'ninth_schema_generated': False, 'public_route_registered': False,
            'full_sdk_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), sort_keys=True))


if __name__ == '__main__':
    main()
