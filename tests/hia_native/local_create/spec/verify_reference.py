"""Verify byte-exact production items and the migration target dependency lock."""
from pathlib import Path
import hashlib
import json
import tomllib

HERE = Path(__file__).resolve().parent
TARGET_COMMIT = '737acf6f901e46c57b0b4374e323e0d1132e0d49'
TARGET_BLOBS = {
    'Cargo.toml': 'af0960b6ad360f26589de66e26cdcabe2fb3266f',
    'Cargo.lock': '23768e4ae7b4ba44d568134e91476b1c82069887',
    'src/mcp/fs/file_ops.rs': '89150932e15439f2a0f35e0c73284e1f8ab56520',
    'src/mcp/fs/remote.rs': 'cb53bc65bd966d405b8313c06fc13ea381df6293',
    'src/mcp/fs/remote_unavailable.rs': '90594fa08e7e580dae135200ef0c685083470a17',
    'src/mcp/fs/delta.rs': '76681c01b571536e80f5bd1b93d79053d9df8985',
    'src/mcp/fs/text_editing.rs': '4a8114e72a51238608201e108288294c6282ab20',
    'src/mcp/request_ctx.rs': '0150c07b2d7ac593851c30557f71c628083d083b',
}
DECLARATIONS = {
    'src/original_remote.rs': ['#[derive(Debug, Clone)]\npub enum PathSource', 'impl PathSource',
        'pub async fn io_exists', 'pub async fn io_create_dir_all', 'pub async fn io_write'],
    'src/original_sftp_unavailable.rs': ['fn unavailable', 'pub async fn remote_exists',
        'pub async fn remote_create_dir_all', 'pub async fn remote_write'],
    'src/original_text_editing.rs': ['pub fn lock_key_for(', 'pub fn lock_key_for_source('],
    'src/original_delta.rs': ['#[derive(Debug, Default)]\npub struct ViewCache', 'impl ViewCache',
        'fn normalize(', 'pub fn note_create('],
    'src/original_request_ctx.rs': ['struct RequestContext', 'tokio::task_local!',
        'pub async fn with_request_context', 'pub fn with_view_cache'],
    'src/original_file_ops.rs': ['async fn create_local_file', 'pub async fn create_file_spec'],
}


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def verify(root=HERE):
    root = Path(root)
    reference = root / 'reference'
    manifest = json.loads((root / 'source-extraction.json').read_bytes())
    assert manifest['schema'] == 'hepta.runtime.local-create-spec-original-extraction.v1'
    assert manifest['target_commit'] == TARGET_COMMIT
    assert set(manifest['source_files']) == set(TARGET_BLOBS)
    targets = {}
    for name, wanted_blob in TARGET_BLOBS.items():
        raw = (reference / 'target' / name).read_bytes()
        found = identity(raw)
        assert found['git_blob'] == wanted_blob
        assert manifest['source_files'][name] == dict(path=name, **found)
        targets[name] = raw
    assert len(manifest['units']) == len(DECLARATIONS) == 6
    assert {unit['path'] for unit in manifest['units']} == set(DECLARATIONS)
    item_count = 0
    for unit in manifest['units']:
        raw = (reference / unit['path']).read_bytes()
        assert {key: unit[key] for key in ('bytes', 'sha256', 'git_blob')} == identity(raw)
        assert [row['declaration'] for row in unit['items']] == DECLARATIONS[unit['path']]
        last_end = 0
        for row in unit['items']:
            source = targets[row['target']]
            original = source[row['start']:row['end']]
            included = raw[row['included_start']:row['included_end']]
            assert row['included_start'] >= last_end and included == original
            assert {key: row[key] for key in ('bytes', 'sha256', 'git_blob')} == identity(original)
            assert original.startswith(row['declaration'].encode()) and original.endswith(b'}\n')
            last_end = row['included_end']
            item_count += 1
            if row['declaration'] == 'async fn create_local_file':
                assert row['bytes'] == 242
                assert row['sha256'] == 'c0b4807c4ba4ebd00a41987cbfb95d802f17ab391802314f6fdcc6e685aa22fc'
    assert item_count == 21
    constants = manifest['exact_constants']
    assert len(constants) == 1
    constant = constants[0]
    literal = constant['literal'].encode()
    assert literal == b'const MAX_CACHED_BYTES: usize = 1024 * 1024;'
    assert targets[constant['target']].count(literal) == 1
    assert (reference / 'src/original_delta.rs').read_bytes().count(literal) == 1
    assert {key: constant[key] for key in ('bytes', 'sha256', 'git_blob')} == identity(literal)
    for name, expected in manifest['cargo'].items():
        assert identity((reference / name).read_bytes()) == expected
    cargo = tomllib.loads((reference / 'Cargo.toml').read_text())
    assert cargo['dependencies'] == {'anyhow': '=1.0.104',
        'tokio': {'version': '=1.53.3', 'features': ['rt', 'fs', 'io-util']}}
    assert cargo['features'] == {'remote-fs': []}
    lock = tomllib.loads((reference / 'Cargo.lock').read_text())
    assert len(lock['package']) == 5
    target_packages = {p['name']: p for p in tomllib.loads(targets['Cargo.lock'].decode())['package']
                       if p['name'] in ('anyhow', 'bytes', 'pin-project-lite', 'tokio')}
    registry = []
    for package in lock['package']:
        if 'source' not in package:
            assert package == dict(name='hepta-local-create-spec-original-oracle', version='0.1.0',
                                   dependencies=['anyhow', 'tokio'])
            continue
        fields = {key: package[key] for key in ('name', 'version', 'source', 'checksum')}
        assert fields == {key: target_packages[package['name']][key] for key in fields}
        if package['name'] == 'tokio':
            assert package['dependencies'] == ['bytes', 'pin-project-lite']
        registry.append(fields)
    assert sorted(registry, key=lambda x: x['name']) == manifest['registry']
    main = (reference / 'src/main.rs').read_bytes()
    for name in DECLARATIONS:
        assert main.count(('include!("' + Path(name).name + '")').encode()) == (0 if name.endswith('original_sftp_unavailable.rs') else 1)
    assert main.count(b'mcp::fs::file_ops::create_file_spec(&source, &content)') == 2
    assert b'async fn create_local_file' not in main and b'pub async fn create_file_spec' not in main
    assert b'with_request_context(context_cache,' in main
    return dict(status='EXACT_LOCAL_SPEC_REFERENCE_SOURCE_PASS', target_commit=TARGET_COMMIT,
        exact_original_items=item_count, target_files=len(TARGET_BLOBS), target_tokio='1.53.3',
        actual_reference_execution=False, public_handler_qualified=False,
        full_create_file_spec_qualified=False, whole_runtime_replaced=False,
        files={str(p.relative_to(root)): identity(p.read_bytes()) for p in sorted(reference.rglob('*'))
               if p.is_file()})


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True, indent=2))
