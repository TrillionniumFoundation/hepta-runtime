"""Verify complete target files and every unchanged extracted Rust item."""
from pathlib import Path
import hashlib
import json
import tomllib

HERE = Path(__file__).resolve().parent
REFERENCE_FILES = ('reference/Cargo.lock', 'reference/Cargo.toml', 'reference/src/cache_observer.rs', 'reference/src/history_observer.rs', 'reference/src/lock_observer.rs', 'reference/src/main.rs', 'reference/src/original_core.rs', 'reference/src/original_delta.rs', 'reference/src/original_line_hash.rs', 'reference/src/original_remote.rs', 'reference/src/original_request_ctx.rs', 'reference/src/original_sftp_unavailable.rs', 'reference/src/original_text_editing.rs', 'reference/target/Cargo.lock', 'reference/target/Cargo.toml', 'reference/target/src/mcp/fs/core.rs', 'reference/target/src/mcp/fs/delta.rs', 'reference/target/src/mcp/fs/remote.rs', 'reference/target/src/mcp/fs/remote_unavailable.rs', 'reference/target/src/mcp/fs/text_editing.rs', 'reference/target/src/mcp/request_ctx.rs', 'reference/target/src/utils/line_hash.rs')
TARGET_COMMIT = 'd3d75c30719db966b004756f610007a7c723729e'
TARGET_TREE = '612e145513961556ac8844b5cc978f9b5175e4d4'
TARGET_BLOBS = {
    'Cargo.toml': 'af0960b6ad360f26589de66e26cdcabe2fb3266f',
    'Cargo.lock': '23768e4ae7b4ba44d568134e91476b1c82069887',
    'src/mcp/fs/core.rs': '0bf273858281618f51792c5663494f6ba37645ed',
    'src/mcp/fs/text_editing.rs': '4a8114e72a51238608201e108288294c6282ab20',
    'src/mcp/fs/remote.rs': 'cb53bc65bd966d405b8313c06fc13ea381df6293',
    'src/mcp/fs/remote_unavailable.rs': '90594fa08e7e580dae135200ef0c685083470a17',
    'src/mcp/fs/delta.rs': '76681c01b571536e80f5bd1b93d79053d9df8985',
    'src/mcp/request_ctx.rs': '0150c07b2d7ac593851c30557f71c628083d083b',
    'src/utils/line_hash.rs': '0e521656ba24869dbc05afc51d62aa4af79b5e44',
}
DECLARATIONS = {'src/original_core.rs': ['const MAX_HISTORY_PER_FILE:',
                          'const MAX_HISTORY_TOTAL_BYTES:',
                          '#[derive(Default)]\nstruct HistoryStore',
                          'impl HistoryStore',
                          'static FILE_HISTORY:',
                          'fn file_history(',
                          'pub async fn save_file_history(',
                          'pub async fn undo_edit('],
 'src/original_delta.rs': ['const MAX_CACHED_BYTES:',
                           '#[derive(Debug, Default)]\npub struct ViewCache',
                           'impl ViewCache',
                           'fn normalize(',
                           'pub fn note_write(',
                           'pub fn forget(',
                           'pub fn removed_marker('],
 'src/original_line_hash.rs': ['fn fnv1a_8(',
                               'pub fn line_hash(',
                               'pub fn line_id(',
                               'pub fn line_id_at('],
 'src/original_remote.rs': ['#[derive(Debug, Clone)]\npub enum PathSource',
                            'impl PathSource',
                            '#[derive(Debug, Clone)]\npub struct RemoteMetadata',
                            '#[derive(Debug, Clone)]\npub struct IoMetadata',
                            'pub async fn io_read_to_string(',
                            'pub async fn io_write(',
                            'pub async fn io_exists(',
                            'pub async fn io_metadata(',
                            'pub async fn io_remove_file('],
 'src/original_request_ctx.rs': ['struct RequestContext',
                                 'tokio::task_local!',
                                 'pub async fn with_request_context',
                                 'pub fn with_view_cache',
                                 'pub fn push_hint(',
                                 'pub fn drain_hints('],
 'src/original_sftp_unavailable.rs': ['fn unavailable(',
                                      'pub async fn remote_read_to_string(',
                                      'pub async fn remote_write(',
                                      'pub async fn remote_exists(',
                                      'pub async fn remote_metadata(',
                                      'pub async fn remote_remove_file('],
 'src/original_text_editing.rs': ['static FILE_LOCKS:',
                                  'fn get_file_locks(',
                                  'pub fn lock_key_for(',
                                  'pub fn lock_key_for_source(',
                                  'const LOCK_MAP_SWEEP_THRESHOLD:',
                                  'pub(crate) async fn acquire_file_lock(',
                                  'pub async fn delete_file_spec(',
                                  'fn normalize_whitespace(',
                                  'fn find_all_positions(',
                                  'fn byte_offset_to_line(',
                                  'fn similarity_ratio(',
                                  'fn line_similarity(',
                                  'fn lcs_length(',
                                  'fn diagnose_mismatch(',
                                  'fn find_closest_matches(',
                                  'fn detect_indent(',
                                  'fn adjust_indentation(',
                                  'fn build_str_replace_diff(',
                                  'pub(crate) fn shift_note(',
                                  'pub async fn atomic_write(',
                                  'const LF_ENDING:',
                                  'const CRLF_ENDING:',
                                  '#[derive(Clone)]\nstruct EditableLine',
                                  '#[derive(Clone)]\npub(crate) struct EditableContent',
                                  'impl EditableContent',
                                  'fn lines_with_ending(',
                                  'fn incoming_content_lines(',
                                  'fn sanitize_incoming_content(',
                                  'fn unescape_literals(',
                                  'async fn apply_unique_replacement(',
                                  'async fn apply_replace_all(',
                                  'pub async fn str_replace_spec(',
                                  'const ECHO_WHOLE_MAX:',
                                  'fn push_added_lines(']}


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def verify(root=HERE):
    root = Path(root)
    reference = root / 'reference'
    manifest = json.loads((root / 'source-extraction.json').read_bytes())
    assert manifest['schema'] == 'hepta.runtime.local-text-body-original-extraction.v1'
    assert (manifest['target_commit'], manifest['target_tree']) == (TARGET_COMMIT, TARGET_TREE)
    assert set(manifest['source_files']) == set(TARGET_BLOBS)
    targets = {}
    for name, expected in TARGET_BLOBS.items():
        raw = (reference / 'target' / name).read_bytes()
        observed = identity(raw)
        assert observed['git_blob'] == expected
        assert manifest['source_files'][name] == dict(path=name, **observed)
        targets[name] = raw
    assert len(manifest['units']) == len(DECLARATIONS) == 7
    assert {unit['path'] for unit in manifest['units']} == set(DECLARATIONS)
    count = 0
    for unit in manifest['units']:
        raw = (reference / unit['path']).read_bytes()
        assert {key: unit[key] for key in ('bytes', 'sha256', 'git_blob')} == identity(raw)
        assert [row['declaration'] for row in unit['items']] == DECLARATIONS[unit['path']]
        previous = 0
        for row in unit['items']:
            source = targets[row['target']]
            original = source[row['start']:row['end']]
            included = raw[row['included_start']:row['included_end']]
            assert row['included_start'] >= previous and included == original
            assert original.startswith(row['declaration'].encode())
            if row['kind'] == 'statement':
                assert row['declaration'].startswith(('const ', 'static ')) and original.endswith(b';\n')
            else:
                assert row['kind'] == 'brace_item' and original.endswith(b'}\n')
            assert {key: row[key] for key in ('bytes', 'sha256', 'git_blob')} == identity(original)
            previous = row['included_end']
            count += 1
    assert count == 74
    for name, expected in manifest['cargo'].items():
        assert identity((reference / name).read_bytes()) == expected
    cargo = tomllib.loads((reference / 'Cargo.toml').read_text())
    assert cargo['package']['name'] == 'hepta-local-text-body-original-oracle'
    assert cargo['package']['edition'] == '2021' and cargo['package']['rust-version'] == '1.95'
    assert cargo['dependencies'] == {'anyhow': '=1.0.104',
        'tokio': {'version': '=1.53.3', 'features': ['rt', 'fs', 'io-util', 'sync']}}
    assert cargo['features'] == {'remote-fs': []} and cargo['workspace'] == {}
    lock = tomllib.loads((reference / 'Cargo.lock').read_text())
    assert len(lock['package']) == 5
    target_packages = {package['name']: package for package in tomllib.loads(targets['Cargo.lock'].decode())['package']
                       if package['name'] in ('anyhow', 'bytes', 'pin-project-lite', 'tokio')}
    registry = []
    for package in lock['package']:
        if 'source' not in package:
            assert package == dict(name='hepta-local-text-body-original-oracle', version='0.1.0',
                                   dependencies=['anyhow', 'tokio'])
        else:
            fields = {key: package[key] for key in ('name', 'version', 'source', 'checksum')}
            assert fields == {key: target_packages[package['name']][key] for key in fields}
            if package['name'] == 'tokio': assert package['dependencies'] == ['bytes', 'pin-project-lite']
            registry.append(fields)
    assert sorted(registry, key=lambda row: row['name']) == manifest['registry']
    main = (reference / 'src/main.rs').read_bytes()
    for name in DECLARATIONS:
        expected = 0 if name.endswith('original_sftp_unavailable.rs') else 1
        assert main.count(('include!("' + Path(name).name + '")').encode()) == expected
    for call in (b'text_editing::str_replace_spec(source, old, new, replace_all)',
                 b'text_editing::delete_file_spec(source)', b'core::undo_edit(source)'):
        assert main.count(call) == 1
    assert b'with_request_context(cache.clone(), body)' in main
    return dict(status='EXACT_LOCAL_TEXT_BODY_REFERENCE_SOURCE_PASS', target_commit=TARGET_COMMIT,
        target_tree=TARGET_TREE, exact_original_items=count, target_files=len(targets), target_tokio='1.53.3',
        actual_reference_execution=False, public_handler_qualified=False, whole_runtime_replaced=False,
        files={name: identity((root / name).read_bytes()) for name in REFERENCE_FILES})


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True, indent=2))
