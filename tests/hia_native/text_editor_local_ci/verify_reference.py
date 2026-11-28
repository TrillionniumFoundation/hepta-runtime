"""Check the current target's original bytes in the actual gateway build."""
from pathlib import Path
import hashlib, json
EXPECTED_MANIFEST = 'caf24ffdb56dfaeca473eb625d4330e2b68013e1aa6f35e58cc23a13a301167f'
TARGET = 'd3d75c30719db966b004756f610007a7c723729e'
TREE = '612e145513961556ac8844b5cc978f9b5175e4d4'

def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())

def verify(reference):
    reference = Path(reference)
    manifest_raw = (reference/'source_manifest.json').read_bytes()
    assert hashlib.sha256(manifest_raw).hexdigest() == EXPECTED_MANIFEST
    manifest = json.loads(manifest_raw)
    assert (manifest['target_commit'],manifest['target_tree']) == (TARGET,TREE)
    actual = {str(p.relative_to(reference)) for p in reference.rglob('*') if p.is_file()}
    assert actual == set(manifest['files']) | {'source_manifest.json'}
    for name,pin in manifest['files'].items():
        assert identity((reference/name).read_bytes()) == pin, name
    for name,pin in manifest['target_files'].items():
        assert identity((reference/'target'/name).read_bytes()) == pin, name
    assert len(manifest['exact_original_items']) == 106
    for item in manifest['exact_original_items']:
        original = (reference/'target'/item['target']).read_bytes()[item['start']:item['end']]
        assert identity(original) == {k:item[k] for k in ('bytes','sha256','git_blob')}
        assert item['compiled_spans']
        for span in item['compiled_spans']:
            assert span['container'].startswith('src/')
            raw = (reference/span['container']).read_bytes()
            assert raw[span['included_start']:span['included_end']] == original
    main = (reference/'src/main.rs').read_text()
    for unit in ['original_core.rs','original_text_editing.rs','original_dispatch.rs','original_gateway.rs',
                 'original_line_hash.rs','history_observer.rs','lock_observer.rs']:
        assert main.count('include!("'+unit+'")') == 1, unit
    assert 'outside this Local Create attachment domain' not in main
    assert manifest['admitted_body_commands'] == ['create','str_replace','delete','undo_edit']
    return dict(status='EXACT_GATEWAY_LOCAL_REFERENCE_SOURCE_PASS', target_commit=TARGET,
        target_files=len(manifest['target_files']), original_items=106,
        public_handler_qualified=False,whole_runtime_replaced=False)

if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent/'reference-v1'),sort_keys=True))
