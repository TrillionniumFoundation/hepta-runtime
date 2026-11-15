#!/usr/bin/env python3
"""Read-only validation of exact upstream blobs, final tests and retained demo evidence."""
from pathlib import Path
import hashlib, json, re
root=Path(__file__).resolve().parent
manifest=json.loads((root/'upstream/manifest.json').read_text())
for entry in manifest['files']:
    blob=(root/'upstream'/entry['path']).read_bytes()
    assert hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest()==entry['git_blob_sha1'],entry['path']
    assert hashlib.sha256(blob).hexdigest()==entry['sha256'],entry['path']
text=(root/'evidence/final-tests.log').read_text()
m=re.search(r'test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;',text)
assert m,'tests have no successful terminal result'
r=json.loads((root/'evidence/demo-final/report.json').read_text())
assert r['gradient_steps']==0 and not r['production_eligible'] and not r['live_checkpoint_modified']
results={v['case']:v for v in r['results']}
assert results['known_repair']['outcome']['accepted']
for name in ['quality_rejection','regression_rejection']:
    out=results[name]['outcome'];assert not out['accepted'] and out['rollback_verified']
    assert out['pointer_before']==out['pointer_after']
    assert 'reuse refused' in results[name]['replay_refusal']
assert all(x['base_still_exact'] for x in r['results'])
print(json.dumps({'source_commit':manifest['source_commit'],'exact_upstream_files':len(manifest['files']),
                  'tests_passed':int(m.group(1)),'tests_ignored':int(m.group(2)),
                  'synthetic_cases_verified':len(results),'production_eligible':False},indent=2))
