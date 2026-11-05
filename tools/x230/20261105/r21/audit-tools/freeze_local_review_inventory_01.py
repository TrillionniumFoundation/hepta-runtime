#!/usr/bin/env python3
"""Freeze exact closed local evidence paths; the packager never selects by glob."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUB = ROOT / 'r21/publication'
draft = json.loads((PUB / 'publication-selector-draft-02.json').read_bytes())
rows = {r['archive_member']: r for r in draft['local_review_bundle_inputs']}
excluded = []

def identity(path):
    b = path.read_bytes()
    return {'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob_sha1':hashlib.sha1(('blob ' + str(len(b)) + '\0').encode() + b).hexdigest()}

def add(path):
    path = path.absolute()
    assert path.resolve() == path and path.is_file() and not path.is_symlink()
    name = str(path.relative_to(ROOT))
    row = {'archive_member':name,'source':str(path),'identity':identity(path)}
    if name in rows:
        assert rows[name] == row, ('original review input changed', name)
    else:
        rows[name] = row

def omit(path, reason):
    excluded.append({'path':str(path.relative_to(ROOT)),'reason':reason})

for row in list(rows.values()):
    assert identity(Path(row['source'])) == row['identity']

# These directories are closed: their owning agents explicitly stopped all
# remote work and local writers before this inventory was produced. Enumeration
# happens once here; only the exact resulting rows reach the archive builder.
closed_dirs = [
    'r21/observations', 'r21/evidence-operations', 'r21/evidence-tools',
    'r21/campaign-replay-01', 'r21/campaign-metrics-01', 'r21/campaign-metrics-02',
    'r21/actual-qualification-01', 'r21/audit-harness/review',
    'r21/audit-harness/mac-evidence-tools', 'r21/publication-verification',
    'r21/publication/drafts', 'r21/publication/reviews',
]
for rel in closed_dirs:
    for path in sorted((ROOT / rel).rglob('*')):
        if not path.is_file():
            continue
        if '__pycache__' in path.parts:
            omit(path, 'Generated interpreter cache; not source evidence.')
        elif rel == 'r21/evidence-operations' and ('-binary-' in path.name and path.suffix in {'.bin','.json'} and not path.name.endswith('.receipt.json')):
            omit(path, 'Successful duplicate transport payload; exact decoded receipt and transfer metadata are retained.')
        elif rel == 'r21/evidence-operations' and path.name in {'evidence-tools-payload-01.json','evidence-tools-transport-01.json'}:
            omit(path, 'Duplicate successful source transport payload; installed source and identity receipts are retained.')
        else:
            add(path)

for rel in ['r20/audit-python/r21-qualification-download-01', 'r21/audit-harness/mac-holder-download-01']:
    base = ROOT / rel
    for path in sorted(base.iterdir()):
        if path.is_file() and not path.name.endswith('.tar.gz'):
            add(path)
        else:
            omit(path, 'Original raw archive is selected separately; restored tree and successful binary chunks are not duplicated.')
for rel in ['r21/audit-harness/mac-holder-download-01/operations', 'r21/audit-harness/mac-holder-download-01/durable-logs']:
    for path in sorted((ROOT / rel).iterdir()):
        if path.name == 'archive-binary-read-0000.json':
            omit(path, 'Successful base64 copy of separately selected original archive; exact transfer receipt retained.')
        elif path.is_file():
            add(path)
for path in sorted((ROOT / 'r20/audit-python/audit-tools').iterdir()):
    if path.is_file() and 'r21' in path.name:
        add(path)

for rel in [
    'r21/campaign-download-01/archive-file-info-01.response.json',
    'r21/campaign-download-01/download-plan-01.json',
    'r21/campaign-download-01/transfer-receipt-01.json',
    'r21/campaign-download-01/preexport/transfer-receipt-01.json',
    'r21/publication/README.md',
    'r21/publication/docs/X230_OPTIMIZATION_20261105_R21.md',
    'r21/publication/build_local_review_archive_01.py',
    'r21/publication/finalize_selector_01.py',
    'r21/publication/finalize_selector_02.py',
    'r21/publication/close_report_01.py',
    'r21/publication/build_orchestration_01.py',
    'r21/publication/build_orchestration_02.py',
    'r21/publication/freeze_local_review_inventory_01.py',
    'r21/publication/orchestration-build-01.stdout',
    'r21/publication/orchestration-build-01.stderr',
    'r21/publication/orchestration-build-02.stdout',
    'r21/publication/orchestration-build-02.stderr',
    'r21/publication/publication-selector-draft-01.json',
    'r21/publication/publication-selector-draft-02.json',
    'r21/publication/evidence-identities-draft-01.json',
    'r21/publication/evidence-identities-draft-02.json',
    'r21/publication/pr87-before-finalization-01.json',
    'r21/publication/doc-selector-link-closure-02.json',
]:
    add(ROOT / rel)

# Preserve the already pinned static sources and reviews, never archive payloads
# or candidate runtime source entries. Their repository copies remain portable.
for batch in ['supplemental-static-inputs-01.json','supplemental-static-inputs-02.json','closed-inputs-batch-01.json']:
    for row in json.loads((PUB / batch).read_bytes()):
        if not row['repo_path'].endswith('.tar.gz'):
            add(Path(row['source']))

for peer in ['final-report-peer-01.json','final-catalog-peer-01.json']:
    assert (ROOT / 'r21/publication-verification' / peer).exists()
assert 'r20/audit-python/r21-qualification-download-01/raw-replay-01.json' in rows
assert len(draft['local_review_bundle_inputs']) == 98
out = {'schema':'hepta-r21-exact-local-review-inventory/v1','writers_stopped':True,
       'scope':'Exact immutable local reviews, complete offline audit outputs, original failures and transport metadata for R20/R21. Original raw archives are published separately. Root final Git operations are outside this pre-publication archive.',
       'original_required_members_preserved':98,
       'closed_directories_enumerated_once':closed_dirs,
       'exclusions':[
           'No credentials, private keys, agent socket, full environment, ELF/object/rlib payloads.',
           'No original tar archives, restored workload trees, successful binary/base64 payload copies, or duplicate embedded campaign manifest.',
           'Successful transport metadata and all recorded failures are retained; archive payloads independently carry the original bytes.',
           'No final catalog/selector, own archive, or future Git tree/commit/ref receipts, avoiding self-referential hashes.',
           {'omitted_existing_paths':excluded}],
       'files':[rows[k] for k in sorted(rows)]}
target = PUB / 'local-review-inventory-final-01.json'
with target.open('x') as f:json.dump(out,f,sort_keys=True,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps({'path':str(target),'identity':identity(target),'files':len(rows),'payload_bytes':sum(r['identity']['size'] for r in rows.values())}))
