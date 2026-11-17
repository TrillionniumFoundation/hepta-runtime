"""Retire only the complete original expansion after comparison with the kept final archive."""
from pathlib import Path
import hashlib
import json
import shutil
import stat
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
VICTIM = Path('/tmp/audit-lifetime-c690-evidence')
assert VICTIM.resolve(strict=True) == VICTIM
kept = ROOT / 'complete-native-owner.zip'
with kept.open('rb') as stream:
    assert hashlib.file_digest(stream,'sha256').hexdigest() == '84a4575033e5105ea7a66340f2ed682e0936697a669b3e153b59b0c0baa72a9a'
readback = json.loads((ROOT / 'complete-native-owner-readback.json').read_bytes())
assert readback['all_complete_object_bytes_and_modes'] and readback['all_original_1860_files_unchanged'] if 'all_original_1860_files_unchanged' in readback else readback['original_1860_files_unchanged']
raw = None
with zipfile.ZipFile(kept) as z,z.open('audit-lifetime-recovery.tar.gz') as stream,tarfile.open(fileobj=stream,mode='r|gz') as tar:
    while member := tar.next():
        if member.name == 'artifact-manifest.json':
            raw = tar.extractfile(member).read()
            break
        tar.members.clear()
assert raw is not None and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) == readback['archive_manifest']
files = json.loads(raw)['files']
observed = {}
for path in sorted(VICTIM.rglob('*')):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        continue
    name = path.relative_to(VICTIM).as_posix()
    with path.open('rb') as source:
        digest = hashlib.file_digest(source,'sha256').hexdigest()
    after = path.lstat()
    assert (info.st_mode,info.st_size,info.st_ino,info.st_mtime_ns,info.st_ctime_ns) == (after.st_mode,after.st_size,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)
    row = dict(bytes=info.st_size,sha256=digest,mode=stat.S_IMODE(info.st_mode))
    assert row == {k:files['evidence/producer/' + name][k] for k in ('bytes','sha256','mode')}
    observed[name] = row
original = json.loads((VICTIM / 'artifact-manifest.json').read_bytes())
expected = dict(original['files'])
value = (VICTIM / 'artifact-manifest.json').read_bytes()
expected['artifact-manifest.json'] = dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest(),mode=0o644)
assert observed == expected and len(observed) == 1860
assert sum(row['bytes'] for row in observed.values()) == 505680659
receipt = dict(schema='hepta.audit-lifetime.verified-duplicate-retirement.v1',victim=str(VICTIM),
               kept=str(kept),kept_zip_sha256=readback['zip']['sha256'],files=observed,
               complete_kept_archive_read=True,all_duplicate_bytes_and_modes_equal=True,
               deleted=False,semantic_executions=0,whole_runtime_replaced=False)
record = ROOT / 'verified-expansion-retirement.json'
assert not record.exists()
record.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
shutil.rmtree(VICTIM)
assert not VICTIM.exists() and kept.is_file()
receipt['deleted'] = True
record.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(deleted=True,files=len(observed),bytes=505680659,kept_zip_sha256=readback['zip']['sha256'])))
