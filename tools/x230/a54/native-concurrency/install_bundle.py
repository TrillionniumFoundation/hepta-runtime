#!/usr/bin/env python3
"""Create only this fresh source directory from a root-pinned UTF-8 bundle."""
import hashlib
import json
import os
from pathlib import Path
import sys

DEST = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a54-native-concurrency-tools-r01')
NAMES = {'run_native_concurrency.py','remote_fixture.py','business.py','selfcheck.py',
         'freeze_plan.py','plan.template.json','PROTOCOL.md','native_owner_recovery.py',
         'selfcheck-preparation-results.json'}
raw = sys.stdin.buffer.read(1024*1024+1)
assert len(raw)<=1024*1024 and len(sys.argv)==2 and hashlib.sha256(raw).hexdigest()==sys.argv[1]
bundle = json.loads(raw)
assert bundle['schema']=='hepta-native-concurrency-source-bundle/v1'
assert os.getuid()==1000 and DEST.parent==DEST.parent.resolve(strict=True)
assert DEST.parent.stat().st_uid==os.getuid() and not os.path.lexists(DEST)
assert {row['path'] for row in bundle['files']}==NAMES and len(bundle['files'])==len(NAMES)
for row in bundle['files']:
    data=row['content'].encode('utf-8')
    assert row['encoding']=='utf-8' and len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
os.umask(0o077)
DEST.mkdir(mode=0o700)
for row in bundle['files']:
    data=row['content'].encode('utf-8')
    fd=os.open(DEST/row['path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    assert hashlib.sha256((DEST/row['path']).read_bytes()).hexdigest()==row['sha256']
fd=os.open(DEST,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
fd=os.open(DEST.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'created':str(DEST),'files':len(bundle['files']),
                  'bundle_sha256':hashlib.sha256(raw).hexdigest(),'business_launches':0,
                  'network_connections':0},sort_keys=True),flush=True)
