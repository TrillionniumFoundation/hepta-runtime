#!/usr/bin/env python3
"""Install only the separately frozen binding-only native driver, create-only."""
import hashlib,json,os,sys
from pathlib import Path
DEST=Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a54-six-host-driver-r01')
EXPECTED = {'run_a54_native_validation_r01.py': '823bf314e4e845cd1c5382bd123cda0d4507eba6306a13d27db5360e85e6f8b6', 'binding.json': 'cd287cdb9ba0a4f4098c145389fadda1ed1cb5da207f07dca5a7b40b5cc08877'}
raw=sys.stdin.buffer.read(1024*1024+1)
assert len(sys.argv)==2 and len(raw)<=1024*1024 and hashlib.sha256(raw).hexdigest()==sys.argv[1]
bundle=json.loads(raw)
assert bundle['schema']=='hepta-a54-six-host-driver-install/v1'
assert os.getuid()==1000 and DEST.parent==DEST.parent.resolve(strict=True) and DEST.parent.stat().st_uid==1000
assert not os.path.lexists(DEST) and len(bundle['files'])==2 and {r['path'] for r in bundle['files']}==set(EXPECTED)
for row in bundle['files']:
    body=row['content'].encode('utf-8')
    assert len(body)==row['bytes'] and row['sha256']==hashlib.sha256(body).hexdigest()==EXPECTED[row['path']]
os.umask(0o077);DEST.mkdir(mode=0o700)
for row in bundle['files']:
    fd=os.open(DEST/row['path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(row['content'].encode('utf-8'));stream.flush();os.fsync(stream.fileno())
for directory in (DEST,DEST.parent):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print(json.dumps({'created':str(DEST),'files':2,'bundle_sha256':hashlib.sha256(raw).hexdigest(),
                  'business_launches':0,'network_connections':0},sort_keys=True))
