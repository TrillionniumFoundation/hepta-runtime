#!/usr/bin/env python3
"""Create the one fresh X230 lease-source directory from a root-pinned bundle."""
import hashlib,json,os,sys
from pathlib import Path
DEST=Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a53-six-host-lease-tools-r01')
NAMES={'custody.py','remote_supervisor.py','main_supervisor.py','run_remote_supervisor.py','run_main_lease.py',
       'selfcheck.py','freeze_plan.py','package-manifest.json','plan.template.json','PROTOCOL.md'}
raw=sys.stdin.buffer.read(1024*1024+1)
assert len(sys.argv)==2 and len(raw)<=1024*1024 and hashlib.sha256(raw).hexdigest()==sys.argv[1]
bundle=json.loads(raw)
assert bundle['schema']=='hepta-six-host-lease-source-bundle/v1' and os.getuid()==1000
assert DEST.parent==DEST.parent.resolve(strict=True) and DEST.parent.stat().st_uid==1000 and not os.path.lexists(DEST)
assert len(bundle['files'])==len(NAMES) and {f['path'] for f in bundle['files']}==NAMES
for row in bundle['files']:
    data=row['content'].encode();assert row['encoding']=='utf-8' and len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
os.umask(0o077);DEST.mkdir(mode=0o700)
for row in bundle['files']:
    fd=os.open(DEST/row['path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(row['content'].encode());stream.flush();os.fsync(stream.fileno())
for path in (DEST,DEST.parent):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print(json.dumps({'created':str(DEST),'files':len(NAMES),'bundle_sha256':hashlib.sha256(raw).hexdigest(),
                  'ssh_connections':0,'agent_queries':0,'business_launches':0},sort_keys=True))
