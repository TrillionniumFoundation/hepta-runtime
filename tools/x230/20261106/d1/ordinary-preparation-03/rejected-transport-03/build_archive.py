from pathlib import Path
import ast,gzip,hashlib,io,json,tarfile
root=Path('/tmp/hepta-runtime-recovery-20261106')
sealed=root/'d1-ordinary-sealed-03'
out=root/'d1-ordinary-transport-03'
out.mkdir(mode=0o700,exist_ok=False)
mapping={
 'tools/launch_ordinary_02.py':'ordinary-tools-02/launch_ordinary_02.py',
 'tools/qualify_ordinary_02.py':'ordinary-tools-02/qualify_ordinary_02.py',
 'tools/verify_ordinary_02.py':'ordinary-tools-02/verify_ordinary_02.py',
 'tools/package-manifest-02.json':'ordinary-tools-02/package-manifest-02.json',
 'ordinary-prerequisites-02.json':'ordinary-prerequisites-02.json',
 'actual-seal-request.json':'ordinary-seal-request-02.json',
 'seal-manifest.json':'ordinary-seal-manifest-02.json',
 'launch-command.json':'ordinary-launch-command-02.json',
}
def ident(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
members={}
for source,target in mapping.items():
 b=(sealed/source).read_bytes()
 if source.endswith('.py'):ast.parse(b)
 members[target]=b
additional={
 'full-prerequisites-03/d1_prerequisites.py':root/'d1-ordinary-supplement-preparation-03/full-prerequisites-03/d1_prerequisites.py',
 'ordinary-preflight-failure-01/native.json':root/'d1-ordinary-supplement-preparation-03/prior-failure/native.json',
 'ordinary-preflight-failure-01/read-000.json':root/'d1-ordinary-supplement-preparation-03/prior-failure/read-000.json',
 'ordinary-preflight-failure-01/start.json':root/'d1-ordinary-supplement-preparation-03/prior-failure/start.json',
}
for name,path in additional.items():
 b=path.read_bytes()
 if name.endswith('.py'):ast.parse(b)
 members[name]=b
manifest={'schema':'hepta-d1-ordinary-deployment/v3','root':'/home/qian/hepta-runtime-phase-cost-20261106-d1',
 'file_count_excluding_manifest':len(members),'files':[dict(path=name,**ident(body)) for name,body in sorted(members.items())],
 'ordinary_executed':False,'compiler_started':False,'performance_acceptance_claim':False}
mb=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
members['ordinary-deployment-manifest-02.json']=mb
plain=io.BytesIO()
with tarfile.open(fileobj=plain,mode='w',format=tarfile.USTAR_FORMAT) as tar:
 for name,body in sorted(members.items()):
  ti=tarfile.TarInfo(name);ti.size=len(body);ti.mode=0o600;ti.mtime=0;ti.uid=ti.gid=0
  tar.addfile(ti,io.BytesIO(body))
compressed=io.BytesIO()
with gzip.GzipFile(fileobj=compressed,mode='wb',mtime=0,filename='') as gz:gz.write(plain.getvalue())
archive=compressed.getvalue()
with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
 actual=tar.getmembers();assert len(actual)==len(members)
 for member in actual:assert member.isfile() and tar.extractfile(member).read()==members[member.name]
for name,body in [('deployment.tar.gz',archive),('deployment-manifest.json',mb)]:
 with (out/name).open('xb') as stream:stream.write(body)
receipt={'schema':'hepta-d1-ordinary-deployment-archive/v3','archive':ident(archive),
 'archive_git_blob':hashlib.sha1(b'blob '+str(len(archive)).encode()+bytes([0])+archive).hexdigest(),
 'manifest':ident(mb),'members':len(members),'member_bytes':sum(len(b) for b in members.values()),
 'expanded_tar_bytes':len(plain.getvalue()),'zero_filesystem_extraction':True,'all_original_members_byte_equal':True,
 'ordinary_executed':False,'compiler_started':False}
with (out/'archive-identity.json').open('x') as stream:stream.write(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps(receipt))
