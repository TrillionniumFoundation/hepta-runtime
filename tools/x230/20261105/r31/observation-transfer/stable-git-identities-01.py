import os,stat,hashlib,json
from pathlib import Path
root=Path('/home/qian/hepta-runtime-optimization-20261105-r31')
expected={
'observation-evidence-01.tar.gz':(3150234,'b3e443d4a871b7d77f809d55b161be0e29ced8c722382a7a68bba66668a610d5'),
'observation-evidence-01.manifest.json':(1084771,'ba545dd018a8b771991c7ec21293466443a0b1f4c250fb193c9969ab9222ac1c'),
'observation-evidence-01.compact.json':(37631,'646a999d0834fccbb27ffccb076504d81d2abed1511ef2f5ca80cd07c71f38a1'),
'archive_r31_observation.py':(37313,'296d84668c1703361cb3dfe6b3a8b0849aed561d125f4a39988a44cda21fd7dc')}
stamp=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
files=[]
for name,(size,digest) in expected.items():
 p=root/name;before=p.lstat()
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size and size<=8*1024*1024
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 sha256=hashlib.sha256();git=hashlib.sha1(b'blob '+str(size).encode()+b'\0');seen=0
 with os.fdopen(fd,'rb') as stream:
  assert stamp(before)==stamp(os.fstat(stream.fileno()))
  while True:
   b=stream.read(min(65536,size+1-seen))
   if not b:break
   seen+=len(b);assert seen<=size
   sha256.update(b);git.update(b)
  after=os.fstat(stream.fileno())
 assert stamp(before)==stamp(after)==stamp(p.lstat()) and seen==size and sha256.hexdigest()==digest
 files.append({'path':str(p),'bytes':seen,'sha256':sha256.hexdigest(),'git_blob_sha1':git.hexdigest(),'version':':'.join(map(str,(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns))),'stable_stat':True})
print(json.dumps({'schema':'hepta-r31-stable-git-object-identities/v1','files':files,'programs_or_benchmarks_run':False},sort_keys=True))
