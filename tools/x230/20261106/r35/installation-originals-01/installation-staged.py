import base64,datetime,gzip,hashlib,io,json,os,stat,sys,tarfile
from pathlib import Path,PurePosixPath
ROOT=Path('/home/qian/hepta-runtime-optimization-20261106-r35')
PARENT=ROOT.parent
assert sys.platform=='linux' and os.getuid()==1000
assert PARENT.resolve(strict=True)==PARENT and PARENT.is_dir()
assert not os.path.lexists(ROOT),'create-only R35 package root already exists'
PACKAGE=Path('/home/qian/hepta-runtime-optimization-20261106-r35-preparation-01.tar.gz')
assert PACKAGE.resolve(strict=True)==PACKAGE
initial=PACKAGE.lstat()
def version(s):return ':'.join(str(x) for x in (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
assert stat.S_ISREG(initial.st_mode) and initial.st_nlink==1 and initial.st_uid==1000
assert version(initial)=="2053:14483364:354738:1793943698009066791:1793943700814068868"
fd=os.open(PACKAGE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as f:
 before=os.fstat(f.fileno())
 assert version(before)==version(initial)
 raw=f.read(1024*1024+1)
 assert version(before)==version(os.fstat(f.fileno()))==version(PACKAGE.lstat())
assert len(raw)==354738 and hashlib.sha256(raw).hexdigest()=='7303e1ded7ac4aab5f02c5240b1e6211bbaf7ca8cd7ebe19d686546842366dba'
with gzip.GzipFile(fileobj=io.BytesIO(raw),mode='rb') as stream:
 tar_raw=stream.read(4*1024*1024+1)
assert len(tar_raw)<=4*1024*1024
files={}
with tarfile.open(fileobj=io.BytesIO(tar_raw),mode='r:') as archive:
 for entry in archive:
  name=PurePosixPath(entry.name)
  assert entry.isfile() and not entry.issym() and not entry.islnk()
  assert not name.is_absolute() and '..' not in name.parts and str(name)==entry.name
  assert len(name.parts)>0 and not any(part in ('','.','..') for part in name.parts)
  assert entry.name not in files and len(files)<64 and 0<=entry.size<=1024*1024
  data=archive.extractfile(entry).read(1024*1024+1)
  assert len(data)==entry.size
  files[entry.name]=data
assert len(files)==39 and sum(map(len,files.values()))==1383630
manifest_raw=files['frozen-preparation-manifest.json']
assert len(manifest_raw)==7532 and hashlib.sha256(manifest_raw).hexdigest()=='a2c8155bca4bbad9d805270fafc4c6ab968e4d559c794636bdb033ef7307f000'
manifest=json.loads(manifest_raw)
assert manifest['root']==str(ROOT) and manifest['baseline_commit']=='baab4def80be7af015b2e7a594cb302f66c4130e'
expected={row['path']:row for row in manifest['files']}
assert len(expected)==len(manifest['files']) and set(files)==set(expected)|{'frozen-preparation-manifest.json'}
for name,pin in expected.items():
 data=files[name]
 assert len(data)==pin['bytes'] and hashlib.sha256(data).hexdigest()==pin['sha256']
usage=os.statvfs(PARENT);free_before=usage.f_bavail*usage.f_frsize
assert free_before>=3*1024**3,'original 3 GiB preflight requirement is not met'
os.mkdir(ROOT,0o700)
dirs={ROOT}
installed={}
for name,data in sorted(files.items()):
 p=ROOT/name
 current=ROOT
 for part in PurePosixPath(name).parts[:-1]:
  current=current/part
  if current not in dirs:
   os.mkdir(current,0o700);dirs.add(current)
  assert current.resolve(strict=True)==current and stat.S_ISDIR(current.lstat().st_mode)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as f:
  f.write(data);f.flush();os.fsync(f.fileno())
 st=p.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==1000 and st.st_size==len(data)
 assert p.resolve(strict=True)==p and hashlib.sha256(p.read_bytes()).hexdigest()==hashlib.sha256(data).hexdigest()
 installed[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
receipt={'schema':'hepta-r35-qualification-package-install/v1','finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'root':str(ROOT),'archive_path':str(PACKAGE),'archive_version':version(initial),'archive_bytes':len(raw),'archive_sha256':hashlib.sha256(raw).hexdigest(),'file_count':len(files),
 'expanded_file_bytes':sum(map(len,files.values())),'files':installed,'free_bytes_before_install':free_before,
 'original_minimum_free_bytes':3*1024**3,'qualification_started':False,'source_materialized':False,'cache_moved':False,'cache_deleted':False,
 'production_services_modified':False}
rb=(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode()
p=ROOT/'qualification-package-install-02.json'
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,'wb') as f:f.write(rb);f.flush();os.fsync(f.fileno())
for d in sorted(dirs,key=lambda p:len(p.parts),reverse=True):
 fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
fd=os.open(PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
print(json.dumps({'installed':True,'root':str(ROOT),'file_count':len(files),'expanded_file_bytes':sum(map(len,files.values())),
 'archive_sha256':hashlib.sha256(raw).hexdigest(),'receipt':{'path':str(p),'bytes':len(rb),'sha256':hashlib.sha256(rb).hexdigest()},
 'free_bytes_before_install':free_before,'qualification_started':False,'cache_moved':False,'cache_deleted':False},sort_keys=True))
