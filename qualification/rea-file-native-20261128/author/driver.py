from pathlib import Path
import os,sys,json,hashlib,tarfile,time,stat,io,traceback
os.umask(0o022);config=json.loads(sys.argv[2]);out=Path(config['output']);out.mkdir(mode=0o700,exist_ok=False);(out/'driver.py').write_text(sys.argv[1]);(out/'config.json').write_text(json.dumps(config,sort_keys=True,indent=2)+'\n')
start=time.monotonic();sha=lambda b:hashlib.sha256(b).hexdigest();CHUNK=32*1024*1024;SHARD=64*1024*1024
manifest={'schema':'hepta.full-evidence-chunk-cas.v1','chunk_bytes':CHUNK,'roots':config['roots'],'files':{},'objects':{},'directories':{},'special_entries':{}}
shards=[];tar=None;shard_size=0;shard_path=None;initial={}
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def finish_shard():
 global tar,shard_size,shard_path
 if tar is not None:
  tar.close();raw=shard_path.read_bytes();shards.append({'name':shard_path.name,'bytes':len(raw),'sha256':sha(raw)});tar=None;shard_size=0
def add_object(raw):
 global tar,shard_size,shard_path
 digest=sha(raw)
 if digest in manifest['objects']:assert manifest['objects'][digest]['bytes']==len(raw);return digest
 if tar is None or shard_size+len(raw)+2048>SHARD:
  finish_shard();shard_path=out/('objects-'+str(len(shards)).zfill(3)+'.tar.gz');tar=tarfile.open(shard_path,'w:gz',compresslevel=6);shard_size=0
 info=tarfile.TarInfo('objects/'+digest);info.size=len(raw);info.mode=0o400;info.mtime=0;tar.addfile(info,io.BytesIO(raw));shard_size+=len(raw)+1024
 manifest['objects'][digest]={'bytes':len(raw),'shard':shard_path.name};return digest
try:
 paths=[]
 for alias,name in sorted(config['roots'].items()):
  p=Path(name);assert p.exists()or p.is_symlink(),name
  paths.append((alias,p))
  if p.is_dir()and not p.is_symlink():
   for folder,dirs,files in os.walk(p,followlinks=False):
    for child in sorted(dirs+files):
     q=Path(folder)/child;paths.append((alias+'/'+str(q.relative_to(p)),q))
 for logical,path in paths:
  s=path.lstat();initial[str(path)]=identity(s);common={'source_path':str(path),'physical_identity':identity(s),'mode':stat.S_IMODE(s.st_mode)}
  if stat.S_ISDIR(s.st_mode):manifest['directories'][logical]=common;continue
  if stat.S_ISLNK(s.st_mode):manifest['special_entries'][logical]={**common,'kind':'symlink','target':os.readlink(path)};continue
  if not stat.S_ISREG(s.st_mode):
   kind='fifo'if stat.S_ISFIFO(s.st_mode)else 'socket'if stat.S_ISSOCK(s.st_mode)else 'other'
   manifest['special_entries'][logical]={**common,'kind':kind};continue
  pieces=[];digest=hashlib.sha256();size=0
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb')as stream:
   assert identity(os.fstat(stream.fileno()))==identity(s)
   while raw:=stream.read(CHUNK):
    digest.update(raw);size+=len(raw);pieces.append(add_object(raw))
   assert identity(os.fstat(stream.fileno()))==identity(s)
  assert identity(path.lstat())==identity(s)and size==s.st_size
  manifest['files'][logical]={**common,'bytes':size,'sha256':digest.hexdigest(),'chunks':pieces}
 finish_shard();manifest['shards']=shards
 raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();(out/'manifest.json').write_bytes(raw)
 seen={}
 for part in shards:
  path=out/part['name'];data=path.read_bytes();assert len(data)==part['bytes']and sha(data)==part['sha256']
  with tarfile.open(path,'r:gz')as archive:
   for member in archive:
    assert member.isfile()and member.name.startswith('objects/');digest=member.name.split('/')[1];payload=archive.extractfile(member).read();assert digest not in seen and digest==sha(payload)and len(payload)==manifest['objects'][digest]['bytes'];seen[digest]=len(payload)
 assert set(seen)==set(manifest['objects'])
 for name,was in initial.items():assert identity(Path(name).lstat())==was,name
 for logical,row in manifest['files'].items():
  path=Path(row['source_path']);digest=hashlib.sha256();total=0
  with path.open('rb')as stream:
   while data:=stream.read(CHUNK):digest.update(data);total+=len(data)
  assert total==row['bytes']and digest.hexdigest()==row['sha256'],logical
 report={'status':'COMPLETE_EVIDENCE_CAPTURE_AND_FULL_READBACK_PASS','logical_files':len(manifest['files']),'directories':len(manifest['directories']),'special_entries':len(manifest['special_entries']),'logical_bytes':sum(x['bytes']for x in manifest['files'].values()),'unique_chunks':len(manifest['objects']),'shards':shards,'manifest_bytes':len(raw),'manifest_sha256':sha(raw),'all_original_physical_identities_unchanged':True,'all_original_file_bytes_reread':True,'seconds':time.monotonic()-start}
except BaseException as e:
 finish_shard();report={'status':'FAILED','error':repr(e),'traceback':traceback.format_exc(),'seconds':time.monotonic()-start};(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True);raise
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
