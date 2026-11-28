from pathlib import Path
import gzip,hashlib,io,json,os,shutil,stat,tarfile,time
R=Path('/home/qian-qi/hia-runtime-process-owner-20261128-2ac5')
Q=R/'job-receipt-complete-archive-v1';Q.mkdir(mode=0o700)
E=Q/'evidence';E.mkdir(mode=0o700);(E/'captured-external-inputs').mkdir(mode=0o700)
names=['job-receipt-native-inputs-v1','job-receipt-native-controller-v2','job-receipt-native-controller-v3','job-receipt-native-functional-v1','job-receipt-native-functional-v2']
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def stamp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
 a=p.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1,str(p)
 raw=p.read_bytes();b=p.lstat();assert stamp(a)==stamp(b),str(p)
 return raw,stat.S_IMODE(a.st_mode)
externals={}
for n in ('job-receipt-native-functional-v1','job-receipt-native-functional-v2'):
 physical=json.loads((R/n/'physical-inputs.json').read_bytes())
 for name,pin in physical.items():
  p=Path(name);raw,mode=read(p)
  assert len(raw)==pin['bytes'] and SHA(raw)==pin['sha256'] and mode==pin['mode'],name
  if not any(p.is_relative_to(R/x) for x in names):
   key=pin['sha256']+'-'+format(mode,'o')
   dst=E/'captured-external-inputs'/key
   if dst.exists():assert read(dst)==(raw,mode)
   else:dst.write_bytes(raw);dst.chmod(mode)
   externals[name]={**pin,'member':'evidence/captured-external-inputs/'+key}
(E/'external-input-map.json').write_text(json.dumps(externals,sort_keys=True,indent=2)+'\n')
sessions=['dpty-5986a77fb3e0c1eef4b2332f9a1476183cadbdaedfbac6dce6ee7f8ee040af01','dpty-732484b083502715cc3f4e11eb212833d8f110c86c3cecf889c7c025dd32ee80','dpty-a7a89ab95ce0b4768d92e48a88d10f8af14fe62b0fb87ae7697853a665af8a7a']
(E/'terminal-archives').mkdir(mode=0o700)
for identity in sessions:
 p=Path('/home/qian-qi/.local/state/hepta-runtime-mac-worker/terminals')/identity/'output.log'
 raw,mode=read(p);dst=E/'terminal-archives'/(identity+'.log');dst.write_bytes(raw);dst.chmod(mode)
(E/'scope.json').write_text(json.dumps({'original_7_paths_unchanged':True,'methods':9,'pack_refusals':5,'record_states':['pending','launched','launch_unknown'],'full_21_methods_claimed':False,'public_process_qualified':False,'all_failures_retained':True,'sessions':sessions,'sources_deleted':False},indent=2)+'\n')
roots=[(R/x,x) for x in names]+[(E,'evidence')]
def inventory():
 rows=[]
 for root,prefix in roots:
  for p in [root,*sorted(root.rglob('*'))]:
   name=prefix if p==root else prefix+'/'+p.relative_to(root).as_posix()
   a=p.lstat();row={'path':name,'mode':stat.S_IMODE(a.st_mode)}
   if stat.S_ISDIR(a.st_mode):row['kind']='directory'
   else:
    raw,mode=read(p);row.update(kind='file',bytes=len(raw),sha256=SHA(raw))
   rows.append(row)
 return rows
before=inventory();index={'schema':'hepta.process-job-receipt-complete-originals.v1','rows':before}
indexraw=(json.dumps(index,sort_keys=True,indent=2)+'\n').encode();(Q/'index.json').write_bytes(indexraw)
archive=Q/'originals.tar.gz'
with archive.open('xb') as output:
 with gzip.GzipFile(fileobj=output,mode='wb',compresslevel=6,mtime=0) as gz:
  with tarfile.open(fileobj=gz,mode='w') as tf:
   for root,prefix in roots:tf.add(root,arcname=prefix,recursive=True)
   info=tarfile.TarInfo('index.json');info.size=len(indexraw);info.mode=0o600;tf.addfile(info,io.BytesIO(indexraw))
seen={}
with tarfile.open(archive,'r:gz') as tf:
 for member in tf:
  assert member.name not in seen,member.name
  if member.name=='index.json':
   assert tf.extractfile(member).read()==indexraw;seen[member.name]=None;continue
  row={'path':member.name,'mode':member.mode}
  if member.isdir():row['kind']='directory'
  else:
   assert member.isfile() and not member.issym() and not member.islnk()
   raw=tf.extractfile(member).read();row.update(kind='file',bytes=len(raw),sha256=SHA(raw))
  seen[member.name]=row
assert set(seen)=={x['path'] for x in before}|{'index.json'}
assert all(seen[x['path']]==x for x in before)
assert inventory()==before
for name,pin in externals.items():
 raw,mode=read(Path(name));assert len(raw)==pin['bytes'] and SHA(raw)==pin['sha256'] and mode==pin['mode']
araw,mode=read(archive)
receipt={'schema':'hepta.process-job-receipt-complete-originals-receipt.v1','archive_bytes':len(araw),'archive_sha256':SHA(araw),'index_bytes':len(indexraw),'index_sha256':SHA(indexraw),'files':sum(x['kind']=='file' for x in before),'directories':sum(x['kind']=='directory' for x in before),'raw_bytes':sum(x.get('bytes',0) for x in before),'external_captures':len(externals),'readback_all_bytes_and_modes':True,'source_terminal_stable':True,'no_original_removed':True}
(Q/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt),flush=True)
