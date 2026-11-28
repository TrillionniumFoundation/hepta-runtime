from pathlib import Path
import os,sys,json,hashlib,stat,tarfile,io,time,traceback
base=Path('/home/qian-qi/hia-runtime-rea-formats-20261128-2ac5');out=base/'asar-complete-component-capture-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1]);started=time.monotonic()
sha=lambda b:hashlib.sha256(b).hexdigest()
def digest(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def stamp(p):
 s=p.lstat();return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
required={'asar-final-component-gates-v2':'FINAL_ASAR_COMPONENT_GATES_PASS','asar-reproducible-component-build-v1':'REPRODUCIBLE_ASAR_COMPONENT_BUILD_PASS','asar-private-sha-x64-build-v3':'PASS','asar-worker-limits-v4':'PASS'}
terminals={n:json.loads((base/n/'terminal.json').read_bytes())for n in required}
for n,r in terminals.items():assert r['status']==required[n],(n,r)
members={};directories={};excluded=[];executables=[]
try:
 for top in sorted(base.iterdir()):
  if not top.name.startswith('asar-')or top==out:continue
  if top.is_file():members[str(top.relative_to(base))]=top;continue
  assert top.is_dir()and not top.is_symlink()
  for folder,dirs,files in os.walk(top,followlinks=False):
   directory=Path(folder);directories[str(directory.relative_to(base))]=stat.S_IMODE(directory.stat().st_mode)
   if 'target'in dirs:excluded.append(directory/'target');dirs.remove('target')
   dirs.sort()
   for name in sorted(files):
    p=directory/name;assert stat.S_ISREG(p.lstat().st_mode),str(p);members[str(p.relative_to(base))]=p
 for target in excluded:
  for profile in ['debug','release']:
   deps=target/profile/'deps'
   if not deps.is_dir():continue
   for p in sorted(deps.iterdir()):
    if p.is_file()and os.access(p,os.X_OK):
     with p.open('rb')as f:magic=f.read(4)
     if magic==bytes.fromhex('7f454c46'):
      n='actual-original-test-executables/'+str(p.relative_to(base));members[n]=p;executables.append(n)
 for name in ['exact-public-crates.tar.gz','available-public-crates.json']:
  p=base/name;assert p.is_file();members[name]=p
 assert len(members)>4000 and len(executables)>=2,(len(members),executables)
 pins={};objects={};initial={};total=0
 for n,p in sorted(members.items()):
  before=stamp(p);assert stat.S_ISREG(before[2])and before[3]>=1
  h=digest(p);assert stamp(p)==before
  pins[n]={'bytes':before[4],'sha256':h,'mode':stat.S_IMODE(before[2])};initial[n]=before;objects.setdefault(h,p);total+=before[4]
  if len(pins)%500==0:print(json.dumps({'phase':'capture','members':len(pins),'bytes':total}),flush=True)
 manifest={'schema':'hepta.runtime.complete-original-content-archive.v1','files':pins,'directories':directories,'logical_bytes':total,'objects':len(objects),'excluded_cargo_incremental_and_dependency_build_cache':[str(p.relative_to(base))for p in excluded],'actual_original_test_executables':executables,'all_failed_and_superseded_component_attempts_retained':True,'public_route_qualified':False,'whole_runtime_replaced':False}
 manifest_raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();(out/'all-original-members.json').write_bytes(manifest_raw)
 archive=out/'complete-asar-native-and-original-proof.tar.gz'
 with tarfile.open(archive,'w:gz',compresslevel=6)as tar:
  info=tarfile.TarInfo('manifest.json');info.size=len(manifest_raw);info.mode=0o600;tar.addfile(info,io.BytesIO(manifest_raw))
  for h,p in sorted(objects.items()):
   info=tarfile.TarInfo('objects/'+h);info.size=p.stat().st_size;info.mode=0o600
   with p.open('rb')as f:tar.addfile(info,f)
 print(json.dumps({'phase':'archive-written','bytes':archive.stat().st_size,'objects':len(objects),'logical_bytes':total}),flush=True)
 checked=set()
 with tarfile.open(archive,'r:gz')as tar:
  for m in tar:
   assert m.isfile()and m.mode==0o600
   f=tar.extractfile(m)
   if m.name=='manifest.json':assert f.read()==manifest_raw;continue
   assert m.name.startswith('objects/')and len(m.name)==72
   h=m.name[8:];assert h in objects and h not in checked and m.size==objects[h].stat().st_size
   actual=hashlib.file_digest(f,'sha256').hexdigest();assert actual==h;checked.add(h)
 assert checked==set(objects)
 for n,p in sorted(members.items()):
  assert stamp(p)==initial[n]and digest(p)==pins[n]['sha256'],n
 report={'schema':'hepta.runtime.rea-asar-complete-component-capture.v1','status':'COMPLETE_ORIGINAL_INPUTS_OUTPUTS_AND_FAILURES_CAPTURED','members':len(pins),'directories':len(directories),'unique_objects':len(objects),'logical_bytes':total,'archive_bytes':archive.stat().st_size,'archive_sha256':digest(archive),'manifest_sha256':sha(manifest_raw),'seconds':time.monotonic()-started,'actual_original_test_executables':executables,'final_source_sha256':'70c1de9a0f9511bed5379cb0ac4eb9495f53fb71b2999a6290cc0605c22d0ab6','final_hia_lowering_sha256':'641e1d1b460251283fccd8d8749b4dfd7ed8689951bb1f43ad918bbd18064af0','final_image_sha256':'d5b57ebd0fe6956464cc95b5712449d543e3af5850442ae67d57049f5ef6fbd5','original_rust_methods':9,'native_original_methods':9,'differential_comparisons':701,'differences':0,'borrowed_abi_controls':174,'boundary_comparisons':12,'real_same_fd_mutation_controls':1,'strict_original_worker_resource_cases':4,'all_source_and_original_bytes_stable':True,'public_route_qualified':False,'whole_runtime_replaced':False}
except BaseException as e:
 report={'status':'FAILED','seconds':time.monotonic()-started,'error':repr(e),'traceback':traceback.format_exc(),'public_route_qualified':False,'whole_runtime_replaced':False}
 (out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True);raise
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
