import pathlib,sys,json,hashlib,tarfile,io,os,stat,subprocess,time,traceback,tomllib
Q=pathlib.Path(sys.argv[1]).resolve()
tool=pathlib.Path(sys.argv[2]).resolve()
RUN=Q/sys.argv[3];RUN.mkdir(mode=0o700)
C=Q/'rust';S=Q/'source';P=Q/'qualification-projection';N=RUN/'native';N.mkdir(mode=0o700)
sha=lambda b:hashlib.sha256(b).hexdigest()
def record(p):
 st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and p.resolve()==p,str(p)
 b=p.read_bytes();return {'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(st.st_mode)}
def snapshot(root):
 return {str(p.relative_to(root)):record(p) for p in sorted(root.rglob('*')) if p.is_file()}
commands=[]
env=dict(os.environ,CARGO_HOME=str(Q/'cargo-home'),CARGO_TARGET_DIR=str(Q/'target'),RUSTC=str(tool/'rustc'),HIA_SSH19_NATIVE_LIB=str(N),CARGO_NET_OFFLINE='true',PATH=str(tool)+':'+os.environ.get('PATH','/usr/bin:/bin'))
def run(label,args,cwd,timeout):
 t=time.monotonic()
 with (RUN/(label+'.stdout')).open('xb')as out,(RUN/(label+'.stderr')).open('xb')as err:
  p=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
  (RUN/(label+'.process.json')).write_text(json.dumps({'pid':p.pid,'argv':args,'cwd':str(cwd),'timeout':timeout})+'\n')
  try:rc=p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   (RUN/(label+'.unknown.json')).write_text(json.dumps({'state':'UNKNOWN','pid':p.pid})+'\n');raise
 row={'label':label,'argv':args,'cwd':str(cwd),'returncode':rc,'seconds':time.monotonic()-t}
 (RUN/(label+'.json')).write_text(json.dumps(row,sort_keys=True)+'\n');commands.append(row);print(json.dumps(row),flush=True)
 assert rc==0,row
 return (RUN/(label+'.stdout')).read_bytes()
start=time.monotonic()
try:
 rel=json.loads((Q/'qualification-source-relation.json').read_bytes())
 for n,x in rel['files'].items():
  a=(S/'asm/ssh_direct'/n).read_bytes();b=(P/n).read_bytes()
  assert sha(a)==x['original'] and sha(b)==x['projected'] and len(b)==x['bytes']
  t=b.decode()
  for h in reversed(rel['relations']):
   if h['path']==n:
    assert t.count(h['after'])==1
    t=t.replace(h['after'],h['before'],1)
  assert t.encode()==a
 tests=C/'src/mcp/runtime/ssh/ssh_direct_tests.rs'
 assert tests.read_bytes().replace(b'use super::Stdio;\n',b'use std::process::Stdio;\n')==(C/'original/ssh_direct_tests.rs').read_bytes()
 assert (C/'src/mcp/runtime/ssh/ssh_direct_entry_tests.rs').read_bytes()==(C/'original/ssh_direct_entry_tests.rs').read_bytes()
 assert sha((C/'original/Cargo.lock').read_bytes())=='b868d2529f17dfb78ba390e078eb281a98d9850e4eaa12245739fec43ec97823'
 dep=json.loads((Q/'dependency-projection.json').read_bytes())
 expected={(x['name'],x['version']):x['checksum'] for x in dep['packages']}
 vendor=Q/'vendor'
 if not vendor.exists():
  vendor.mkdir(mode=0o700)
  with tarfile.open(Q/'exact-dependency-archives.tar','r')as tf:
   for m in tf.getmembers():
    assert m.isfile() and pathlib.PurePosixPath(m.name).name==m.name and m.name.endswith('.crate')
    raw=tf.extractfile(m).read()
    candidates=[(n,v,h)for(n,v),h in expected.items()if m.name==n+'-'+v+'.crate'];assert len(candidates)==1
    n,v,h=candidates[0];assert sha(raw)==h
    base=n+'-'+v;destination=vendor/base;destination.mkdir()
    files={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as crate:
     for member in crate.getmembers():
      path=pathlib.PurePosixPath(member.name)
      assert path.parts[0]==base and '..'not in path.parts and not path.is_absolute()
      if member.isdir():continue
      assert member.isfile()
      name='/'.join(path.parts[1:]);b=crate.extractfile(member).read()
      p=destination/name;p.parent.mkdir(parents=True,exist_ok=True);assert not p.exists()
      p.write_bytes(b);p.chmod(0o644);files[name]=sha(b)
    (destination/'.cargo-checksum.json').write_text(json.dumps({'files':files,'package':h},sort_keys=True))
  assert len(list(vendor.iterdir()))==len(expected)
 config=C/'.cargo';config.mkdir(exist_ok=True)
 conf='[source.crates-io]\nreplace-with = "captured-original"\n[source.captured-original]\ndirectory = '+json.dumps(str(vendor))+'\n'
 p=config/'config.toml'
 if p.exists():assert p.read_text()==conf
 else:p.write_text(conf)
 raw=run('rustc-version',[str(tool/'rustc'),'-Vv'],C,30);assert b'rustc 1.95.0 'in raw
 run('cargo-version',[str(tool/'cargo'),'-Vv'],C,30)
 run('resolve-original-projection',[str(tool/'cargo'),'generate-lockfile','--offline'],C,60)
 lock=(C/'Cargo.lock').read_bytes()
 entries=tomllib.loads(lock.decode())['package']
 for x in entries:
  if x.get('source'):
   assert x['source']=='registry+https://github.com/rust-lang/crates.io-index'
   assert expected[(x['name'],x['version'])]==x['checksum']
 (RUN/'dependency-resolution.json').write_text(json.dumps({'original_lock_sha256':dep['original_lock_sha256'],'qa_lock_sha256':sha(lock),'actual_packages':entries,'scope':dep['scope']},sort_keys=True,indent=2)+'\n')
 before={'rust':snapshot(C),'sources':snapshot(S),'projection':snapshot(P),'images':snapshot(Q/'images')}
 (RUN/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
 parts=['core.S','api.S','spawn.S','ownership.S','io.S','owner.S','future.S']
 combined='\n'.join((P/n).read_text()for n in parts)+'\n'+(S/'asm/ssh_direct/private.S').read_text()+'\n'+(S/'asm/ssh_direct/qa_marshal.S').read_text()+'\n.section .note.GNU-stack,"",@progbits\n'
 (N/'owner.S').write_text(combined)
 layout=[('ssh_original_child','child'),('ssh_request_admission','admission'),('ssh_shared_owner','core'),('ssh_capture_io','io'),('ssh_capture_future','future')]
 embed=['.intel_syntax noprefix','.section .text']
 for name,label in layout:
  raw=(Q/'images'/(name+'.bin')).read_bytes()
  pin=json.loads((S/'native'/(name+'_composition.json')).read_bytes())['qualified_image']
  assert len(raw)==pin['bytes'] and sha(raw)==pin['sha256']
  (N/(name+'.bin')).write_bytes(raw)
  embed+=['.balign 16','.global ssh_hia_'+label,'ssh_hia_'+label+':','.incbin "'+name+'.bin"']
 embed+=['.section .note.GNU-stack,"",@progbits']
 (N/'images.S').write_text('\n'.join(embed)+'\n')
 run('assemble-owner',['/usr/bin/as','--64','-o','owner.o','owner.S'],N,60)
 run('assemble-images',['/usr/bin/as','--64','-o','images.o','images.S'],N,60)
 run('archive-native',['/usr/bin/ar','rcs','libssh_original19.a','owner.o','images.o'],N,60)
 run('build-original19-adapter',[str(tool/'cargo'),'test','--release','--lib','--no-run','--offline','--locked','-j','2','--message-format=json-render-diagnostics'],C,600)
 artifacts=[json.loads(line)for line in(RUN/'build-original19-adapter.stdout').read_text().splitlines()if line.startswith('{')]
 exe=[x['executable']for x in artifacts if x.get('reason')=='compiler-artifact' and x.get('profile',{}).get('test') and x.get('executable')]
 assert len(exe)==1,exe
 after={'rust':snapshot(C),'sources':snapshot(S),'projection':snapshot(P),'images':snapshot(Q/'images')}
 assert before==after
 (RUN/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
 actual=pathlib.Path(exe[0]);unit=RUN/'native-original19-unit';unit.write_bytes(actual.read_bytes());unit.chmod(0o500)
 (RUN/'compiler-artifacts.json').write_text(json.dumps(artifacts,sort_keys=True,indent=2)+'\n')
 result={'passed':True,'scope':'mechanical QA adapter build only; original19 execution not yet run','unit':str(unit),'unit_record':record(unit),'native':{p.name:record(p)for p in N.iterdir()if p.is_file()},'commands':commands,'seconds':time.monotonic()-start}
except BaseException:
 result={'passed':False,'error':traceback.format_exc(),'commands':commands,'seconds':time.monotonic()-start}
 (RUN/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'passed':False,'error':result['error'],'seconds':result['seconds']}),flush=True);raise
(RUN/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'passed':True,'scope':result['scope'],'unit':str(unit),'unit_record':result['unit_record'],'seconds':result['seconds']}),flush=True)
