from pathlib import Path
import hashlib,json,os,stat,subprocess,sys
repo=Path('/home/qian-qi/hepta-runtime-rea-full-20261103-r1')
work=Path('/home/qian-qi/work/hepta-rea-tmpfs-matrix-20261103-r2')
target=Path('/home/qian-qi/work/hepta-rea-full-20261103-r1-target')
tmp=Path('/run/user/'+str(os.geteuid())+'/hr2')
out=repo/'docs/qualification/rea-full-tmpfs-20261103-r2'
assert not work.exists() and not tmp.exists() and not out.exists()
mounts=[]
for line in Path('/proc/self/mountinfo').read_text().splitlines():
 a,b=line.split(' - ',1);left=a.split();right=b.split()
 mounts.append({'mount':left[4],'mount_options':left[5],'fstype':right[0],'super_options':right[2]})
matches=[m for m in mounts if str(tmp.parent)==m['mount'] or str(tmp.parent).startswith(m['mount'].rstrip('/')+'/')]
mounted=max(matches,key=lambda m:len(m['mount']))
assert mounted['fstype']=='tmpfs' and 'noexec' not in mounted['mount_options'].split(',')
parent=tmp.parent.stat()
assert parent.st_uid==os.geteuid() and stat.S_IMODE(parent.st_mode)==0o700
assert os.statvfs(tmp.parent).f_bavail*os.statvfs(tmp.parent).f_frsize>8*1024**3
work.mkdir(mode=0o700);tmp.mkdir(mode=0o700)
env=os.environ.copy()
env.update({'TMPDIR':str(tmp),'CARGO_HOME':'/home/qian-qi/work/hepta-rea-full-20261103-r1-cargo','CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'4','CARGO_TERM_COLOR':'never','CARGO_NET_OFFLINE':'true','RUSTUP_TOOLCHAIN':'1.95.0','RUSTC':'/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc'})
probe=subprocess.run(['/usr/bin/python3','-B','-c','import json,os,tempfile; from pathlib import Path; p=Path(tempfile.mkdtemp(prefix="matrix-probe-")); print(json.dumps({"selected_tempdir":tempfile.gettempdir(),"actual_directory":str(p),"uid":p.stat().st_uid,"mode":oct(p.stat().st_mode&0o7777)})); p.rmdir()'],env=env,text=True,capture_output=True,check=True)
receipt={'schema':'hepta.rea.temporary-storage-matrix.v1','scope':'Full functional Rust gates on explicitly selected task-private executable tmpfs. Does not qualify physical-disk latency or power-loss durability. Earlier ext4 budget failures are preserved. Source and production query budgets are unchanged.','tmpdir':str(tmp),'mount':mounted,'probe':json.loads(probe.stdout),'uid':os.geteuid(),'runner_sha256':hashlib.sha256((repo/'scripts/rea_full_qualification.py').read_bytes()).hexdigest(),'environment':{k:env[k] for k in ('TMPDIR','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_TERM_COLOR','CARGO_NET_OFFLINE','RUSTUP_TOOLCHAIN','RUSTC')},'child_launch_umask':'0022','output_dir':str(out)}
(work/'launch-environment.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'event':'tmpfs_matrix_launch','tmpdir':str(tmp),'filesystem':mounted,'source_edits_by_wrapper':False}),flush=True)
os.execvpe(sys.executable,[sys.executable,'-B',str(repo/'scripts/rea_full_qualification.py'),'--repo',str(repo),'--cargo-home',env['CARGO_HOME'],'--target-dir',str(target),'--jobs','4','--output-dir',str(out),'--cargo','/home/qian-qi/.cargo/bin/cargo','--rustc',env['RUSTC']],env)
