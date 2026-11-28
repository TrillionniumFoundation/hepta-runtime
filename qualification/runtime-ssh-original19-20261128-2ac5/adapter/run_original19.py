from pathlib import Path
import hashlib,json,os,re,stat,subprocess,time,traceback,ctypes,signal,sys
Q=Path('/home/qian-qi/hia-runtime-ssh-original19-adapter-20261128-2ac5/candidate-v1')
B=Q/'build-v1';G=Q/'original19-native-v1';G.mkdir(mode=0o700)
sha=lambda b:hashlib.sha256(b).hexdigest()
def rec(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
 b=p.read_bytes();return {'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(s.st_mode)}
def snap(root):return {str(p.relative_to(root)):rec(p)for p in sorted(root.rglob('*'))if p.is_file()}
def all_inputs():return {'rust':snap(Q/'rust'),'sources':snap(Q/'source'),'projection':snap(Q/'qualification-projection'),'images':snap(Q/'images')}
before=all_inputs();assert before==json.loads((B/'source-after.json').read_bytes())
unit=B/'native-original19-unit';unitrec=rec(unit);assert unitrec==json.loads((B/'result.json').read_bytes())['unit_record']
(G/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
(G/'host-before.json').write_text(json.dumps({'loadavg':Path('/proc/loadavg').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'tmpdir':os.environ.get('TMPDIR'),'tmp_mount':Path('/proc/self/mountinfo').read_text(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text(),'statvfs':list(os.statvfs(G))},sort_keys=True)+'\n')
journal=G/'journals';journal.mkdir(mode=0o700)
expected=[]
for file in ['ssh_direct_tests.rs','ssh_direct_entry_tests.rs']:
 raw=(Q/'rust/original'/file).read_text()
 prefix='mcp::runtime::ssh::direct::tests::'+('entry_tests::'if'entry_tests'in file else'')
 for m in re.finditer(r'#\[(?:tokio::)?test\]\s*(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\s*\(',raw):expected.append(prefix+m.group(1))
assert len(expected)==20
env=dict(os.environ,HIA_SSH19_JOURNAL_DIR=str(journal),RUST_BACKTRACE='1')
with(G/'list.stdout').open('xb')as out,(G/'list.stderr').open('xb')as err:
 p=subprocess.run([str(unit),'mcp::runtime::ssh::direct::tests::','--list'],stdout=out,stderr=err,env=env,timeout=30)
assert p.returncode==0
actual=[x[:-6]for x in(G/'list.stdout').read_text().splitlines()if x.endswith(': test')]
assert len(actual)==20 and set(actual)==set(expected)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(36,1,0,0,0)==0
(G/'tests.json').write_text(json.dumps(expected,indent=2)+'\n')
started=time.monotonic();proc=None;orphans=[]
try:
 with(G/'stdout').open('xb')as out,(G/'stderr').open('xb')as err:
  args=[str(unit),'mcp::runtime::ssh::direct::tests::','--nocapture']
  proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,cwd=G,start_new_session=True)
  (G/'process.json').write_text(json.dumps({'pid':proc.pid,'argv':args,'outer_seconds':180,'test_parallelism':'original default; no override','internal_deadlines':'unmodified original files','outer_subreaper':True})+'\n')
  try:rc=proc.wait(timeout=180)
  except subprocess.TimeoutExpired:
   (G/'unknown.json').write_text(json.dumps({'state':'UNKNOWN','pid':proc.pid})+'\n');raise
 after=all_inputs();(G/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
 assert after==before and rec(unit)==unitrec
 while True:
  try:pid,status=os.waitpid(-1,os.WNOHANG)
  except ChildProcessError:break
  if pid==0:break
  orphans.append({'pid':pid,'status':status,'cleanup_signal':False})
 live=Path('/proc/self/task/'+str(os.getpid())+'/children').read_text().split()
 (G/'adopted.json').write_text(json.dumps({'reaped':orphans,'live':live})+'\n')
 stdout=(G/'stdout').read_text();stderr=(G/'stderr').read_text()
 journals={p.name:rec(p)for p in journal.iterdir()if p.is_file()}
 result={'passed':rc==0 and '20 passed; 0 failed; 0 ignored;'in stdout and not orphans and not live,'scope':'all retained original19 methods against five exact native HIA policies plus explicit mechanical QA callback/fault adapter','methods':19,'test_entries':20,'returncode':rc,'seconds':time.monotonic()-started,'unit':unitrec,'journal_files':journals,'tests':expected,'source_unchanged':True,'adopted':{'reaped':orphans,'live':live},'stdout_sha256':sha(stdout.encode()),'stderr_sha256':sha(stderr.encode()),'stdout_tail':stdout[-10000:],'stderr_tail':stderr[-16000:]}
 (G/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items()if k not in ['journal_files','tests']}),flush=True)
 # Only cleanup actual adopted children after a failed, terminal qualification.
 # It cannot contribute to a passing original-child receipt.
 if live:
  assert not result['passed']
  cleanup=[]
  for pid in map(int,live):
   fd=os.pidfd_open(pid,0)
   try:
    raw=Path('/proc/'+str(pid)+'/stat').read_text();parts=raw.rsplit(') ',1)[1].split();assert int(parts[1])==os.getpid()
    signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
    got,status=os.waitpid(pid,0);assert got==pid;cleanup.append({'pid':pid,'status':status,'birth':parts[19],'cleanup_signal':True})
   finally:os.close(fd)
  (G/'failure-cleanup.json').write_text(json.dumps(cleanup,sort_keys=True)+'\n')
 if not result['passed']:raise RuntimeError('original19 native gate failed; complete original output preserved')
except BaseException:
 if not(G/'result.json').exists():
  result={'passed':False,'error':traceback.format_exc(),'seconds':time.monotonic()-started,'pid':proc.pid if proc else None,'returncode':proc.poll()if proc else None}
  (G/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result),flush=True)
 raise
