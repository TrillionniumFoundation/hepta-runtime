#!/usr/bin/python3
import fcntl,json,os,pathlib,sys,time
root=pathlib.Path('/tmp/hepta-v9-async-native-private-skcmba6m')
expected=['-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'RemoteCommand=none', '-o', 'RequestTTY=no', '--', 'v9-fixed-local-health-only', "printf 'hepta-host-health-v1\\n'"]
harness={'pid': 2188089, 'uid': 1000, 'start': '4553709', 'state': 'R'}
def identity(pid):
 try:
  p=pathlib.Path('/proc')/str(pid);s=(p/'stat').read_text();v=s[s.rfind(')')+2:].split()
  return {'pid':pid,'uid':p.stat().st_uid,'start':v[19],'state':v[0]}
 except (FileNotFoundError,ProcessLookupError):return None
def same(a,b):return bool(a and b and a['pid']==b['pid'] and a['uid']==b['uid'] and a['start']==b['start'] and b['state']!='Z')
def event(value):
 fd=os.open(root/'events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX);os.write(fd,(json.dumps(value,sort_keys=True)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
if sys.argv[1:]!=expected:
 event({'event':'refused_nonfixed_argv'});raise SystemExit(85)
parent=identity(os.getppid());mine=identity(os.getpid())
if parent is None or mine is None:raise SystemExit(86)
event({'event':'spawned',**mine,'parent_pid':parent['pid'],'parent_start':parent['start']})
deadline=time.monotonic()+12
while (root/'gate').exists():
 if time.monotonic()>=deadline or os.getppid()!=parent['pid'] or not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):
  event({'event':'self_exit',**mine});raise SystemExit(86)
 time.sleep(.015)
if not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):raise SystemExit(86)
event({'event':'fixed_response',**mine})
sys.stdout.write('hepta-host-health-v1\n');sys.stdout.flush()
