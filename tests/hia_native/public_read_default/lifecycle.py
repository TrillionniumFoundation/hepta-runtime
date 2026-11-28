from pathlib import Path
import os,sys,json,time,signal,subprocess,select,hashlib,shlex,traceback,socket,ctypes
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import load
P,R,O,build,elf,elf_sha=load('lifecycle')
INFO_SHA='455c5dfd3bafe490d50825f2c3fbc7344424e852d4c662d323902afbd5cc0a70'
argv=(P/'network/original-ssh-arguments.bin').read_bytes().split(b'\0')[:-1]
info_command=argv[3*11+10].decode()
if '1257472'not in info_command:raise ValueError('network file_info command identity differs')
(O/'info-command').write_text(info_command)
root=O/'files';root.mkdir();file=root/'read.txt';file.write_text('owned network read Ω\n')
config=O/'config.json'
config.write_text(json.dumps({'state_dir':str(O/'state'),'controller_workspace_roots':[str(O)],'hosts':{'a':{'ssh_target':'local-native','remote_state_dir':str(O/'remote'),'execution_mode':'operator','allowed_read_path_prefixes':[str(root)]}}})+'\n')
sys.path.insert(0,str(R/'tests/hia_native'))
from test_native_read_bootstrap import LoopbackSSH
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'fixture child subreaper')
server=LoopbackSSH(O)
enabled=O/'hold-enabled';ready=O/'relay-ready';pidfile=O/'forced-pid';fifo=O/'release.fifo'
os.mkfifo(fifo,0o600);hold_fd=os.open(fifo,os.O_RDWR|os.O_CLOEXEC)
client_config=O/'ssh_client_config'
client_config.write_text('\n'.join(['Host local-native',' HostName 127.0.0.1',' Port '+str(server.port),' User '+server.user,' IdentityFile '+str(server.root/'client'),' IdentitiesOnly yes',' UserKnownHostsFile '+str(server.known_hosts),' GlobalKnownHostsFile /dev/null',' StrictHostKeyChecking yes',' BatchMode yes',' LogLevel ERROR','']))
bin_dir=O/'bin';bin_dir.mkdir();shim=bin_dir/'ssh'
relay_source="""#!/usr/bin/python3 -I
import os,sys,json,signal,ctypes
from pathlib import Path
O=Path(%r);ssh=%r;cfg=%r
args=sys.argv[1:];command=args[-1] if args else ''
if not (O/'hold-enabled').exists()or command!=(O/'info-command').read_text():
 os.execv(ssh,[ssh,'-F',cfg,*args])
parent=os.getpid();readfd,writefd=os.pipe()
child=os.fork()
if child==0:
 os.close(readfd)
 if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0:os._exit(124)
 if os.getppid()!=parent:os._exit(124)
 def forward(size):
  while size:
   data=os.read(0,min(size,65536))
   if not data:raise RuntimeError('early stream EOF')
   size-=len(data);at=0
   while at<len(data):at+=os.write(writefd,data[at:])
 forward(1257472+32)
 (O/'forced-pid').write_text(json.dumps({'ssh':parent,'relay':os.getpid()}))
 (O/'relay-ready').write_text('ready')
 with (O/'release.fifo').open('rb',buffering=0)as release:release.readline()
 while True:
  data=os.read(0,65536)
  if not data:break
  at=0
  while at<len(data):at+=os.write(writefd,data[at:])
 os.close(writefd);os._exit(0)
os.close(writefd);os.dup2(readfd,0);os.close(readfd)
os.execv(ssh,[ssh,'-F',cfg,*args])
"""%(str(O),server.ssh,str(client_config))
shim.write_text(relay_source);shim.chmod(0o755)
source="__name__='default_lifecycle_original'\n"+'\n'.join((R/'src/mcp/runtime'/name).read_text()for name in('file_metadata.py','inode_patch.py','binary_file.py'))
namespace={};exec(compile(source,'complete-original-read-source','exec'),namespace)
expected_read=namespace['main']({'op':'read','root':str(root),'path':str(file),'offset':0,'limit':20,'expected_version':None})
expected_info=namespace['main']({'op':'info','root':str(root),'path':str(file)})
started=time.monotonic();sessions=[];owned=[];cases=[]
report={'status':'RUNNING','actual_default_public_entrypoint':True,'actual_network_ssh':True,'elf_sha256':elf_sha,'public_routes_qualified':False,'isolated':sys.flags.isolated,'optimize':sys.flags.optimize,'fixture':'actual ssh retains its original PID; owned fixture relay holds remaining stdin after full exact helper plus 32 request bytes; relay uses parent-death signal and is reaped only by the fixture'}
def proc(pid):
 try:
  text=Path('/proc/%d/stat'%pid).read_text();parts=text[text.rfind(')')+2:].split()
  result={'pid':pid,'state':parts[0],'ppid':int(parts[1]),'start':int(parts[19])}
  try:result['exe']=os.readlink('/proc/%d/exe'%pid)
  except OSError:result['exe']=None
  return result
 except FileNotFoundError:return None
def live(row):
 now=proc(row['pid'])
 return now is not None and now['start']==row['start']
def tree(pid):
 seen=set();todo=[pid];out=[]
 while todo:
  pid=todo.pop()
  if pid in seen:continue
  seen.add(pid)
  if len(seen)>20:raise AssertionError('owned process-tree bound')
  row=proc(pid)
  if row is None:continue
  out.append(row)
  for thread in Path('/proc/%d/task'%pid).glob('*'):
   try:todo.extend(int(x)for x in(thread/'children').read_text().split())
   except FileNotFoundError:pass
 return out
def wait_until(predicate,seconds,label):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=predicate()
  if value:return value
  time.sleep(.01)
 raise AssertionError('owned wait deadline: '+label)
def reap(rows,seconds=5,adopted=False):
 reaped=[];last=[]
 def complete():
  nonlocal last
  last=[]
  for row in rows:
   now=proc(row['pid'])
   if now is None or now['start']!=row['start']:continue
   last.append(now)
   if adopted and now['state']=='Z'and now['ppid']==os.getpid():
    got,status=os.waitpid(now['pid'],os.WNOHANG)
    if got==now['pid']:
     reaped.append({'pid':got,'waitstatus':status,'already_dead':True});last.pop()
  return not last
 try:wait_until(complete,seconds,'owned PIDs gone '+str([r['pid']for r in rows]))
 except BaseException:
  report.setdefault('pending_owned_terminals',[]).append({'at':time.monotonic()-started,'rows':last,'adopted':adopted})
  raise
 return {'pids':[row['pid']for row in rows],'all_reaped':True,'fixture_reaped_already_dead_adoptees':reaped}
class Session:
 def __init__(self,label):
  self.folder=O/label;self.folder.mkdir();self.err=(self.folder/'stderr').open('xb')
  self.p=subprocess.Popen([str(elf),'--runtime-config',str(config)],cwd=O,env={'PATH':str(bin_dir)+':/usr/bin:/bin','HOME':str(O),'LC_ALL':'C'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True)
  self.buffer=b'';self.requests=[];self.responses=[];sessions.append(self)
  self.send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'actual-lifecycle','version':'1'}}})
  got=self.receive(10)
  if got.get('id')!=1 or 'result'not in got:raise AssertionError(got)
  self.send({'jsonrpc':'2.0','method':'notifications/initialized'})
 def send(self,value):
  self.requests.append(value);self.p.stdin.write(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()+b'\n');self.p.stdin.flush()
 def call(self,identity,tool,args=None):
  self.send({'jsonrpc':'2.0','id':identity,'method':'tools/call','params':{'name':tool,'arguments':args or {'host':'a','path':str(file)}}})
 def receive(self,seconds):
  end=time.monotonic()+seconds
  while b'\n'not in self.buffer:
   left=end-time.monotonic()
   if left<=0 or not select.select([self.p.stdout],[],[],left)[0]:raise AssertionError('actual response timeout')
   got=os.read(self.p.stdout.fileno(),65536)
   if not got:raise AssertionError(('public EOF',self.p.poll(),self.err))
   self.buffer+=got
  line,self.buffer=self.buffer.split(b'\n',1);value=json.loads(line);self.responses.append(value);return value
 def close(self):
  if not self.p.stdin.closed:self.p.stdin.close()
  code=self.p.wait(timeout=30);tail=self.buffer+self.p.stdout.read()
  if code!=0 or tail:raise AssertionError(('normal public EOF/join',code,tail))
  return code
def hold(session,identity):
 for p in(ready,pidfile):
  if p.exists():p.unlink()
 enabled.write_text('hold\n');session.call(identity,'file_info')
 wait_until(lambda:ready.exists()and pidfile.exists(),10,'actual partial helper stream')
 marker=json.loads(pidfile.read_text());relay=proc(marker['relay']);observed=[]
 if relay is None:raise AssertionError('owned relay absent')
 owned.append(relay)
 def helper():
  nonlocal observed
  observed=tree(server.process.pid)
  for row in observed:
   if row['exe']and row['exe'].startswith('/tmp/.hepta-hia-'):
    try:
     if hashlib.sha256(Path('/proc/%d/exe'%row['pid']).read_bytes()).hexdigest()==INFO_SHA:return row
    except FileNotFoundError:pass
  return None
 native=wait_until(helper,10,'actual info helper started')
 observed=tree(native['ppid'])
 subprocess_state=Path('/proc/%d/syscall'%native['pid']).read_text().strip()
 if not subprocess_state.startswith('0 '):raise AssertionError(('helper not blocked on actual stdin read',subprocess_state))
 owned.extend(observed)
 local=[row for row in tree(session.p.pid)if row.get('exe')==str(Path(server.ssh).resolve())]
 if len(local)!=1:raise AssertionError(('one owned actual SSH client',local))
 owned.extend(local)
 enabled.unlink()
 if local[0]['pid']!=marker['ssh']:raise AssertionError('fixture did not exec actual SSH in original owned PID')
 return {'helper':native,'remote_owned':observed,'local_ssh':local,'fixture_relay':relay,'read_syscall':subprocess_state}
def reap_relay(held):
 row=held['fixture_relay']
 def observed():
  try:
   got,status=os.waitpid(row['pid'],os.WNOHANG)
   if got==row['pid']:
    held['fixture_relay_waitstatus']=status
    return True
  except ChildProcessError:
   if not live(row):return True
  return False
 wait_until(observed,5,'only owned fixture relay reap')
 return {'pid':row['pid'],'fixture_reaped':True}
def success(reply,identity,expected):
 if reply.get('id')!=identity or reply.get('result',{}).get('isError')is not False:raise AssertionError(reply)
 text=reply['result']['content'][0]['text']
 if json.loads(text)!=expected:raise AssertionError(('original decoded Value',reply,expected))
try:
 session=Session('cancel');held=hold(session,20)
 session.call(21,'binary_read',{'host':'a','path':str(file),'offset':0,'limit':20})
 session.call(22,'read_multiple_files',{'host':'a','paths':[str(file)]})
 answers={row['id']:row for row in(session.receive(10),session.receive(10))}
 if set(answers)!={21,22}:raise AssertionError(('held task blocked unrelated request',answers))
 success(answers[21],21,expected_read)
 multi=answers[22]
 if multi.get('result',{}).get('isError')is not False or json.loads(multi['result']['content'][0]['text'])['files'][0]['text']!=file.read_text():raise AssertionError(multi)
 cancel_time=time.monotonic()
 session.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':20,'reason':'owned cancellation qualification'}})
 session.send({'jsonrpc':'2.0','id':23,'method':'ping'})
 ping=session.receive(10)
 if ping.get('id')!=23 or ping.get('result')!={}:raise AssertionError(('cancelled task emitted response',ping))
 if not all(live(row)for row in held['local_ssh'])or not live(held['helper']):raise AssertionError('ordinary notification incorrectly dropped active handler')
 os.write(hold_fd,b'release\n')
 local=reap(held['local_ssh']);local['elapsed']=time.monotonic()-cancel_time
 remote=reap(held['remote_owned'],adopted=True);reap_relay(held)
 session.call(24,'file_info');success(session.receive(10),24,expected_info)
 code=session.close()
 cases.append({'label':'concurrent-notification-retains-handler-and-discards-wire','status':'PASS','local':local,'remote':remote,'held':held,'returncode':code})
 print('PUBLIC_LIFECYCLE_CASE notification PASS',flush=True)
 session=Session('eof');held=hold(session,30);end_start=time.monotonic();code=session.close()
 local=reap(held['local_ssh']);remote=reap(held['remote_owned'],adopted=True);reap_relay(held)
 cases.append({'label':'EOF-reaps-owned-remote','status':'PASS','held':held,'local':local,'remote':remote,'returncode':code,'elapsed':time.monotonic()-end_start})
 print('PUBLIC_LIFECYCLE_CASE eof PASS',flush=True)
 session=Session('deadline');deadline_started=time.monotonic();held=hold(session,40)
 timeout=session.receive(35);elapsed=time.monotonic()-deadline_started
 wanted='direct SSH original deadline expired; no automatic retry'
 if timeout.get('id')!=40 or timeout.get('result',{}).get('isError')is not True or timeout['result']['content']!=[{'type':'text','text':wanted}]:raise AssertionError(('original 30s deadline error',timeout,wanted))
 if not 29<=elapsed<=35:raise AssertionError(('original 30s deadline elapsed',elapsed))
 local=reap(held['local_ssh']);remote=reap(held['remote_owned'],adopted=True);reap_relay(held)
 session.call(41,'file_info');success(session.receive(10),41,expected_info);code=session.close()
 cases.append({'label':'original-30s-deadline-and-recover','status':'PASS','elapsed':elapsed,'held':held,'local':local,'remote':remote,'returncode':code})
 print('PUBLIC_LIFECYCLE_CASE deadline PASS',flush=True)
 if len(cases)!=3:raise AssertionError('exact lifecycle control count')
 report['status']='PASS'
except BaseException as exc:
 report.update(status='FAIL',error=repr(exc));traceback.print_exc()
finally:
 for session in sessions:
  if session.p.poll()is None:
   os.killpg(session.p.pid,signal.SIGKILL);session.p.wait(timeout=10)
  for f in(session.p.stdin,session.p.stdout,session.err):
   if not f.closed:f.close()
  (session.folder/'requests.json').write_text(json.dumps(session.requests,ensure_ascii=False,indent=2)+'\n')
  (session.folder/'responses.json').write_text(json.dumps(session.responses,ensure_ascii=False,indent=2)+'\n')
 for row in owned:
  if live(row):
   try:os.kill(row['pid'],signal.SIGTERM)
   except ProcessLookupError:pass
 time.sleep(.05)
 for row in owned:
  if live(row):
   try:os.kill(row['pid'],signal.SIGKILL)
   except ProcessLookupError:pass
 os.close(hold_fd)
 server.log.flush();(O/'sshd-session.log').write_bytes((server.root/'sshd.log').read_bytes());server.close()
 report.update(elapsed=time.monotonic()-started,cases=cases,observed_owned=owned,session_count=len(sessions))
 (O/'result.json').write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in('cases','observed_owned')},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='PASS'else 1)
