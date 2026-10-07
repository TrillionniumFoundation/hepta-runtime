#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Installed native stream receiver acceptance without service restart."""
import argparse,base64,fcntl,hashlib,importlib.util,json,os,pathlib,signal,subprocess,sys,termios,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from runtime_http_acceptance import Client
spec=importlib.util.spec_from_file_location('exporter',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)
WORKER="import hashlib,json,os,sys\nm=os.urandom(32);t=0\nprint(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(m).hexdigest(),'total':0}),flush=True)\nfor l in sys.stdin:\n t+=int(l);print(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(m).hexdigest(),'total':t}),flush=True)"
APP="""import hashlib,json,os,subprocess,sys
m=os.urandom(32);t=0
w=subprocess.Popen([sys.executable,'-u','-c',%r],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
child=json.loads(w.stdout.readline());print(json.dumps({'event':'READY','pid':os.getpid(),'hash':hashlib.sha256(m).hexdigest(),'total':0,'worker':child}),flush=True)
for l in sys.stdin:
 t+=int(l);w.stdin.write(str(int(l)).encode()+b'\\n');child=json.loads(w.stdout.readline())
 print(json.dumps({'event':'VALUE','pid':os.getpid(),'hash':hashlib.sha256(m).hexdigest(),'total':t,'worker':child}),flush=True)
w.stdin.close();w.stdout.close();w.wait(timeout=5)
""" % WORKER
def descendants(pid):
 out=[];q=[pid]
 while q:
  p=q.pop(0)
  try: children=list(map(int,(pathlib.Path('/proc')/str(p)/'task'/str(p)/'children').read_text().split()))
  except FileNotFoundError: children=[]
  for c in children:
   if c not in out: out.append(c);q.append(c)
 return out
def sha(path):
 with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--token-file',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 binary=pathlib.Path(a.binary).resolve(strict=True);expected=sha(binary);token=pathlib.Path(a.token_file).read_text().strip()
 report={'complete':False,'binary_sha256':expected,'checks':[],'service_restart_performed':False,'DC_modified':False,'cloud_binding_used':False}
 def save(): pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,detail=None): report['checks'].append({'check':label,'detail':detail});save();print('PASS',label,flush=True)
 def client(): return Client('http://127.0.0.1:8790/mcp',token)
 app=None
 try:
  c=client();names={v['name'] for v in c.rpc('tools/list',{})['tools']}
  required={'stream_handoff_prepare','stream_handoff_status','stream_handoff_read','stream_handoff_write','stream_handoff_close','stream_handoff_list'}
  assert required<=names;passed('installed endpoint exposes all six stream ownership tools',len(names))
  app=subprocess.Popen([sys.executable,'-u','-c',APP],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
  deadline=time.monotonic()+3;child=[]
  while time.monotonic()<deadline:
   child=descendants(app.pid)
   if len(child)==1:break
   time.sleep(.02)
  assert len(child)==1,child
  app.stdin.write(b'17\n');app.stdin.flush();pending=bytearray(4)
  for _ in range(100):
   fcntl.ioctl(app.stdout.fileno(),termios.FIONREAD,pending,True)
   if int.from_bytes(pending,sys.byteorder)>0:break
   time.sleep(.02)
  queued=int.from_bytes(pending,sys.byteorder);assert queued>0
  key='installed-native-'+os.urandom(12).hex();prepared=c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':[app.pid,*child]});sid=prepared['session_id']
  ack=EXPORT.transfer(prepared['handoff_socket'],sid,{'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno(),'stderr_reader':app.stderr.fileno()},[app.pid,*child],acknowledge_quiesced_io=True)
  assert ack['accepted'];app.stdin.close();app.stdout.close();app.stderr.close()
  passed('installed broker accepts exact live pipes',{'queued_before':queued,'application_pids':[app.pid,*child]})
  c=client();assert any(v['session_id']==sid for v in c.call('stream_handoff_list',{'limit':20})['sessions'])
  cursor=0
  def read_until(needle):
   nonlocal cursor
   text='';deadline=time.monotonic()+8
   while time.monotonic()<deadline:
    page=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':cursor,'limit':4096})
    block=base64.b64decode(page['data_base64']);cursor=page['next_offset'];text+=block.decode()
    if needle in text:return text
    time.sleep(.05)
   raise AssertionError('missing '+needle)
  text=read_until('"total": 17');events=[json.loads(v) for v in text.splitlines() if v.startswith('{')]
  ready=next(v for v in events if v['event']=='READY');before=next(v for v in events if v['event']=='VALUE')
  assert before['hash']==ready['hash'] and before['worker']['hash']==ready['worker']['hash']
  passed('new MCP client recovers broker identity and queued output')
  write={'session_id':sid,'request_id':'installed-norestart-01','data_base64':base64.b64encode(b'5\n').decode()}
  first=c.call('stream_handoff_write',write);second=c.call('stream_handoff_write',write)
  assert first['state']=='confirmed' and second['reused']
  c.call('stream_handoff_write',{**write,'data_base64':base64.b64encode(b'6\n').decode()},denied=True)
  value=read_until('"total": 22');after=next(v for v in map(json.loads,[x for x in value.splitlines() if x.startswith('{')]) if v.get('event')=='VALUE')
  assert after['hash']==ready['hash'] and after['worker']['hash']==ready['worker']['hash']
  passed('installed input retry is once-only and app/child memory identities persist')
  c.call('stream_handoff_close',{'session_id':sid});app.wait(timeout=8)
  for _ in range(100):
   status=c.call('stream_handoff_status',{'session_id':sid})
   if status['state']=='exited':break
   time.sleep(.05)
  assert status['state']=='exited' and status['output_complete']
  final=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
  assert final['eof'] and final['output_complete']
  state=json.loads((pathlib.Path.home()/'.config/hepta-runtime-operator/runtime.json').read_text())['state_dir']
  receipts=(pathlib.Path(state)/'stream_handoffs'/sid/'input_receipts.jsonl').read_text()
  assert base64.b64encode(b'5\n').decode() not in receipts and '5\\n' not in receipts
  passed('installed close yields complete archive and no raw input in receipts')
  report.update(complete=True,passed=len(report['checks']),session_id=sid,application_pid=ready['pid'],child_pid=ready['worker']['pid'],application_processes_stopped=False)
  save();print('STREAM_INSTALLED_NORESTART_PASS',report['passed'],flush=True)
 finally:
  if app is not None and app.poll() is None:
   os.killpg(app.pid,signal.SIGTERM);app.wait(timeout=5)
  save()
if __name__=='__main__':main()
