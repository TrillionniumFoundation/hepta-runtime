#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native MCP dump/restore of a disposable non-cooperative ordinary Python process.
Only observation instrumentation, no application save/restore/checkpoint protocol.
Same numeric PID, random memory, unread internal-pipe bytes and log offset verified.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
from runtime_http_acceptance import Client

CRIU='/home/qian/.local/src/hepta-criu-4.2.1-20261006/criu/criu'
CRIU_SHA='773ebe0534f7934e93ff208819c76e326b773be5e265a8b41e931ca4a196523f'


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--out',required=True);ap.add_argument('--url');ap.add_argument('--token-file');ap.add_argument('--host',default='x230');ap.add_argument('--threads',type=int,default=1,choices=[1,4,16]);a=ap.parse_args()
 ident=secrets.token_hex(12);target='/home/qian/hepta-native-snapshot-'+ident;sid=None;controller=None
 with open(a.binary,'rb') as binary_file:artifact_sha=hashlib.file_digest(binary_file,'sha256').hexdigest()
 report={'binary_sha256':artifact_sha,'complete':False,'checks':[],'application_checkpoint_code':False,'installed_endpoint':bool(a.url),'images_exported':False,'business_processes_modified':False}
 def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
 def passed(name):report['checks'].append(name);save();print('PASS '+name,flush=True)
 def ssh(code):
  p=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6','x230-ts','/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=20)
  if p.returncode:raise RuntimeError(p.stderr)
  return p.stdout
 program="""import hashlib,json,os,pathlib,time
root=pathlib.Path(__file__).parent
memory=os.urandom(128);value=8273641;r,w=os.pipe();unread=os.urandom(97);os.write(w,unread);os.close(w)
# Keep both directions present to establish the pipe as process-internal during preflight.
# A duplicate writable descriptor remains open but never writes again.
before={'pid':os.getpid(),'uid':os.getuid(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(unread).hexdigest(),'value':value}
(root/'before.json').write_text(json.dumps(before));print('START_ONCE',flush=True)
while not(root/'continue').exists():time.sleep(.05)
after={'pid':os.getpid(),'uid':os.getuid(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(os.read(r,97)).hexdigest(),'value':value}
(root/'after.json').write_text(json.dumps(after));print('RESTORED_MEMORY',flush=True)
""".replace('os.write(w,unread);os.close(w)','os.write(w,unread)')
 if a.threads>1:
  program="""import hashlib,json,os,pathlib,time,threading
root=pathlib.Path(__file__).parent;before_workers={};after_workers={};lock=threading.Lock();done=threading.Event()
def worker(index):
 memory=os.urandom(128);r,w=os.pipe();unread=os.urandom(97);os.write(w,unread);value=8273641+index
 state={'tid':threading.get_native_id(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(unread).hexdigest(),'value':value}
 with lock:before_workers[index]=state
 while not(root/'continue').exists():time.sleep(.05)
 state={'tid':threading.get_native_id(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(os.read(r,97)).hexdigest(),'value':value}
 with lock:after_workers[index]=state
 done.wait(timeout=60);os.close(r);os.close(w)
threads=[threading.Thread(target=worker,args=(i,)) for i in range(3)]
for t in threads:t.start()
while len(before_workers)!=3:time.sleep(.01)
before={'pid':os.getpid(),'uid':os.getuid(),'workers':before_workers}
(root/'before.json').write_text(json.dumps(before));print('START_ONCE',flush=True)
while len(after_workers)!=3:time.sleep(.05)
after={'pid':os.getpid(),'uid':os.getuid(),'workers':after_workers}
(root/'after.json').write_text(json.dumps(after));print('RESTORED_MEMORY',flush=True);done.set()
for t in threads:t.join()
"""
  program=program.replace('range(3)', 'range('+str(a.threads-1)+')').replace('!=3:', '!='+str(a.threads-1)+':')
 report['requested_threads']=a.threads
 ssh('import pathlib;r=pathlib.Path('+repr(target)+');r.mkdir(mode=0o700);(r/"app.py").write_text('+repr(program)+')')
 with tempfile.TemporaryDirectory(prefix='hepta-checkpoint-controller-') as tmp:
  root=pathlib.Path(tmp);(root/'workspace').mkdir();token=secrets.token_hex(32);(root/'token').write_text(token);(root/'token').chmod(0o600)
  host={'ssh_target':'x230-ts','platform':'linux','execution_mode':'operator','remote_state_dir':target+'/runtime','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[target],'allowed_write_path_prefixes':[target],'checkpoint_binary':CRIU,'checkpoint_binary_sha256':CRIU_SHA}
  (root/'config.json').write_text(json.dumps({'state_dir':str(root/'state'),'controller_workspace_roots':[str(root/'workspace')],'hosts':{a.host:host}}))
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  if not a.url:
   with (root/'controller.log').open('w') as log:controller=subprocess.Popen([a.binary,'mcp','--path',str(root/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(root/'config.json'),'--auth-token-file',str(root/'token')],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
  c=None;job=None;restored=False
  try:
   for _ in range(100):
    try:c=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
    except (OSError,RuntimeError):time.sleep(.1)
   if c is None:raise RuntimeError('native MCP unavailable')
   schema=next(x['inputSchema'] for x in c.rpc('tools/list',{})['tools'] if x['name']=='process_checkpoint')
   assert not {'configured_binary','sudo','images_dir'}&schema['properties'].keys()
   # Use regular-file stdio and an independent session; parent supervisor is not checkpointed.
   launch="import os;f=open("+repr(target+'/stdout.log')+",'ab',buffering=0);n=open('/dev/null','rb');os.dup2(n.fileno(),0);os.dup2(f.fileno(),1);os.dup2(f.fileno(),2);os.execv('/usr/bin/python3',['/usr/bin/python3','-u',"+repr(target+'/app.py')+"])"
   job=c.call('process_start',{'host':a.host,'executable':'/usr/bin/python3','args':['-c',launch],'timeout_seconds':300})['job']['id']
   before=None
   for _ in range(80):
    raw=ssh('import pathlib;p=pathlib.Path('+repr(target+'/before.json')+');print(p.read_text() if p.exists() else "null")');before=json.loads(raw)
    if before:break
    time.sleep(.1)
   assert before and before['uid']==1000;report['before']=before
   info=c.call('process_checkpoint',{'host':a.host,'action':'inspect','pid':before['pid']});assert info['ready'] and info['thread_count']==a.threads,info
   passed('native inventory accepted real same-login process and internal anonymous pipe without exposing images')
   request={'host':a.host,'action':'dump','pid':before['pid'],'expected_identity':info['identity'],'checkpoint_id':'native-'+ident,'acknowledge_process_stop':True}
   c.call('process_checkpoint',{**request,'expected_identity':{**info['identity'],'start_ticks':info['identity']['start_ticks']+1}},denied=True)
   assert c.call('process_checkpoint',{'host':a.host,'action':'inspect','pid':before['pid']})['identity']==info['identity']
   dumped=c.call('process_checkpoint',request);assert dumped['state']=='dumped';report['dump']=dumped
   # Original supervisor must reap its original child before the numeric PID can be restored.
   c.call('process_wait',{'host':a.host,'job_id':job,'timeout_seconds':15})
   report['original_job_state']=c.call('process_status',{'host':a.host,'job_id':job})
   prefix=ssh('import pathlib,hashlib,json;p=pathlib.Path('+repr(target+'/stdout.log')+');b=p.read_bytes();print(json.dumps({"size":len(b),"sha256":hashlib.sha256(b).hexdigest()}))');report['original_log_prefix']=json.loads(prefix)
   passed('stale PID identity rejected, real CRIU image captured and original process stopped only after valid dump')
   resumed=c.call('process_checkpoint',{'host':a.host,'action':'restore','checkpoint_id':'native-'+ident,'acknowledge_process_stop':True});restored=True;report['restore']=resumed
   assert resumed['same_numeric_pid'] and resumed['restored_identity']['pid']==before['pid']
   assert resumed['state']=='restored_stopped' and resumed['requires_explicit_resume'] and resumed['restored_kernel_state']=='T'
   assert resumed['live_thread_count']==a.threads and resumed['all_threads_stopped'] and resumed['restored_threads_match']
   repeated=c.call('process_checkpoint',{'host':a.host,'action':'restore','checkpoint_id':'native-'+ident,'acknowledge_process_stop':True});assert repeated['reused']
   ssh('import pathlib;pathlib.Path('+repr(target+'/continue')+').write_text("1")')
   time.sleep(.15)
   assert json.loads(ssh('import pathlib,json;print(json.dumps(pathlib.Path('+repr(target+'/after.json')+').exists()))')) is False
   restore_identity=resumed['restored_identity']
   c.call('process_checkpoint',{'host':a.host,'action':'resume','checkpoint_id':'native-'+ident,'expected_identity':restore_identity},denied=True)
   c.call('process_checkpoint',{'host':a.host,'action':'resume','checkpoint_id':'native-'+ident,'acknowledge_resume':True,'expected_identity':{**restore_identity,'start_ticks':restore_identity['start_ticks']+1}},denied=True)
   stopped_status=c.call('process_checkpoint',{'host':a.host,'action':'status','checkpoint_id':'native-'+ident})
   assert stopped_status['state']=='restored_stopped' and stopped_status['restored_kernel_state']=='T'
   passed('restore reports stopped state; missing consent and stale restored identity cannot resume it')
   if controller is not None:
    controller.terminate();controller.wait(timeout=20)
    with (root/'controller.log').open('a') as log:
     controller=subprocess.Popen([a.binary,'mcp','--path',str(root/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(root/'config.json'),'--auth-token-file',str(root/'token')],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
    for _ in range(100):
     try:c=Client(f'http://127.0.0.1:{port}/mcp',token);break
     except (OSError,RuntimeError):time.sleep(.1)
    status=c.call('process_checkpoint',{'host':a.host,'action':'status','checkpoint_id':'native-'+ident})
    assert status['state']=='restored_stopped' and status['restored_identity']==restore_identity and status['restored_kernel_state']=='T'
    report['controller_restarted_while_target_stopped']=True
    passed('fresh controller recovers the same private checkpoint and stopped restored identity before resume')

   resume_request={'host':a.host,'action':'resume','checkpoint_id':'native-'+ident,'acknowledge_resume':True,'expected_identity':restore_identity}
   continued=c.call('process_checkpoint',resume_request);report['resume']=continued
   assert continued['state']=='resumed' and not continued['reused']
   replay=c.call('process_checkpoint',resume_request);assert replay['reused']

   after=None
   for _ in range(80):
    after=json.loads(ssh('import pathlib;p=pathlib.Path('+repr(target+'/after.json')+');print(p.read_text() if p.exists() else "null")'))
    if after:break
    time.sleep(.1)
   assert after==before,(before,after);report['after']=after
   logs=json.loads(ssh('import pathlib,json;print(json.dumps(pathlib.Path('+repr(target+'/stdout.log')+').read_text()))'))
   assert logs=='START_ONCE\nRESTORED_MEMORY\n',logs
   status=c.call('process_checkpoint',{'host':a.host,'action':'status','checkpoint_id':'native-'+ident,'acknowledge_process_stop':True});report['status']=status
   passed('same PID/UID/random memory/unread pipe bytes restored; stdout offset retained and start not repeated')
   report.update(complete=True,two_phase_restore_resume=True,passed=len(report['checks']),host='x230-ts',checkpoint_id='native-'+ident,third_party_resources_universally_supported=False,final_stdout_sha256=hashlib.sha256(logs.encode()).hexdigest());save()
  finally:
   if job and c:
    try:c.call('process_cancel',{'host':a.host,'job_id':job})
    except Exception:pass
   if restored and c:
    try:
     ssh('import pathlib;pathlib.Path('+repr(target+'/continue')+').touch()')
     state=c.call('process_checkpoint',{'host':a.host,'action':'status','checkpoint_id':'native-'+ident})
     if state['state']=='restored_stopped':
      c.call('process_checkpoint',{'host':a.host,'action':'resume','checkpoint_id':'native-'+ident,'acknowledge_resume':True,'expected_identity':state['restored_identity']})
      report['cleanup_resumed_only_own_stopped_fixture']=True
    except Exception as error:report['cleanup_error']=str(error)[:300]
   if controller:controller.terminate();controller.wait(timeout=20)
   save()


if __name__=='__main__':main()
