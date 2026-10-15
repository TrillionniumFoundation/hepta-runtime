#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Sequential source-pinned helper acceptance on one configured Mac SSH target."""
import argparse
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import time
import uuid
from operator_job_identity_tests import CODES, ROOT

CHILD="""import fcntl,json,os,pathlib,signal,time,sys
base=pathlib.Path(sys.argv[1]);base.mkdir(exist_ok=True)
with (base/'launch-count.lock').open('a') as lock:
 fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
 p=base/'launch-counter.json'
 n=json.loads(p.read_text())['launches'] if p.exists() else 0
 p.write_text(json.dumps({'launches':n+1}))
if sys.argv[2]=='ignore':signal.signal(signal.SIGTERM,signal.SIG_IGN)
(base/'ready.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid()}))
print('MAC_OWNED_READY',flush=True)
time.sleep(45)
"""
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--receipt-dir',required=True)
    ap.add_argument('--diagnostic-capture',action='store_true');args=ap.parse_args()
    out=pathlib.Path(args.receipt_dir).resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    report={'schema':'hepta-operator-mac-owner-helper-v1','origin':'source_pinned_real_configured_mac_ssh',
        'ssh_host_alias':'macbook-pro','jobs_source_sha256':sha(ROOT/'src/mcp/runtime/jobs.rs'),
        'harness_sha256':sha(pathlib.Path(__file__)),'model_origin':False,'native_mcp_envelope_tested':False,
        'installed_services_changed':False,'DC_changed':False,'full_dc_replacement_qualified':False,
        'checks':[],'owned_jobs':[],'cleanup':{},'complete':False}
    fixture=None;rows=[];failure=None
    with (out/'helper-dispatch.jsonl').open('x',encoding='utf-8') as log:
        def remote(code,q,timeout=45):
            if args.diagnostic_capture and code==CODES['START_CODE']:
                code="""import pathlib,subprocess
HEPTA_ACTUAL_POPEN=subprocess.Popen
def capture_owner(argv,**kw):
 if len(argv)==2 and str(argv[1]).endswith('/runner.py'):
  owned=pathlib.Path(argv[1]).parent
  kw['stdout']=open(owned/'diagnostic-owner.stdout.log','ab')
  kw['stderr']=open(owned/'diagnostic-owner.stderr.log','ab')
 return HEPTA_ACTUAL_POPEN(argv,**kw)
subprocess.Popen=capture_owner
"""+code
            p=subprocess.run(['/usr/bin/ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','macbook-pro',
                '/usr/bin/python3 -c '+shlex.quote(code)],input=json.dumps(q),capture_output=True,text=True,timeout=timeout)
            log.write(json.dumps({'request':q,'code_sha256':hashlib.sha256(code.encode()).hexdigest(),
                'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})+'\n');log.flush()
            return p,json.loads(p.stdout) if p.returncode==0 and p.stdout.strip() else None
        def query(op,row=None):
            code="""import json,os,pathlib,shutil,subprocess,sys
q=json.load(sys.stdin);base=pathlib.Path(q['base'])
if base.is_symlink() or not base.name.startswith('hepta-mac-owner-') or base.stat().st_uid!=os.geteuid():
 raise ValueError('owned Mac fixture binding refused')
if q['op']=='remove':shutil.rmtree(base);result={'removed':True}
else:
 job=base/q['name'];work=base/(q['name']+'-work')
 if q['op']=='ready':
  p=work/'ready.json';result=json.loads(p.read_text()) if p.exists() else None
 elif q['op']=='markers':
  started=(job/'started.json').read_bytes()
  result={'binding_sha256':__import__('hashlib').sha256(started).hexdigest(),
   'launches':json.loads((work/'launch-counter.json').read_text())['launches']}
 elif q['op']=='diagnostic':
  result={name:(job/name).read_text(errors='replace')[-65536:] if (job/name).exists() else '' for name in ('diagnostic-owner.stderr.log','diagnostic-owner.stdout.log')}
 elif q['op']=='replay':
  p=subprocess.run(['/usr/bin/python3',str(job/'runner.py')],capture_output=True,text=True,timeout=5)
  result={'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
print(json.dumps(result))
"""
            p,value=remote(code,{'base':fixture,'op':op,'name':row['name'] if row else ''})
            if p.returncode:raise RuntimeError('owned Mac fixture query failed')
            return value
        try:
            p,value=remote("import json,tempfile,os;print(json.dumps({'base':tempfile.mkdtemp(prefix='hepta-mac-owner-'),'uid':os.geteuid()}))",{})
            assert p.returncode==0;fixture=value['base'];report['fixture_uid']=value['uid']
            for mode in ('normal','ignore'):
                name='owned-'+mode;job=fixture+'/'+name;work=fixture+'/'+name+'-work'
                q={'job_id':'owned-mac-'+uuid.uuid4().hex,'job_dir':job,'unit':'owned-mac-'+uuid.uuid4().hex,
                   'request_fingerprint':uuid.uuid4().hex,'platform':'macos','execution_mode':'operator',
                   'executable':'/usr/bin/python3','args':['-u','-c',CHILD,work,mode],'cwd':fixture,'env':{},
                   'stdin':None,'timeout_seconds':50,'allow_job_network':True,'allow_detached_fallback':True}
                ref={key:q[key] for key in ('job_id','job_dir','unit')}
                row={'name':name,'reference':ref};rows.append(row)
                p,launch=remote(CODES['START_CODE'],q)
                assert p.returncode==0 and launch['backend']=='detached'
                ready=None
                for _ in range(30):
                    ready=query('ready',row)
                    if ready:break
                    time.sleep(.1)
                assert ready and ready['uid']==report['fixture_uid']
                before=query('markers',row);assert before['launches']==1
                replay=query('replay',row);assert replay['exit_code']!=0
                assert query('markers',row)==before
                p,ack=remote(CODES['CANCEL_CODE'],{**ref,'grace_seconds':12})
                assert p.returncode==0 and ack['result']=='term_sent' and ack['atomic_identity'] is False
                assert ack['termination_confirmed'] is False
                p,status=remote(CODES['STATUS_CODE'],{**ref,'wait_seconds':20})
                assert p.returncode==0 and status['state']=='cancelled' and status['output_complete'] is True
                assert status['exit_code']==(-9 if mode=='ignore' else -15)
                assert query('markers',row)==before
                replay=query('replay',row);assert replay['exit_code']!=0
                assert query('markers',row)==before
                report['owned_jobs'].append({'mode':mode,'job_id':q['job_id'],'launch':launch,
                    'ack':ack,'status':status,'marker':before,'terminal_confirmed':True})
                report['checks'].append(mode+' kqueue non-reaping cancellation/output drain + live/completed replay refusal with original binding/counter')
            report['source_stable']=sha(ROOT/'src/mcp/runtime/jobs.rs')==report['jobs_source_sha256']
        except Exception as exc:
            failure=exc;report['error_type']=type(exc).__name__;report['error']=str(exc)[:2000]
        finally:
            all_terminal=True
            if args.diagnostic_capture:
                report['diagnostic_owner_output']={}
                for row in rows:
                    try:report['diagnostic_owner_output'][row['name']]=query('diagnostic',row)
                    except Exception as error:report['diagnostic_owner_output'][row['name']]={'error_type':type(error).__name__}
            for row in rows:
                try:
                    p,status=remote(CODES['STATUS_CODE'],{**row['reference'],'wait_seconds':0})
                    if p.returncode!=0 or status.get('state') not in ('succeeded','failed','cancelled','timed_out'):
                        remote(CODES['CANCEL_CODE'],{**row['reference'],'grace_seconds':12})
                        p,status=remote(CODES['STATUS_CODE'],{**row['reference'],'wait_seconds':20})
                    if p.returncode!=0 or status.get('state') not in ('succeeded','failed','cancelled','timed_out'):
                        all_terminal=False
                except Exception:all_terminal=False
            report['cleanup']['owned_jobs_terminal']=all_terminal
            if fixture and all_terminal:
                try:report['cleanup']['fixture_removed']=query('remove')['removed']
                except Exception:report['cleanup']['fixture_removed']=False
            else:report['cleanup']['fixture_removed']=False
            if fixture and not report['cleanup']['fixture_removed']:report['cleanup']['retained_owned_fixture']=fixture
    report['logs']={'helper-dispatch.jsonl':{'sha256':sha(out/'helper-dispatch.jsonl'),'bytes':(out/'helper-dispatch.jsonl').stat().st_size}}
    report['diagnostic_capture']=args.diagnostic_capture
    report['selected_complete']=failure is None and report.get('source_stable') is True and report['cleanup']['fixture_removed'] and len(report['owned_jobs'])==2
    report['complete']=report['selected_complete'] and not args.diagnostic_capture
    (out/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print('MAC_OWNED_HELPER_COMPLETE',report['complete'],len(report['checks']),flush=True)
    if not report['complete']:raise SystemExit(1)
if __name__=='__main__':main()
