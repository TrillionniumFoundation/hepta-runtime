#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real full-facade -> installed runtime -> selected-host acceptance.
Only disposable paths/processes are touched. The runtime, DC and tunnel are never
restarted. These are local-origin tests, not evidence of a ChatGPT-origin call.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import select
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]


class StdioClient:
    def __init__(self,command,log):
        self.command=command;self.log=log;self.counter=0
        self.proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0)
        initial=self.rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'hepta-full-local-qualification','version':'1'}})
        if 'error' in initial:
            self.close();raise RuntimeError(json.dumps(initial))
        self.proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
    def rpc(self,method,params):
        self.counter+=1;number=self.counter
        self.proc.stdin.write((json.dumps({'jsonrpc':'2.0','id':number,'method':method,'params':params},ensure_ascii=False)+'\n').encode())
        self.proc.stdin.flush()
        deadline=time.monotonic()+180;output=bytearray()
        while time.monotonic()<deadline:
            if not select.select([self.proc.stdout],[],[],max(0,deadline-time.monotonic()))[0]:break
            # Read available bytes without buffered-file prefetch hiding readiness.
            part=os.read(self.proc.stdout.fileno(),65536)
            if not part:raise RuntimeError('facade terminated before result')
            output.extend(part)
            if len(output)>17*1024*1024:raise RuntimeError('facade output too large')
            if output.endswith(b'\n'):
                result=json.loads(output);assert result.get('id')==number
                return result
        raise TimeoutError('operation outcome unknown; no automatic retry')
    def call(self,name,args,denied=False):
        result=self.rpc('tools/call',{'name':name,'arguments':args})
        failed='error' in result or result.get('result',{}).get('isError',False)
        if denied:
            assert failed,(name,result)
            return result
        if failed:raise RuntimeError(json.dumps(result))
        blocks=result['result'].get('content',[])
        text=next((b['text'] for b in blocks if b['type']=='text'),None)
        if text is None:return result['result']
        try:return json.loads(text)
        except json.JSONDecodeError:return text
    def close(self):
        if self.proc.poll() is None:self.proc.terminate()
        self.proc.wait(timeout=10)
        for stream in (self.proc.stdin,self.proc.stdout):stream.close()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--host',required=True);ap.add_argument('--ssh-target',required=True)
    ap.add_argument('--facade',default=str(ROOT/'deploy/chatgpt_full_operator.py'));ap.add_argument('--contract',default=str(ROOT/'deploy/contracts/hepta-runtime-full-operator-v1.json'))
    ap.add_argument('--token-file',default=str(pathlib.Path.home()/'.config/hepta-runtime-operator/token'));ap.add_argument('--upstream',default='http://127.0.0.1:8790/mcp');ap.add_argument('--out',required=True)
    ap.add_argument('--sudo-smoke',action='store_true');a=ap.parse_args()
    contract=pathlib.Path(a.contract);contract_sha=hashlib.sha256(contract.read_bytes()).hexdigest();key=uuid.uuid4().hex;target='/tmp/hepta-full-operator-'+key
    command=[sys.executable,a.facade,'--stdio','--upstream',a.upstream,'--token-file',a.token_file,'--contract',str(contract),'--contract-sha256',contract_sha,'--acknowledge-full-operator']
    report={'host':a.host,'ssh_target':a.ssh_target,'complete':False,'checks':[],'local_facade_origin':True,'chatgpt_originated':False,'tunnel_originated':False,'runtime_or_DC_restarted':False,'business_files_touched':False,'contract_sha256':contract_sha,'target_directory':target}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(name,details=None):report['checks'].append({'name':name,'details':details});save();print('PASS',name,flush=True)
    with tempfile.TemporaryFile('w+b') as log:
        client=None;sessions=[]
        try:
            client=StdioClient(command,log)
            listed=client.rpc('tools/list',{})['result']['tools'];original=json.loads(contract.read_text())['tools']
            assert listed==original and len(listed)==len(original)
            report['pinned_tool_count']=len(original)
            for name in ('shell_start','sudo_start','host_signal','pty_write','binary_write','document_write'):
                tool=next(t for t in listed if t['name']==name);assert not tool['annotations']['readOnlyHint'] and tool['annotations']['destructiveHint']
            client.call('unreviewed_tool',{},denied=True)
            passed(f'all {len(original)} native tools and exact schemas/annotations, unknown direct call denied')
            hosts=client.call('host_list',{})['hosts'];host=next(h for h in hosts if h['name']==a.host)
            assert host['execution_mode']=='operator'
            if host.get('platform')=='macos':
                target='/private'+target;report['target_directory']=target
            passed('configured real operator host selected')
            def wait(job):
                for _ in range(10):
                    result=client.call('process_wait',{'host':a.host,'job_id':job,'timeout_seconds':10})
                    if result['state'] not in ('running','launching','pending'):return result
                raise TimeoutError('fixture job not terminal')
            def read_job(job):return client.call('process_read',{'host':a.host,'job_id':job})
            params={'host':a.host,'cwd':'/tmp','command':'umask 077; mkdir '+shlex.quote(target)+'; printf "alpha\\nbeta\\n" | tail -n1 > '+shlex.quote(target+'/shell.txt')+'; cat '+shlex.quote(target+'/shell.txt')+'; printf "%s\\n" "$HEPTA_VALUE"; id -u',
                    'env':{'HEPTA_VALUE':'中文 ; $() literal'},'idempotency_key':key+'-shell','timeout_seconds':30}
            job=client.call('shell_start',params)['job']['id'];assert wait(job)['state']=='succeeded'
            output=read_job(job)['stdout']['text'];assert 'beta\n' in output and '中文 ; $() literal' in output
            assert client.call('shell_start',params)['job']['id']==job
            client.call('shell_start',{**params,'command':'echo DIFFERENT'},denied=True)
            passed('actual shell pipeline/redirection/env/Unicode and native request idempotency')
            data=bytes(range(256))*4096;path=target+'/large-request.bin'
            binary=client.call('binary_write',{'host':a.host,'path':path,'expected_version':'absent','data_base64':base64.b64encode(data).decode()})
            info=client.call('file_info',{'host':a.host,'path':path});assert info['size']==len(data) and info['sha256']==hashlib.sha256(data).hexdigest()
            passed('actual binary write with >1-MiB JSON request, complete target SHA256',{'bytes':len(data)})
            doc=target+'/document.docx';created=client.call('document_write',{'host':a.host,'path':doc,'format':'docx','expected_sha256':'absent','content':'# Full Operator\nOriginal 中文'})
            client.call('document_edit',{'host':a.host,'path':doc,'expected_sha256':created['sha256'],'old_xml':'Original','new_xml':'Edited'})
            viewed=client.call('document_read',{'host':a.host,'path':doc});assert 'Edited' in str(viewed)
            passed('native document write/edit/read over unchanged installed backend')
            def pty_until(sid,marker):
                for _ in range(100):
                    value=client.call('pty_read',{'host':a.host,'session_id':sid})
                    if marker in value['text']:return value
                    if value['status']['state']!='running':raise RuntimeError(str(value))
                    time.sleep(.05)
                raise TimeoutError('fixture PTY marker missing')
            sid=client.call('pty_start',{'host':a.host,'executable':'/bin/sh','args':['-i'],'cwd':target,'idempotency_key':key+'-pty'})['session_id'];sessions.append(sid)
            client.call('pty_write',{'host':a.host,'session_id':sid,'data':"printf 'READY_%s\\n' OK\n",'request_id':'ready'})
            pty_until(sid,'READY_OK');client.call('pty_write',{'host':a.host,'session_id':sid,'data':'sleep 20\n','request_id':'sleep'})
            time.sleep(.2);client.call('pty_write',{'host':a.host,'session_id':sid,'data':'\x03','request_id':'ctrl-c'})
            client.call('pty_write',{'host':a.host,'session_id':sid,'data':"printf 'CTRL_%s\\n' OK\n",'request_id':'after'});pty_until(sid,'CTRL_OK')
            client.call('pty_write',{'host':a.host,'session_id':sid,'data':'exit\n','request_id':'exit'});client.call('pty_close',{'host':a.host,'session_id':sid});sessions.remove(sid)
            passed('actual interactive PTY input, output, Ctrl-C and close')
            # Create only this self-expiring fixture outside runtime, then test native
            # identity-aware signals; no business PID or generic cleanup is selected.
            code="import subprocess,sys,json;p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);print(json.dumps({'pid':p.pid}))"
            spawned=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=8',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=20)
            if spawned.returncode:raise RuntimeError(spawned.stderr[-500:])
            pid=json.loads(spawned.stdout)['pid'];row=client.call('host_processes',{'host':a.host,'after_pid':pid-1,'limit':1})['processes'][0];assert row['pid']==pid
            signal={'host':a.host,'pid':pid,'expected_identity':row['identity'],'signal':0}
            assert client.call('host_signal',signal)['result']=='probe_succeeded'
            client.call('host_signal',{**signal,'expected_identity':'stale-fixture-identity','signal':15},denied=True)
            assert client.call('host_signal',signal)['result']=='probe_succeeded'
            delivered=client.call('host_signal',{**signal,'signal':15});assert delivered['result']=='signal_sent'
            passed('external disposable PID: stale identity refusal and actual authorized signal',{'fixture_pid':pid})
            if a.sudo_smoke:
                sid=client.call('sudo_start',{'host':a.host,'executable':'/usr/bin/id','args':['-u'],'non_interactive':True})['session_id'];sessions.append(sid)
                result=pty_until(sid,'0\r\n');assert result['text'].strip()=='0'
                client.call('pty_close',{'host':a.host,'session_id':sid});sessions.remove(sid)
                passed('temporary sudo PTY real UID 0 through existing host authorization')
            resume={'host':a.host,'cwd':target,'command':"printf x >> once; sleep 2; printf COUNT=; wc -c < once",'idempotency_key':key+'-resume','timeout_seconds':20}
            job=client.call('shell_start',resume)['job']['id'];client.close();client=StdioClient(command,log)
            assert client.call('shell_start',resume)['job']['id']==job and wait(job)['state']=='succeeded'
            assert 'COUNT=1' in read_job(job)['stdout']['text'].replace(' ','')
            passed('facade-only restart preserves existing durable job and once-only effect')
            report.update(complete=True,passed=len(report['checks']));save();print('FULL_OPERATOR_ACCEPTANCE_PASS',report['passed'],flush=True)
        finally:
            if client is not None:
                for sid in sessions:
                    try:client.call('pty_close',{'host':a.host,'session_id':sid})
                    except Exception:pass
                client.close()
            save()


if __name__=='__main__':main()
