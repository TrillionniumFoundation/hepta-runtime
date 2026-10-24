#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real v6 native MCP + reviewed stdio facade request-cancellation qualification.
Uses six fixed SSH aliases sequentially and only owned temporary fixture jobs.
Cancellation is a native request intent: the durable business job must continue.
This is local native/facade evidence, never authenticated ChatGPT caller evidence.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from dc_parity_release_six_host_acceptance import HOSTS, digest, services
from runtime_http_acceptance import Client

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
from mcp_tool_contract import ToolContract

EXPECTED_TOOLS = 58
TERMINAL = {'succeeded', 'failed', 'cancelled', 'timed_out', 'launch_failed'}
VERSION_META = {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': {'name':'hepta-owned-cancel-qualification','version':'1'},
}
JOB_SOURCE = """import os,sys,time
with open(sys.argv[1],'a',encoding='ascii') as f:
 f.write('1');f.flush();os.fsync(f.fileno())
print('BEGIN 中文α',flush=True)
print('ERR_BEGIN 中文β',file=sys.stderr,flush=True)
time.sleep(6)
print('END 中文α',flush=True)
print('ERR_END 中文β',file=sys.stderr,flush=True)
"""
EXPECTED_STDOUT = 'BEGIN 中文α\nEND 中文α\n'.encode()
EXPECTED_STDERR = 'ERR_BEGIN 中文β\nERR_END 中文β\n'.encode()


def target_python(ssh, source):
    p = subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',ssh,
        'python3 -c ' + shlex.quote(source)], capture_output=True, text=True,
        timeout=35, check=True)
    return json.loads(p.stdout) if p.stdout.strip() else None


def create_fixture(ssh):
    return target_python(ssh, """
import json,os,pathlib,tempfile
base=pathlib.Path(os.path.realpath(tempfile.mkdtemp(prefix='hepta-v6-real-cancel-')))
(base/'workspace').mkdir(mode=0o700)
(base/'state').mkdir(mode=0o700)
print(json.dumps({'base':str(base),'root':str(base/'workspace'),'uid':os.geteuid()}))
""")


def inspect_once(ssh, fixture):
    return target_python(ssh, """
import hashlib,json,os,pathlib
base=pathlib.Path(""" + repr(fixture['base']) + """)
if not base.name.startswith('hepta-v6-real-cancel-') or base.is_symlink() or base.stat().st_uid!=os.geteuid():
 raise ValueError('owned fixture identity refused')
data=(base/'workspace'/'once').read_bytes()
print(json.dumps({'once':data.decode('ascii'),'sha256':hashlib.sha256(data).hexdigest()}))
""")


def remove_fixture(ssh, fixture):
    return target_python(ssh, """
import json,os,pathlib,shutil
base=pathlib.Path(""" + repr(fixture['base']) + """)
if not base.name.startswith('hepta-v6-real-cancel-') or base.is_symlink() or base.stat().st_uid!=os.geteuid():
 raise ValueError('owned fixture cleanup refused')
if base.stat().st_uid!=""" + str(fixture['uid']) + """:raise ValueError('fixture UID changed')
shutil.rmtree(base)
print(json.dumps({'removed':True}))
""")


def decode_tool(reply):
    if 'error' in reply or reply.get('result',{}).get('isError'):
        raise RuntimeError('owned facade tool result rejected')
    blocks=reply['result'].get('content',[])
    text='\n'.join(x.get('text','') for x in blocks if x.get('type')=='text')
    return json.loads(text)


class OwnedWire:
    """Unique outer IDs; records only this test's own credential-free RPC frames."""
    def __init__(self, command, wire_log, stderr_log):
        self.counter=0;self.buffer=bytearray();self.sent=[]
        self.writer=wire_log
        self.proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=stderr_log,bufsize=0)
        self.rpc('server/discover',{})

    def record(self, direction, frame):
        self.writer.write(json.dumps({'direction':direction,'frame':frame},
            ensure_ascii=False,separators=(',',':'))+'\n')
        self.writer.flush()

    def send(self, method, params, notify=False):
        self.counter+=1
        ident='owned-'+str(self.counter)+'-'+uuid.uuid4().hex[:10]
        payload={'jsonrpc':'2.0','method':method,'params':dict(params)}
        if not notify:
            payload['id']=ident
            payload['params']['_meta']=dict(VERSION_META)
        self.record('request',payload);self.sent.append(payload)
        self.proc.stdin.write((json.dumps(payload,ensure_ascii=False,separators=(',',':'))+'\n').encode())
        self.proc.stdin.flush()
        return None if notify else ident

    def receive(self, ident, timeout=35):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if b'\n' in self.buffer:
                raw,_,rest=self.buffer.partition(b'\n');self.buffer=bytearray(rest)
                frame=json.loads(raw);self.record('response',frame)
                if frame.get('id')!=ident:
                    raise RuntimeError('unexpected or duplicate owned outer response identity')
                return frame
            wait=max(0,deadline-time.monotonic())
            if not select.select([self.proc.stdout],[],[],wait)[0]:break
            chunk=os.read(self.proc.stdout.fileno(),65536)
            if not chunk:raise RuntimeError('facade closed before owned response; no replay')
            self.buffer.extend(chunk)
            if len(self.buffer)>16*1024*1024:raise RuntimeError('owned response bound exceeded')
        raise TimeoutError('owned operation response unavailable; no automatic retry')

    def rpc(self, method, params):
        return self.receive(self.send(method,params))

    def call(self, name, args):
        return decode_tool(self.rpc('tools/call',{'name':name,'arguments':args}))

    def start_call(self,name,args):
        return self.send('tools/call',{'name':name,'arguments':args})

    def cancel(self,ident):
        self.send('notifications/cancelled',{'requestId':ident},notify=True)

    def close(self):
        if self.proc.stdin and not self.proc.stdin.closed:self.proc.stdin.close()
        try:self.proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=3)
        self.proc.stdout.close()


def audit_rows(state):
    directory=state/'request-audit'
    if not directory.exists():return {}
    rows={}
    for path in directory.glob('*.json'):
        row=json.loads(path.read_text())
        # Never persist owner, private directory handles or caller-supplied metadata.
        rows[row['request_id']]={k:row[k] for k in
            ('request_id','tool_name','state','accepted_unix_ms','elapsed_ms')}
    return rows


def observe_intent(state,before,tool,timeout=3):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        rows=audit_rows(state)
        candidates=[row for key,row in rows.items()
            if key not in before and row['tool_name']==tool and row['elapsed_ms'] is None]
        if len(candidates)>1:raise RuntimeError('ambiguous owned native durable intent')
        if candidates:return candidates[0]
        time.sleep(.025)
    raise TimeoutError('real native durable intent not observed before cancellation')


def observe_completion(state,request_id,timeout=20):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        row=audit_rows(state).get(request_id)
        if row and row['elapsed_ms'] is not None:return row
        time.sleep(.025)
    raise TimeoutError('native request did not produce durable completion metadata')


def history_record(wire,request_id):
    after=None;seen=set()
    for _ in range(8):
        page=wire.call('request_history',{'limit':32,**({'after_id':after} if after else {})})
        assert page['session_scope']=='native_mcp_session_only'
        assert page['cross_session_resume'] is False
        for row in page['requests']:
            if row['request_id']==request_id:return row
        after=page.get('next_after_id')
        if not after:break
        if after in seen:raise RuntimeError('owned history cursor failed to advance')
        seen.add(after)
    raise RuntimeError('facade history cannot find its real native owned request')


def qualify_host(wire,direct,state,name,ssh,fixture):
    checks=[];job=None
    params={'host':name,'executable':'/usr/bin/python3','args':['-u','-c',JOB_SOURCE,fixture['root']+'/once'],
        'cwd':fixture['root'],'timeout_seconds':20,'idempotency_key':'owned-once-'+uuid.uuid4().hex}
    start=wire.call('process_start',params)
    job=start['job']['id']
    assert start['reused'] is False and start['job']['launch_state']=='launched'
    checks.append('one genuine owned job submitted and job ID retained')

    before=set(audit_rows(state))
    unknown_outer=wire.start_call('process_wait',{'host':name,'job_id':job,'timeout_seconds':1})
    unknown_intent=observe_intent(state,before,'process_wait')
    wire.cancel('not-an-active-owned-request-'+uuid.uuid4().hex)
    unknown_reply=wire.receive(unknown_outer)
    unknown_result=decode_tool(unknown_reply)
    assert unknown_result['state']=='running','six-second owned job ended before unknown-cancel probe'
    unknown_final=observe_completion(state,unknown_intent['request_id'])
    assert unknown_final['state']=='completed'
    unknown_history=history_record(wire,unknown_intent['request_id'])
    assert unknown_history['state']=='completed'
    checks.append('unknown cancellation cannot cancel another active native wait')

    before=set(audit_rows(state))
    outer=wire.start_call('process_wait',{'host':name,'job_id':job,'timeout_seconds':10})
    intent=observe_intent(state,before,'process_wait')
    assert intent['state']=='unknown' and intent['elapsed_ms'] is None
    wire.cancel(outer)
    reply=wire.receive(outer)
    if 'error' in reply:
        details=reply['error'].get('data',{})
        assert details.get('automatic_retry') is False
        assert details.get('cancellation')=='request_intent_only'
        assert details.get('outcome')=='unavailable'
        wait_shape='facade_read_response_unavailable_after_request_cancel'
    else:
        waited=decode_tool(reply)
        assert waited['job_id']==job
        wait_shape='native_wait_result_generated_after_cancel'
    final=observe_completion(state,intent['request_id'])
    assert final['state']=='unknown','native context cancellation was not observed; retain failure'
    history=history_record(wire,intent['request_id'])
    assert history['state']=='unknown'
    assert history['request_id']==intent['request_id']
    checks.append('real stdio cancellation reaches native context; facade history says unknown')

    # Request cancellation is not durable job termination. Read-only reconciliation
    # uses the same ID and never resends process_start or invents another key.
    status=direct.call('process_status',{'host':name,'job_id':job})
    if status['state']=='running':
        status=direct.call('process_wait',{'host':name,'job_id':job,'timeout_seconds':25})
    assert status['job_id']==job and status['state']=='succeeded' and status['exit_code']==0
    assert status['output_complete'] is True
    output=wire.call('process_read',{'host':name,'job_id':job,'limit':16384})
    stdout=bytes.fromhex(output['stdout']['bytes_hex'])
    stderr=bytes.fromhex(output['stderr']['bytes_hex'])
    assert stdout==EXPECTED_STDOUT and stderr==EXPECTED_STDERR
    assert output['stdout']['eof'] is True and output['stderr']['eof'] is True
    assert output['stdout']['next_offset']==len(stdout) and output['stderr']['next_offset']==len(stderr)
    once=inspect_once(ssh,fixture)
    assert once['once']=='1'
    own_starts=[x for x in wire.sent if x['method']=='tools/call'
        and x['params'].get('name')=='process_start'
        and x['params']['arguments'].get('host')==name]
    assert len(own_starts)==1
    checks.append('same job completes with exact Unicode stdout/stderr and once=1; no business replay')

    before=set(audit_rows(state))
    health=wire.call('host_health',{'host':name})
    health_intents=[x for key,x in audit_rows(state).items()
        if key not in before and x['tool_name']=='host_health']
    assert len(health_intents)==1
    health_history=history_record(wire,health_intents[0]['request_id'])
    assert health_history['state']=='completed'
    assert health['reachable'] is True
    checks.append('ordinary facade health works after cancellation; native request is completed')
    return {'host':name,'job_id':job,'passed':len(checks),'complete':True,'checks':checks,
        'unknown_cancel_audit':unknown_history,'cancelled_wait_audit':history,
        'wait_response_shape':wait_shape,'job_terminal':{'state':status['state'],'exit_code':status['exit_code'],
            'output_complete':status['output_complete']},
        'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
        'once_sha256':once['sha256'],'process_start_submission_count':len(own_starts)}


def redacted_log(raw,token,private_root):
    text=raw.decode('utf-8',errors='backslashreplace')
    if token:text=text.replace(token,'[REDACTED_TOKEN]')
    text=text.replace(str(private_root),'[OWNED_CONTROLLER]')
    # Do not publish HTTP authorization/header captures, even if an unexpected
    # library emits them. Real test RPC frames are retained separately.
    safe=[]
    for line in text.splitlines(keepends=True):
        if any(name in line.lower() for name in
            ('x-hepta-runtime-token','authorization:','mcp-session-id:')):
            safe.append('[REDACTED_HEADER_LINE]\n')
        else:safe.append(line)
    return ''.join(safe).encode()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binaryrelease',required=True)
    ap.add_argument('--contract',required=True)
    ap.add_argument('--receipt-dir',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--host',choices=[name for name,_ in HOSTS])
    args=ap.parse_args()
    binary=pathlib.Path(args.binaryrelease).resolve(strict=True)
    contract_path=pathlib.Path(args.contract).resolve(strict=True)
    contract_sha=digest(contract_path)
    contract=ToolContract.load(contract_path,contract_sha)
    assert len(contract.tools)==EXPECTED_TOOLS
    required={'process_start','process_wait','process_status','process_read','host_health','request_history'}
    assert required<=set(contract.by_name)
    directory=pathlib.Path(args.receipt_dir).resolve()
    directory.mkdir(parents=True,exist_ok=False,mode=0o700)
    output=pathlib.Path(args.out)
    if output.exists():raise ValueError('receipt output must be absent')
    selected=[item for item in HOSTS if not args.host or item[0]==args.host]
    baseline=services()
    assert all(x.get('ActiveState')=='active' and x.get('MainPID')!='0' for x in baseline.values())
    report={'schema':'hepta-v6-real-native-stdio-request-cancel-v1',
        'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_head':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
        'binary_sha256':digest(binary),'adapter_sha256':digest(ROOT/'deploy/chatgpt_full_operator.py'),
        'contract_sha256':contract_sha,'contract_catalog_sha256':contract.catalog_sha256,
        'contract_tool_count':len(contract.tools),
        'script_sha256':digest(pathlib.Path(__file__).resolve()),
        'origin':'local_native_and_stdio_facade','chatgpt_originated':False,
        'authenticated_scope':'native_session_and_private_adapter_channel_only',
        'cancellation_semantics':'request_intent_only_not_durable_job_termination',
        'production_or_DC_restarted':False,'business_workspaces_changed':False,
        'full_dc_replacement_qualified':False,'protected_services_before':baseline,
        'selected_hosts':[x[0] for x in selected],'results':[],'cleanup':[],'complete':False}
    fixtures={};jobs={};terminal={};wire=None;direct=None;native=None;token_value=''
    failure=None
    with tempfile.TemporaryDirectory(prefix='hepta-v6-cancel-controller-') as controller:
        base=pathlib.Path(controller).resolve();state=base/'state';workspace=base/'workspace';workspace.mkdir(mode=0o700)
        native_stdout=base/'native.stdout.raw';native_stderr=base/'native.stderr.raw';facade_stderr=base/'facade.stderr.raw'
        try:
            for name,ssh in selected:fixtures[name]=create_fixture(ssh)
            hosts={name:{'ssh_target':ssh,'platform':'macos' if name=='mac' else 'linux',
                'execution_mode':'operator','remote_state_dir':fixtures[name]['base']+'/state',
                'allow_execute':True,'allow_pty':False,'allow_write':True,
                'allow_job_network':True,'allow_detached_fallback':True,
                'allowed_read_path_prefixes':[fixtures[name]['root']],
                'allowed_write_path_prefixes':[fixtures[name]['root']]}
                for name,ssh in selected}
            config=base/'runtime.json';config.write_text(json.dumps({'state_dir':str(state),
                'controller_workspace_roots':[str(workspace)],'hosts':hosts}))
            token=base/'token';token_value=secrets.token_hex(32);token.write_text(token_value);token.chmod(0o600)
            with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            endpoint=f'http://127.0.0.1:{port}/mcp'
            native_command=[str(binary),'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}',
                '--runtime-config',str(config),'--auth-token-file',str(token)]
            with native_stdout.open('wb') as nout,native_stderr.open('wb') as nerr:
                native=subprocess.Popen(native_command,stdin=subprocess.DEVNULL,stdout=nout,stderr=nerr)
                for _ in range(90):
                    if native.poll() is not None:raise RuntimeError('owned native controller exited at startup')
                    try:direct=Client(endpoint,token_value);break
                    except (OSError,RuntimeError):time.sleep(.1)
                else:raise TimeoutError('owned native controller did not start')
                native_catalog=direct.rpc('tools/list',{})['tools'];contract.verify(native_catalog)
                with (directory/'owned-wire.jsonl').open('x',encoding='utf-8') as transcript,facade_stderr.open('wb') as ferr:
                    wire=OwnedWire([sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio',
                        '--upstream',endpoint,'--token-file',str(token),'--contract',str(contract_path),
                        '--contract-sha256',contract_sha,'--acknowledge-full-operator'],transcript,ferr)
                    facade_catalog=wire.rpc('tools/list',{})['result']['tools'];contract.verify(facade_catalog)
                    for name,ssh in selected:
                        # The local job record is the authoritative retained ID even
                        # if a later response/assertion fails; never resubmit a start.
                        before_jobs=set(path.stem for path in (state/'jobs').glob('*.json'))
                        try:
                            row=qualify_host(wire,direct,state,name,ssh,fixtures[name])
                            jobs[name]=row['job_id'];terminal[name]=True
                            report['results'].append(row)
                            print('PASS',name,'real-native-facade-cancel',row['passed'],flush=True)
                        finally:
                            for p in (state/'jobs').glob('*.json'):
                                if p.stem not in before_jobs:
                                    rec=json.loads(p.read_text())
                                    if rec['host']==name:jobs[name]=rec['id']
                    report['candidate_hashes_stable']=(digest(binary)==report['binary_sha256']
                        and digest(ROOT/'deploy/chatgpt_full_operator.py')==report['adapter_sha256']
                        and digest(contract_path)==contract_sha)
        except Exception as exc:
            failure=exc
            report['error_type']=type(exc).__name__
            report['error']=redacted_log(str(exc).encode(),token_value,base).decode()[:2000]
        finally:
            # Query only our recorded IDs. No arbitrary host PID signals, DC calls
            # or business command replay are used for cleanup.
            for name,ssh in selected:
                if name not in fixtures:continue
                try:
                    if name in jobs and not terminal.get(name):
                        if direct is None:raise RuntimeError('owned job state cannot be confirmed')
                        status=direct.call('process_status',{'host':name,'job_id':jobs[name]})
                        if status['state']=='running':
                            status=direct.call('process_wait',{'host':name,'job_id':jobs[name],'timeout_seconds':25})
                        terminal[name]=status['state'] in TERMINAL and status.get('output_complete') is True
                    safe=name not in jobs or terminal.get(name) is True
                    if not safe:raise RuntimeError('owned job not confirmed terminal; fixture retained')
                    remove_fixture(ssh,fixtures[name])
                    report['cleanup'].append({'host':name,'removed':True,'job_id':jobs.get(name),'job_terminal_confirmed':name not in jobs or terminal.get(name) is True})
                except Exception as exc:
                    report['cleanup'].append({'host':name,'removed':False,'error_type':type(exc).__name__,
                        'retained_owned_fixture':fixtures[name]['base'],'job_id':jobs.get(name)})
            report['owned_jobs']=[{'host':name,'job_id':job_id,'terminal_confirmed':terminal.get(name) is True}
                for name,job_id in jobs.items()]
            if wire is not None:
                try:wire.close()
                except Exception as exc:report['facade_close_error_type']=type(exc).__name__
            if native is not None and native.poll() is None:
                native.terminate()
                try:native.wait(timeout=10)
                except subprocess.TimeoutExpired:native.kill();native.wait(timeout=5)
            logs={}
            for label,path in [('native-stdout',native_stdout),('native-stderr',native_stderr),('facade-stderr',facade_stderr)]:
                raw=path.read_bytes() if path.exists() else b''
                saved=directory/(label+'.log')
                saved.write_bytes(redacted_log(raw,token_value,base))
                logs[label]={'bytes':saved.stat().st_size,'sha256':digest(saved),'redacted':True}
            transcript=directory/'owned-wire.jsonl'
            if transcript.exists():logs['owned-wire']={'bytes':transcript.stat().st_size,'sha256':digest(transcript),
                'content':'only unique test-owned RPC requests/responses; no tokens or HTTP headers'}
            report['logs']=logs
    try:
        report['protected_services_after']=services()
        report['service_identity_stable']=report['protected_services_after']==baseline
    except Exception as exc:
        report['service_identity_stable']=False
        report['service_observation_error_type']=type(exc).__name__
    report['selected_complete']=(failure is None and len(report['results'])==len(selected)
        and all(x['complete'] for x in report['results']) and report.get('candidate_hashes_stable') is True
        and report['service_identity_stable'] and len(report['cleanup'])==len(selected)
        and all(x['removed'] for x in report['cleanup']))
    report['complete']=(report['selected_complete'] and len(selected)==len(HOSTS))
    with output.open('x',encoding='utf-8') as f:f.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('REAL_NATIVE_CANCEL_COMPLETE',report['complete'],'SELECTED_COMPLETE',report['selected_complete'],flush=True)
    if failure is not None or not report['selected_complete']:sys.exit(1)

if __name__=='__main__':
    main()
