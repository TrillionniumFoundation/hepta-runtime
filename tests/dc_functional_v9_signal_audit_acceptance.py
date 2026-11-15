#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Six genuine targets: owned PID-pinned TERM + local audit/ACK fault injection.
A private ssh forwarding wrapper always executes real /usr/bin/ssh with the
native configured arguments. Faults occur only AFTER a genuine signal ACK, or
before native intent recording in this disposable controller's legacy audit.
No product policy, installed service, existing business process or credential is modified.
"""
import argparse
from dc_functional_v9_version_pin import add_helper_pins, verify_helper_pins
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import stat
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import traceback
import importlib.util
import re

from dc_parity_release_six_host_acceptance import HOSTS, digest, services
from runtime_http_acceptance import Client

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
ToolContract=None

TERMINAL={'succeeded','failed','cancelled','timed_out','launch_failed'}

CHILD_SOURCE="""import json,os,pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1]);count=0
def save(name,value):
 p=root/name;t=root/(name+'.tmp')
 t.write_text(json.dumps(value));os.replace(t,p)
def term(signum,frame):
 global count
 count+=1
 save('counter',{'count':count,'pid':os.getpid(),'uid':os.geteuid()})
 print('TERM_COUNT='+str(count),flush=True)
signal.signal(signal.SIGTERM,term)
save('counter',{'count':0,'pid':os.getpid(),'uid':os.geteuid()})
save('ready',{'pid':os.getpid(),'uid':os.geteuid()})
print('READY',flush=True)
deadline=time.monotonic()+90
while not (root/'release').exists() and time.monotonic()<deadline:time.sleep(.05)
print('RELEASED',flush=True)
"""

BRIDGE_SOURCE="""#!/usr/bin/python3
import hashlib,json,os,pathlib,subprocess,sys
data=sys.stdin.buffer.read()
control=pathlib.Path(os.environ['HEPTA_SIGNAL_FAULT_CONTROL'])
events=pathlib.Path(os.environ['HEPTA_SIGNAL_BRIDGE_EVENTS'])
try:q=json.loads(data)
except (ValueError,UnicodeError):q={}
fault=json.loads(control.read_text()) if control.exists() else {'mode':'normal'}
is_signal=q.get('op')=='signal'
mode=fault.get('mode','normal') if is_signal else 'normal'
actual=subprocess.run(['/usr/bin/ssh',*sys.argv[1:]],input=data,capture_output=True)
if is_signal:
 try:ack=json.loads(actual.stdout)
 except (ValueError,UnicodeError):ack=None
 row={'mode':mode,'pid':q.get('pid'),'signal':q.get('signal'),
  'expected_identity':q.get('expected_identity'),'real_ssh_exit':actual.returncode,
  'real_ack':ack,'stdout_sha256':hashlib.sha256(actual.stdout).hexdigest(),
  'stderr_sha256':hashlib.sha256(actual.stderr).hexdigest()}
 with events.open('a',encoding='utf-8') as f:
  f.write(json.dumps(row,separators=(',',':'))+'\\n');f.flush();os.fsync(f.fileno())
 if actual.returncode==0 and mode=='completion_audit_failure':
  path=pathlib.Path(fault['audit_path']);backup=pathlib.Path(fault['backup_path'])
  if backup.exists() or not path.is_file() or path.is_symlink():raise RuntimeError('owned audit fault precondition')
  os.replace(path,backup);path.mkdir(mode=0o700)
 if actual.returncode==0 and mode=='lost_ack':
  raise SystemExit(255)
 if actual.returncode==0 and mode=='invalid_ack':
  sys.stdout.buffer.write(b'NOT_A_SIGNAL_ACK\\n');sys.stdout.buffer.flush()
  raise SystemExit(0)
sys.stdout.buffer.write(actual.stdout);sys.stdout.buffer.flush()
sys.stderr.buffer.write(actual.stderr);sys.stderr.buffer.flush()
raise SystemExit(actual.returncode)
"""



def source_identity():
    """Fingerprint compile inputs independently of HEAD and generated locks."""
    paths=set(ROOT.glob('src/**/*.rs'))|set(ROOT.glob('src/**/*.py'))
    paths.update([ROOT/'Cargo.toml',ROOT/'Cargo.lock'])
    entries={}
    for path in sorted(paths,key=lambda value:value.relative_to(ROOT).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError('compile input must be a regular non-symlink file')
        raw=path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    head=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    scope=['src','Cargo.toml','Cargo.lock']
    changed=subprocess.check_output(['git','-C',str(ROOT),'diff','--name-only','--no-renames','-z','HEAD','--',*scope],text=True).split('\0')
    tracked=set(subprocess.check_output(['git','-C',str(ROOT),'ls-files','--cached','-z','--',*scope],text=True).split('\0'))
    def is_compile(p):return p in ('Cargo.toml','Cargo.lock') or (p.startswith('src/') and pathlib.PurePosixPath(p).suffix in ('.rs','.py'))
    dirty=any(is_compile(p) for p in changed) or not set(entries)<=tracked
    encoded=json.dumps(entries,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    return {'base_HEAD':head,'dirty_source':bool(dirty),
        'source_fingerprint_algorithm':'sha256(canonical sorted relative path -> byte-count and sha256 map)',
        'source_code_fingerprint':hashlib.sha256(encoded).hexdigest(),'source_files':entries}


def private_controller_directory():
    """Keep failed state outside the repository; never publish its auth token."""
    parent=pathlib.Path.home()/'.local/state/hepta-runtime-acceptance'
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('private acceptance state directory identity/mode refused')
    return pathlib.Path(tempfile.mkdtemp(prefix='hepta-v8-signal-controller-',dir=parent)).resolve()


def save_private_json(path,value):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(descriptor,'w',encoding='utf-8') as writer:
        json.dump(value,writer,ensure_ascii=False,indent=2);writer.write('\n');writer.flush();os.fsync(writer.fileno())


class TargetOperationError(RuntimeError):
    def __init__(self, error_type, returncode=None, stderr=b'', stdout=b''):
        super().__init__('fixed target SSH operation failed; inspect retained diagnostic')
        self.transport_error_type=error_type;self.returncode=returncode
        self.stderr=stderr if isinstance(stderr,bytes) else str(stderr or '').encode()
        self.stdout=stdout if isinstance(stdout,bytes) else str(stdout or '').encode()
    def diagnostic(self,token='',base=''):
        return {'transport_error_type':self.transport_error_type,'returncode':self.returncode,
            'stderr_tail':redacted(self.stderr[-4096:],token,base).decode('utf-8')[-2000:],
            'stdout_sha256':hashlib.sha256(self.stdout).hexdigest()}


def target_python(ssh,source):
    try:
        p=subprocess.run(['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ForwardAgent=no','-o','ConnectTimeout=10',ssh,
            '/usr/bin/python3 -c '+shlex.quote(source)],capture_output=True,text=True,timeout=35)
    except subprocess.TimeoutExpired as error:
        raise TargetOperationError('TimeoutExpired',None,error.stderr,error.stdout) from None
    if p.returncode:
        raise TargetOperationError('NonzeroSSHExit',p.returncode,p.stderr,p.stdout)
    try:return json.loads(p.stdout) if p.stdout.strip() else None
    except json.JSONDecodeError:
        raise TargetOperationError('InvalidJSONAcknowledgement',p.returncode,p.stderr,p.stdout) from None


def planned_fixture(name,ssh,nonce):
    if name not in dict(HOSTS) or dict(HOSTS)[name]!=ssh or not re.fullmatch('[0-9a-f]{32}',nonce):
        raise ValueError('fixed configured target and random nonce required')
    parent='/private/tmp' if name=='mac' else '/tmp'
    base=parent+'/hepta-v8-signal-audit-'+nonce
    return {'host':name,'ssh_target':ssh,'parent':parent,'base':base,'root':base+'/workspace',
        'nonce':nonce,'platform':'macos' if name=='mac' else 'linux','uid':None,
        'prepare_attempted':False,'prepare_confirmed':False,'reconcile_readonly':None}


def save_fixture_record(path,item):
    path=pathlib.Path(path);parent=path.parent
    info=parent.lstat()
    if parent.is_symlink() or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('owned private fixture-record directory refused')
    temporary=path.with_name(path.name+'.next')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(descriptor,'w') as writer:
        json.dump(item,writer,sort_keys=True,indent=2);writer.write('\n');writer.flush();os.fsync(writer.fileno())
    if path.exists():
        original=path.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink!=1 or original.st_uid!=os.getuid() or stat.S_IMODE(original.st_mode)!=0o600:
            raise ValueError('owned fixture recovery record identity changed')
    os.replace(temporary,path)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def fixture_guard(item,require_layout=True):
    # Remote read-only descriptor checks bind every later query/removal to this
    # exact planned path, operator UID and single-link nonce marker.
    return """import json,os,pathlib,stat,sys
base=pathlib.Path("""+repr(item['base'])+""")
assert base.is_absolute() and str(base.parent)=="""+repr(item['parent'])+""" and base.name=="""+repr('hepta-v8-signal-audit-'+item['nonce'])+"""
fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd)
 assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.geteuid()=="""+repr(item['uid'])+"""
 marker=os.open('.fixture-owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 try:
  mi=os.fstat(marker);assert stat.S_ISREG(mi.st_mode) and mi.st_nlink==1 and stat.S_IMODE(mi.st_mode)==0o600 and mi.st_uid==info.st_uid and mi.st_size<=2048
  raw=os.read(marker,2049);assert len(raw)==mi.st_size
  ownership=json.loads(raw)
  assert ownership=="""+repr({'schema':'hepta-v8-owned-signal-fixture-v1','host':item['host'],'base':item['base'],'root':item['root'],'nonce':item['nonce'],'uid':item['uid'],'platform':item['platform']})+"""
 finally:os.close(marker)
 linked=base.lstat();assert (linked.st_dev,linked.st_ino)==(info.st_dev,info.st_ino) and not base.is_symlink()
 assert ('linux' if sys.platform=='linux' else 'macos' if sys.platform=='darwin' else 'unsupported')=="""+repr(item['platform'])+"""
finally:os.close(fd)
root=base/'workspace'
"""+("""
for name in ('workspace','state'):
 fd=os.open(base/name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  child=os.fstat(fd);assert stat.S_ISDIR(child.st_mode) and child.st_uid==info.st_uid and stat.S_IMODE(child.st_mode)==0o700
 finally:os.close(fd)
""" if require_layout else '')


def reconcile_fixture(ssh,item):
    source="""import json,pathlib
base=pathlib.Path("""+repr(item['base'])+""")
if not base.exists() and not base.is_symlink():
 print(json.dumps({'present':False,'owned':False,'readonly':True}));raise SystemExit(0)
"""+fixture_guard(item,require_layout=False)+"""
layout_complete=True
for child in ('workspace','state'):
 p=base/child
 try:
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   si=os.fstat(fd);assert si.st_uid==info.st_uid and stat.S_IMODE(si.st_mode)==0o700
  finally:os.close(fd)
 except FileNotFoundError:layout_complete=False
print(json.dumps({'present':True,'owned':True,'readonly':True,'layout_complete':layout_complete}))
"""
    result=target_python(ssh,source)
    if (not isinstance(result,dict) or result.get('readonly') is not True
            or not isinstance(result.get('present'),bool) or not isinstance(result.get('owned'),bool)
            or (result['owned'] and result.get('layout_complete') not in (True,False))):
        raise ValueError('read-only same-fixture reconciliation acknowledgement invalid')
    return result


def prepare_fixture(ssh,item,record_path):
    # The first local record was saved before ANY SSH call by main. This lookup
    # is read-only and binds UID/platform/canonical fixed parent before creation.
    environment=target_python(ssh,"""import json,os,pathlib,stat,sys
p=pathlib.Path("""+repr(item['parent'])+""")
assert p.is_absolute() and not p.is_symlink() and os.path.realpath(p)==str(p)
info=p.stat();assert stat.S_ISDIR(info.st_mode)
print(json.dumps({'parent':str(p),'uid':os.geteuid(),'platform':'linux' if sys.platform=='linux' else 'macos' if sys.platform=='darwin' else 'unsupported'}))
""")
    if (not isinstance(environment,dict) or environment.get('parent')!=item['parent']
            or environment.get('platform')!=item['platform'] or not isinstance(environment.get('uid'),int)
            or isinstance(environment['uid'],bool) or environment['uid']<0):
        raise ValueError('fixed target planning UID/platform/parent differs')
    item['uid']=environment['uid'];item['prepare_attempted']=True
    save_fixture_record(record_path,item)
    expected={'schema':'hepta-v8-owned-signal-fixture-v1','host':item['host'],'base':item['base'],
        'root':item['root'],'nonce':item['nonce'],'uid':item['uid'],'platform':item['platform']}
    source="""import json,os,pathlib,stat,sys
q="""+repr(expected)+"""
base=pathlib.Path(q['base'])
assert str(base.parent)=="""+repr(item['parent'])+""" and not base.exists() and not base.is_symlink()
assert os.geteuid()==q['uid'] and ('linux' if sys.platform=='linux' else 'macos' if sys.platform=='darwin' else 'unsupported')==q['platform']
base.mkdir(mode=0o700) # exactly one create-only attempt; no parents or retry
fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 os.fchmod(fd,0o700)
 marker=os.open('.fixture-owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
 with os.fdopen(marker,'w') as writer:
  json.dump(q,writer,sort_keys=True);writer.write('\\n');writer.flush();os.fsync(writer.fileno())
 os.fsync(fd)
 (base/'workspace').mkdir(mode=0o700);(base/'state').mkdir(mode=0o700)
 os.fsync(fd)
finally:os.close(fd)
print(json.dumps(q))
"""
    try:
        actual=target_python(ssh,source)
        if actual!=expected:raise ValueError('create acknowledgement nonce/root/platform/UID differs from locally sealed plan')
    except Exception as error:
        # This path is never randomized or created again. Lost ACK is a failed
        # run with a read-only same-reference observation, not a launch retry.
        item['prepare_error_type']=type(error).__name__
        if isinstance(error,TargetOperationError):item['prepare_transport']=error.diagnostic()
        try:item['reconcile_readonly']=reconcile_fixture(ssh,item)
        except Exception as reconcile_error:
            item['reconcile_error_type']=type(reconcile_error).__name__
            if isinstance(reconcile_error,TargetOperationError):item['reconcile_transport']=reconcile_error.diagnostic()
        save_fixture_record(record_path,item)
        raise
    item['prepare_confirmed']=True;save_fixture_record(record_path,item)
    return item


def owned_query(ssh,item,operation,want=None):
    if item.get('prepare_confirmed') is not True:
        raise ValueError('unconfirmed prepare has only read-only reconciliation; retained same reference')
    if operation not in ('ready','counter','release','remove'):raise ValueError('owned fixture operation refused')
    return target_python(ssh,fixture_guard(item)+"""
import shutil,time
op="""+repr(operation)+"""
if op=='remove':
 shutil.rmtree(base);result={'removed':True}
elif op=='release':
 (root/'release').write_text('owned release');result={'released':True}
else:
 name='ready' if op=='ready' else 'counter';deadline=time.monotonic()+5;result=None
 while time.monotonic()<deadline:
  try:result=json.loads((root/name).read_text())
  except FileNotFoundError:time.sleep(.025);continue
  if """+repr(want)+""" is None or result.get('count')=="""+repr(want)+""":break
  time.sleep(.025)
 if result is None:raise ValueError('owned child marker missing')
print(json.dumps(result))
""")


def sealed_harness_inputs():
    paths=[pathlib.Path(__file__).resolve(),ROOT/'tests/dc_successor_contract.py',
        ROOT/'tests/runtime_http_acceptance.py',ROOT/'tests/dc_parity_release_six_host_acceptance.py',
        ROOT/'deploy/mcp_tool_contract.py',ROOT/'tests/dc_functional_v9_version_pin.py']
    paths.extend(ROOT/('deploy/contracts/hepta-runtime-full-operator-v'+str(v)+'.json') for v in (4,5,6,7,8,9))
    return {p.relative_to(ROOT).as_posix():{'bytes':p.stat().st_size,'sha256':digest(p)} for p in paths}


def load_reviewed_v9(path,expected_contract,expected_loader,expected_tool_helper):
    global ToolContract
    loader=ROOT/'tests/dc_successor_contract.py';helper=ROOT/'deploy/mcp_tool_contract.py'
    if digest(loader)!=expected_loader or digest(helper)!=expected_tool_helper:
        raise ValueError('reviewed contract loader/tool helper SHA differs from explicit pins')
    if digest(path)!=expected_contract:raise ValueError('reviewed candidate contract SHA differs')
    helper_spec=importlib.util.spec_from_file_location('mcp_tool_contract',helper)
    helper_module=importlib.util.module_from_spec(helper_spec)
    sys.modules['mcp_tool_contract']=helper_module;helper_spec.loader.exec_module(helper_module)
    ToolContract=helper_module.ToolContract
    spec=importlib.util.spec_from_file_location('hepta_signal_reviewed_v8_contract',loader)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if module.REVIEWED_SUCCESSORS.get(expected_contract)!=9:
        raise ValueError('exact explicitly reviewed V9 contract required')
    contract=ToolContract.load(path,expected_contract)
    module.verify_successor(contract.tools,path)
    return contract


class OwnedClient(Client):
    def __init__(self,url,token,trace):
        self.trace=trace
        super().__init__(url,token)
    def call(self,name,args,denied=False):
        result=super().call(name,args,denied)
        # host_processes can return unrelated processes after a dead PID; its
        # response is recorded only after the caller verifies the owned PID.
        if name!='host_processes' and not self.trace.closed:
            self.trace.write(json.dumps({'tool':name,'arguments':args,'result':result},
                ensure_ascii=False,separators=(',',':'))+'\n');self.trace.flush()
        return result
    def owned_process_trace(self,args,row):
        self.trace.write(json.dumps({'tool':'host_processes','arguments':args,
            'verified_owned_process':row},separators=(',',':'))+'\n');self.trace.flush()


def set_fault(control,mode,**fields):
    temp=control.with_suffix('.tmp')
    temp.write_text(json.dumps({'mode':mode,**fields}));temp.chmod(0o600);os.replace(temp,control)


def bridge_rows(events):
    if not events.exists():return []
    return [json.loads(line) for line in events.read_text().splitlines() if line]


def restore_audit(path,backup):
    if path.is_dir():
        if path.is_symlink():raise RuntimeError('refusing audit symlink restoration')
        path.rmdir()
    if backup.exists():
        if path.exists():raise RuntimeError('owned audit destination changed during restoration')
        os.replace(backup,path)


def verify_ack(ack,pid,identity,uid):
    assert ack['pid']==pid and ack['signal']==15 and ack['identity']==identity
    assert ack['result']=='signal_sent' and ack['effective_uid']==uid
    assert ack['termination_confirmed'] is False
    assert isinstance(ack['atomic_identity'],bool)


def redacted(raw,token,base):
    text=raw.decode('utf-8',errors='backslashreplace')
    if token:text=text.replace(token,'[REDACTED_TOKEN]')
    if base:text=text.replace(str(base),'[OWNED_CONTROLLER]')
    text=re.sub(r'(?i)(password|access_token|auth_token)(\s*[:=]\s*)([^\s,;]+)',r'\1\2[REDACTED]',text)
    lines=[]
    for line in text.splitlines(keepends=True):
        if any(x in line.lower() for x in ('x-hepta-runtime-token','authorization','mcp-session-id')):
            lines.append('[REDACTED_HEADER_LINE]\n')
        else:lines.append(line)
    return ''.join(lines).encode()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binaryrelease','--binary',dest='binaryrelease',required=True)
    ap.add_argument('--contract',required=True)
    ap.add_argument('--receipt-dir',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--host',choices=[name for name,_ in HOSTS])
    ap.add_argument('--expected-head','--HEAD',dest='expected_head',required=True)
    ap.add_argument('--expected-candidate-sha256','--binaryexpectedSHA',dest='expected_candidate_sha256',required=True)
    ap.add_argument('--expected-contract-sha256',required=True)
    ap.add_argument('--expected-loader-sha256',required=True)
    ap.add_argument('--expected-tool-helper-sha256',required=True)
    ap.add_argument('--expected-source-fingerprint','--FP',dest='expected_source_fingerprint',required=True,help='Compile-input fingerprint sealed by this actual build')
    add_helper_pins(ap, existing_loader=True, existing_tool_helper=True)
    args=ap.parse_args()
    verify_helper_pins(args, ROOT)
    binary=pathlib.Path(args.binaryrelease).resolve(strict=True)
    contract_path=pathlib.Path(args.contract).resolve(strict=True)
    contract_sha=digest(contract_path)
    if digest(binary)!=args.expected_candidate_sha256:raise ValueError('candidate native SHA differs from build pin')
    contract=load_reviewed_v9(contract_path,args.expected_contract_sha256,args.expected_loader_sha256,args.expected_tool_helper_sha256)
    harness_before=sealed_harness_inputs()
    assert {'process_start','process_status','process_wait','process_read','host_processes','host_signal'}<=set(contract.by_name)
    selected=[x for x in HOSTS if not args.host or x[0]==args.host]
    destination=pathlib.Path(args.receipt_dir).resolve();destination.mkdir(parents=True,exist_ok=False,mode=0o700)
    output=pathlib.Path(args.out)
    if output.exists():raise ValueError('receipt output must be absent')
    source_before=source_identity()
    if args.expected_head and source_before['base_HEAD']!=args.expected_head:
        raise ValueError('source HEAD differs from expected committed HEAD')
    if args.expected_source_fingerprint and source_before['source_code_fingerprint']!=args.expected_source_fingerprint:
        raise ValueError('compile-input fingerprint differs from supplied build pin')
    baseline=services()
    assert all(v.get('ActiveState')=='active' and v.get('MainPID')!='0' for v in baseline.values())
    report={'schema':'hepta-v9-real-signal-audit-faults-owned-prepare-v1',
        'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_head':source_before['base_HEAD'],'source_before':source_before,
        'source_head_is_compiled_code_claim':False,'expected_head':args.expected_head,
        'expected_compiled_source_fingerprint':args.expected_source_fingerprint,
        'compile_input_binding_scope':'observed compile inputs; a supplied build fingerprint is checked, not invented',
        'script_sha256':digest(pathlib.Path(__file__).resolve()),'binary_sha256':digest(binary),
        'operator_source_sha256':digest(ROOT/'src/mcp/runtime/operator.rs'),
        'process_helper_sha256':digest(ROOT/'src/mcp/runtime/process_ops.py'),
        'contract_sha256':contract_sha,'contract_catalog_sha256':contract.catalog_sha256,
        'tool_count':len(contract.tools),'origin':'local_native_real_ssh_with_owned_controller_fault_bridge',
        'chatgpt_originated':False,'native_session_only':True,'installed_service_changed':False,
        'DC_changed':False,'full_dc_replacement_qualified':False,
        'signal':15,'sudo_used':False,'target_processes':'only PID-and-identity verified disposable test children',
        'protected_services_before':baseline,
        'protected_service_identity_scope':'controller PROTECTED units; remote business service identities are not qualified',
        'selected_hosts':[x[0] for x in selected],'harness_inputs_before':harness_before,
        'expected_candidate_sha256':args.expected_candidate_sha256,'expected_loader_sha256':args.expected_loader_sha256,
        'expected_tool_helper_sha256':args.expected_tool_helper_sha256,
        'prepare_scope':'locally durable fixed path/nonce before one remote create-only; lost ACK permits same-path readonly reconcile only',
        'results':[],'cleanup':[],'complete':False, 'adapted_from_V8_named_harness': 'tests/dc_functional_v8_signal_audit_acceptance.py', 'adapted_from_V8_harness_sha256': '3b7c30bc34ed76fb2f194a26615004db5c22519182a29c9673b860aea858151e', 'V9_async_request_start_cancel_qualified_by_this_regression_adapter': False}
    items={};jobs={};terminal={};owned_processes={};launch_attempted=set()
    controller=None;client=None;failure=None;token_value=''
    directory=private_controller_directory()
    base=pathlib.Path(directory).resolve();workspace=base/'workspace';workspace.mkdir(mode=0o700)
    state=base/'state';control=base/'fault.json';events=base/'bridge-events.jsonl';bin_dir=base/'bin';bin_dir.mkdir(mode=0o700)
    wrapper=bin_dir/'ssh';wrapper.write_text(BRIDGE_SOURCE);wrapper.chmod(0o700)
    legacy=state/'audit'/'events.jsonl';active_backup=None
    native_stdout=base/'native.stdout.raw';native_stderr=base/'native.stderr.raw'
    for name,ssh in selected:
        items[name]=planned_fixture(name,ssh,secrets.token_hex(16))
        save_fixture_record(base/('fixture-plan-'+name+'.json'),items[name])
    report['planned_target_recovery_references']=[dict(items[name]) for name,_ in selected]
    try:
        for name,ssh in selected:
            report['active_phase']='prepare:'+name
            prepare_fixture(ssh,items[name],base/('fixture-plan-'+name+'.json'))
        host_config={name:{'ssh_target':ssh,'platform':items[name]['platform'],'execution_mode':'operator',
            'remote_state_dir':items[name]['base']+'/state','allow_execute':True,'allow_pty':False,
            'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,
            'allowed_read_path_prefixes':[items[name]['root']],'allowed_write_path_prefixes':[items[name]['root']]}
            for name,ssh in selected}
        config=base/'runtime.json';config.write_text(json.dumps({'state_dir':str(state),
            'controller_workspace_roots':[str(workspace)],'hosts':host_config}))
        token_value=secrets.token_hex(32);token=base/'token'
        descriptor=os.open(token,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(descriptor,'w',encoding='ascii') as writer:
            writer.write(token_value);writer.flush();os.fsync(writer.fileno())
        set_fault(control,'normal')
        env=dict(os.environ);env.update(PATH=str(bin_dir)+os.pathsep+env.get('PATH',''),
            HEPTA_SIGNAL_FAULT_CONTROL=str(control),HEPTA_SIGNAL_BRIDGE_EVENTS=str(events))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        with native_stdout.open('wb') as nout,native_stderr.open('wb') as nerr,(destination/'owned-tools.jsonl').open('x',encoding='utf-8') as trace:
            controller=subprocess.Popen([str(binary),'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}',
                '--runtime-config',str(config),'--auth-token-file',str(token)],stdin=subprocess.DEVNULL,
                stdout=nout,stderr=nerr,env=env)
            for _ in range(90):
                if controller.poll() is not None:raise RuntimeError('owned signal controller exited at startup')
                try:client=OwnedClient(f'http://127.0.0.1:{port}/mcp',token_value,trace);break
                except (OSError,RuntimeError):time.sleep(.1)
            else:raise TimeoutError('owned signal controller did not start')
            contract.verify(client.rpc('tools/list',{})['tools'])
            for name,ssh in selected:
                report['active_phase']='signal:'+name
                item=items[name];checks=[];phases=[]
                before_jobs=set(p.stem for p in (state/'jobs').glob('*.json'))
                try:
                    launch_attempted.add(name)
                    start=client.call('process_start',{'host':name,'executable':'/usr/bin/python3',
                        'args':['-u','-c',CHILD_SOURCE,item['root']],'cwd':item['root'],
                        'timeout_seconds':110,'idempotency_key':'owned-signal-'+uuid.uuid4().hex})
                    job=start['job']['id'];jobs[name]=job
                    assert start['reused'] is False and start['job']['launch_state']=='launched'
                    ready=owned_query(ssh,item,'ready')
                    pid=ready['pid'];uid=ready['uid'];assert uid==item['uid'] and 0<pid<2**31
                    listing_args={'host':name,'after_pid':pid-1,'limit':1}
                    listing=client.call('host_processes',listing_args)
                    candidates=[p for p in listing['processes'] if p['pid']==pid]
                    assert len(candidates)==1 and candidates[0]['uid']==uid
                    identity=candidates[0]['identity'];client.owned_process_trace(listing_args,candidates[0])
                    owned_processes[name]={'pid':pid,'uid':uid,'identity':identity}
                    checks.append('real owned child PID/UID and native start identity independently verified')
                    signal_args={'host':name,'pid':pid,'signal':15,'expected_identity':identity,'sudo':False}

                    for phase,mode,count in [('normal','normal',1),
                            ('completion_audit_failure','completion_audit_failure',2),
                            ('intent_audit_failure','intent_audit_failure',2),
                            ('lost_ack','lost_ack',3),('invalid_ack','invalid_ack',4)]:
                        prior=len(bridge_rows(events));backup=state/'audit'/('events-backup-'+name+'-'+phase+'.jsonl')
                        active_backup=backup
                        if mode=='intent_audit_failure':
                            assert legacy.is_file() and not legacy.is_symlink()
                            os.replace(legacy,backup);legacy.mkdir(mode=0o700)
                            set_fault(control,'normal')
                        elif mode=='completion_audit_failure':
                            set_fault(control,mode,audit_path=str(legacy),backup_path=str(backup))
                        else:set_fault(control,mode)
                        try:
                            if mode=='intent_audit_failure':
                                reply=client.call('host_signal',signal_args,denied=True)
                                assert 'no signal request dispatched' in reply
                                assert len(bridge_rows(events))==prior
                            else:
                                reply=client.call('host_signal',signal_args)
                                rows=bridge_rows(events);assert len(rows)==prior+1
                                real=rows[-1]
                                assert real['pid']==pid and real['expected_identity']==identity and real['signal']==15
                                assert real['real_ssh_exit']==0
                                verify_ack(real['real_ack'],pid,identity,uid)
                                assert reply['pid']==pid and reply['signal']==15
                                assert reply['automatic_retry'] is False
                                assert reply['termination_confirmed'] is False
                                if mode in ('lost_ack','invalid_ack'):
                                    assert reply['result']=='signal_outcome_unknown'
                                    assert reply['outcome']=='unknown' and reply['expected_identity']==identity
                                    assert 'reconcile_warning' in reply
                                else:
                                    verify_ack(reply,pid,identity,uid)
                                    assert reply['audit_recorded'] is (mode=='normal')
                                    if mode=='completion_audit_failure':assert 'audit_warning' in reply
                            text=json.dumps(reply,ensure_ascii=False)
                            assert str(base) not in text and token_value not in text
                            observed=owned_query(ssh,item,'counter',count)
                            assert observed=={'count':count,'pid':pid,'uid':uid}
                            phases.append({'phase':phase,'count':count,'signal_rpc_dispatches':len(bridge_rows(events))-prior,
                                'result':reply,'physical_effect_verified':True})
                            checks.append(phase+' retains correct owned identity/effect and prevents blind replay')
                        finally:
                            set_fault(control,'normal')
                            restore_audit(legacy,backup);active_backup=None
                    # The same child remains alive throughout all fault phases.
                    again=client.call('host_processes',listing_args)
                    same=[p for p in again['processes'] if p['pid']==pid]
                    assert len(same)==1 and same[0]['identity']==identity and same[0]['uid']==uid
                    client.owned_process_trace(listing_args,same[0])
                    owned_query(ssh,item,'release')
                    done=client.call('process_wait',{'host':name,'job_id':job,'timeout_seconds':25})
                    assert done['state']=='succeeded' and done['exit_code']==0 and done['output_complete'] is True
                    terminal[name]=True
                    stream=client.call('process_read',{'host':name,'job_id':job,'limit':16384})
                    stdout=bytes.fromhex(stream['stdout']['bytes_hex'])
                    assert stdout==b'READY\nTERM_COUNT=1\nTERM_COUNT=2\nTERM_COUNT=3\nTERM_COUNT=4\nRELEASED\n'
                    assert bytes.fromhex(stream['stderr']['bytes_hex'])==b''
                    checks.append('same child identity survives all phases, then owned release exits normally with exact count log')
                    report['results'].append({'host':name,'job_id':job,'pid':pid,'identity':identity,
                        'atomic_identity':phases[0]['result']['atomic_identity'],'phases':phases,
                        'passed':len(checks),'checks':checks,'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'complete':True})
                    print('PASS',name,'signal-audit-real-faults',len(checks),flush=True)
                finally:
                    for p in (state/'jobs').glob('*.json'):
                        if p.stem not in before_jobs:
                            record=json.loads(p.read_text())
                            if record['host']==name:jobs[name]=record['id']
    except Exception as exc:
        failure=exc;report['error_type']=type(exc).__name__
        report['error']=redacted(str(exc).encode(),token_value,base).decode()[:2000]
        report['failure_phase']=report.get('active_phase','prepare')
        report['failure_frames']=[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)]
        if isinstance(exc,TargetOperationError):report['transport_failure']=exc.diagnostic(token_value,base)
    finally:
        try:
            set_fault(control,'normal')
            if active_backup is not None:restore_audit(legacy,active_backup)
        except Exception as exc:report['audit_restore_error_type']=type(exc).__name__
        for name,ssh in selected:
            if name not in items:continue
            item=items[name]
            if not item.get('prepare_attempted'):
                report['cleanup'].append({'host':name,'removed':True,'remote_create_never_attempted':True})
                continue
            if not item.get('prepare_confirmed'):
                observed=item.get('reconcile_readonly')
                absent=isinstance(observed,dict) and observed.get('present') is False
                report['cleanup'].append({'host':name,'removed':absent,'prepare_ack_unconfirmed':True,
                    'reconcile_readonly':observed,'retained_owned_fixture':None if absent else item['base'],
                    'automatic_retry':False,'recovery_reference':str(base/('fixture-plan-'+name+'.json'))})
                continue
            try:
                if name in launch_attempted and name not in jobs:
                    raise RuntimeError('launch attempted without a retained job ID; fixture retained for reconciliation')
                if name in jobs and not terminal.get(name):
                    owned_query(ssh,items[name],'release')
                    if client is None:raise RuntimeError('owned job status unavailable')
                    status=client.call('process_status',{'host':name,'job_id':jobs[name]})
                    if status['state']=='running':
                        status=client.call('process_wait',{'host':name,'job_id':jobs[name],'timeout_seconds':25})
                    terminal[name]=status['state'] in TERMINAL and status.get('output_complete') is True
                if name in jobs and not terminal.get(name):raise RuntimeError('owned job not confirmed terminal; fixture retained')
                owned_query(ssh,items[name],'remove')
                report['cleanup'].append({'host':name,'job_id':jobs.get(name),'removed':True,
                    'job_terminal_confirmed':name not in jobs or terminal.get(name) is True})
            except Exception as exc:
                report['cleanup'].append({'host':name,'job_id':jobs.get(name),'removed':False,
                    'error_type':type(exc).__name__,'retained_owned_fixture':items[name]['base'],
                    'failure_frames':[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)],
                    'transport_failure':exc.diagnostic(token_value,base) if isinstance(exc,TargetOperationError) else None,
                    'launch_attempted':name in launch_attempted,'owned_process':owned_processes.get(name)})
        try:
            if controller is not None and controller.poll() is None:
                controller.terminate()
                try:controller.wait(timeout=10)
                except subprocess.TimeoutExpired:controller.kill();controller.wait(timeout=5)
        except Exception as exc:report['controller_stop_error_type']=type(exc).__name__
        report['owned_controller_stopped']=controller is None or controller.poll() is not None
        logs={}
        for label,path in [('native-stdout',native_stdout),('native-stderr',native_stderr),('bridge-events',events)]:
            try:
                saved=destination/(label+'.log');saved.write_bytes(redacted(path.read_bytes() if path.exists() else b'',token_value,base))
                logs[label]={'bytes':saved.stat().st_size,'sha256':digest(saved),'redacted':True}
            except Exception as exc:
                report.setdefault('evidence_save_errors',[]).append({'label':label,'error_type':type(exc).__name__})
        trace=destination/'owned-tools.jsonl'
        try:
            if trace.exists():logs['owned-tools']={'bytes':trace.stat().st_size,'sha256':digest(trace),
                'content':'only test-owned requests/results; no tokens, headers or unrelated process-list output'}
        except Exception as exc:
            report.setdefault('evidence_save_errors',[]).append({'label':'owned-tools','error_type':type(exc).__name__})
        report['logs']=logs
        report['target_prepare_recovery']=[dict(items[name]) for name,_ in selected]
        report['owned_jobs']=[{'host':name,'job_id':job,'terminal_confirmed':terminal.get(name) is True} for name,job in jobs.items()]
    try:
        report['protected_services_after']=services()
        report['service_identity_stable']=report['protected_services_after']==baseline
    except Exception as exc:
        report['service_identity_stable']=False;report['service_observation_error_type']=type(exc).__name__
    try:
        source_after=source_identity();report['source_after']=source_after
        report['harness_inputs_after']=sealed_harness_inputs()
        report['harness_inputs_stable']=report['harness_inputs_after']==harness_before
        report['source_fingerprint_stable']=source_before['source_code_fingerprint']==source_after['source_code_fingerprint']
        report['source_head_stable']=source_before['base_HEAD']==source_after['base_HEAD']
        report['compile_input_build_pin_verified']=(args.expected_source_fingerprint is not None
            and source_after['source_code_fingerprint']==args.expected_source_fingerprint)
        report['candidate_hashes_after']={'binary_sha256':digest(binary),
            'operator_source_sha256':digest(ROOT/'src/mcp/runtime/operator.rs'),
            'process_helper_sha256':digest(ROOT/'src/mcp/runtime/process_ops.py'),
            'script_sha256':digest(pathlib.Path(__file__).resolve()),'contract_sha256':digest(contract_path)}
        report['candidate_hashes_stable']=(all(report['candidate_hashes_after'][key]==report[key]
            for key in report['candidate_hashes_after']) and report['source_fingerprint_stable'] and report['source_head_stable'] and report['harness_inputs_stable'])
    except Exception as exc:
        report['candidate_hashes_stable']=False;report['source_observation_error_type']=type(exc).__name__
    report['selected_complete']=(failure is None and len(report['results'])==len(selected)
        and report.get('candidate_hashes_stable') is True and report['service_identity_stable']
        and 'audit_restore_error_type' not in report and report['owned_controller_stopped']
        and 'controller_stop_error_type' not in report and not report.get('evidence_save_errors')
        and len(report['cleanup'])==len(selected) and all(x['removed'] for x in report['cleanup']))
    report['complete']=report['selected_complete'] and len(selected)==len(HOSTS)
    if report['selected_complete']:
        try:
            shutil.rmtree(base)
            report['controller_cleanup']={'removed':True,'owned_controller_stopped':controller is None or controller.poll() is not None}
        except Exception as exc:
            report['selected_complete']=False;report['complete']=False
            report['controller_cleanup']={'removed':False,'error_type':type(exc).__name__}
    if not report['selected_complete']:
        # The 0700 parent/base and separately 0600 token stay local only. Receipts
        # contain references and no token value; this directory is never committed.
        recovery={'schema':'hepta-v8-owned-signal-audit-recovery-v1','binary':str(binary),
            'binary_sha256':report['binary_sha256'],'contract':str(contract_path),
            'contract_sha256':contract_sha,'source_before':source_before,
            'controller_state_dir':str(state),'runtime_config':str(config) if 'config' in locals() else None,
            'controller_stopped':controller is None or controller.poll() is not None,
            'audit_path':str(legacy),'active_audit_backup':str(active_backup) if active_backup is not None else None,
            'automatic_retry':False,'credentials_in_metadata':False,
            'targets':[{'host':name,'ssh_target':ssh,'fixture':items.get(name),
                'job_id':jobs.get(name),'launch_attempted':name in launch_attempted,
                'terminal_confirmed':terminal.get(name) is True,'owned_process':owned_processes.get(name)}
                for name,ssh in selected]}
        recovery_path=base/'recovery.json'
        try:
            save_private_json(recovery_path,recovery)
            report['recovery']={'controller_directory':str(base),'metadata_path':str(recovery_path),
                'directory_mode':'0700','metadata_mode':'0600','auth_token_retained_private':token_value!='',
                'auth_token_not_in_receipts':True,'automatic_retry':False}
        except Exception as exc:
            report['recovery']={'controller_directory':str(base),'metadata_saved':False,'error_type':type(exc).__name__}
    with output.open('x',encoding='utf-8') as f:f.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('SIGNAL_AUDIT_COMPLETE',report['complete'],'SELECTED_COMPLETE',report['selected_complete'],flush=True)
    if not report['selected_complete']:sys.exit(1)

if __name__=='__main__':
    main()
