#!/usr/bin/env python3
"""Finite independent REA 6.8.0 public MCP EOF oracle and native differential.

Modes are intentionally sequential: reference creates immutable inputs and raw
Node/REA observations; native reuses those paths and compares complete public
result envelopes. This runner never asserts global parity or deployability.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import select
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import traceback

sys.dont_write_bytecode = True
PACKAGE_SHA = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
NODE_SHA = '94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90'
NODE_VERSION = 'v22.23.4'
CORPUS_SHA = '289d512884e2ee47fa784ad6f70d76813da1e2f54b84a9b35522320b63f0b4fb'
DENOMINATOR = 116
MAX_LINE = 16 * 1024 * 1024
MAX_WIRE = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_frame_json(raw):
    def reject_constant(token):
        raise ValueError('non-JSON numeric constant in MCP frame: '+token)
    return json.loads(raw.decode('utf-8'),parse_constant=reject_constant)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def read_regular(path):
    p = Path(path)
    st = p.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'expected single-link regular file: '+str(p))
    raw = p.read_bytes()
    after = p.lstat()
    require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'changed file: '+str(p))
    return raw


def identity_bytes(path, raw):
    return dict(path=str(Path(path)),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def identity(path):
    return identity_bytes(path, read_regular(path))


def write(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return identity(path)


def save(path, value):
    return write(path,json_bytes(value))


def package_identity(package, archive):
    archive_raw=read_regular(archive);archive_id=identity_bytes(archive,archive_raw)
    require(archive_id['sha256']==PACKAGE_SHA, 'fixed npm archive hash mismatch')
    expected={}
    with tarfile.open(fileobj=io.BytesIO(archive_raw),mode='r:gz') as bundle:
        for member in bundle:
            parts=PurePosixPath(member.name).parts
            require(parts and parts[0]=='package' and '..' not in parts and not member.name.startswith('/'), 'unsafe tar member')
            if member.isdir():continue
            require(member.isfile() and len(parts)>1, 'unsupported tar member')
            name=PurePosixPath(*parts[1:]).as_posix()
            require(name not in expected, 'duplicate archive member')
            data=bundle.extractfile(member).read()
            expected[name]=dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    actual={}
    for directory,dirs,files in os.walk(package,followlinks=False):
        for name in dirs:
            require(not (Path(directory)/name).is_symlink(), 'package symlink directory')
        for name in files:
            p=Path(directory)/name
            relative=p.relative_to(package).as_posix()
            file_raw=read_regular(p)
            actual[relative]={**identity_bytes(p,file_raw),'path':relative}
            if relative=='package.json':package_meta_raw=file_raw
    require(expected==actual, 'installed original package does not equal fixed npm archive')
    meta=json.loads(package_meta_raw)
    require((meta['name'],meta['version'])==('rea-agents','6.8.0'),'unexpected package metadata')
    return dict(package_root=str(package),tarball=archive_id,file_count=len(actual),
                own_files_sha256=hashlib.sha256(json_bytes(sorted(actual.values(),key=lambda x:x['path']))).hexdigest(),
                dependency_scope='Transitive dependencies are trusted external inputs; no claim of complete dependency authentication')


def source_identity(repo):
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    status_text=subprocess.check_output(['git','status','--porcelain'],cwd=repo,text=True)
    names=subprocess.check_output(['git','ls-files','-z'],cwd=repo).decode().split('\0')
    entries=[{**identity(repo/name),'path':name} for name in names if name]
    return dict(commit=commit,clean=not status_text,status=status_text,
                tracked_files=len(entries),tracked_files_sha256=hashlib.sha256(json_bytes(entries)).hexdigest())


def process_identity(pid):
    raw=(Path('/proc')/str(pid)/'stat').read_text()
    tail=raw[raw.rfind(')')+2:].split()
    return dict(pid=pid,parent_pid=int(tail[1]),process_group=int(tail[2]),start_ticks=int(tail[19]))


def group_exists(pid):
    try:os.killpg(pid,0);return True
    except ProcessLookupError:return False


class MCP:
    """Single outstanding request; raw bytes retained before protocol validation."""
    def __init__(self, command, cwd, env, output):
        self.out=output;output.mkdir()
        self.handles=[];self.process=None;self.pidfd=None;self.owner=None
        self.closed=False;self.close_result=None;self.next=1;self.buffer=b''
        self.stdout_eof=False;self.total_received=0;self.last_response_raw=None
        self.protocol_errors=[];self.capture_truncated=False
        try:
            def opened(name):
                f=(output/name).open('xb');self.handles.append(f);return f
            self.ins=opened('stdin.ndjson');self.outs=opened('stdout.ndjson')
            self.err=opened('stderr.log');self.times=opened('wire-events.ndjson')
            self.process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True,bufsize=0)
            self.pidfd=os.pidfd_open(self.process.pid)
            self.owner=process_identity(self.process.pid)
            os.set_blocking(self.process.stdout.fileno(),False)
            save(output/'launch.json',dict(command=command,cwd=str(cwd),environment=env,owner=self.owner))
        except BaseException:
            self.close()
            raise
    def log(self,direction,raw):
        stream=self.ins if direction=='sent' else self.outs
        stream.write(raw);stream.flush()
        self.times.write((json.dumps(dict(direction=direction,monotonic_ns=time.monotonic_ns(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))+'\n').encode());self.times.flush()
    def receive_frame(self,seconds):
        deadline=time.monotonic()+seconds
        while b'\n' not in self.buffer:
            if self.stdout_eof:
                require(not self.buffer,'unterminated final MCP frame')
                raise EOFError('MCP stdout closed')
            left=deadline-time.monotonic()
            if left<=0 or not select.select([self.process.stdout],[],[],max(0,left))[0]:raise TimeoutError('MCP frame deadline')
            raw=os.read(self.process.stdout.fileno(),65536)
            if not raw:self.stdout_eof=True;continue
            # Retain the exact bounded offending chunk before any limit check.
            self.log('received',raw);self.total_received+=len(raw);self.buffer+=raw
            if self.total_received>MAX_WIRE or (b'\n' not in self.buffer and len(self.buffer)>MAX_LINE):
                self.capture_truncated=True
                raise ValueError('MCP capture bound exceeded; offending prefix retained')
        raw,self.buffer=self.buffer.split(b'\n',1);raw+=b'\n'
        require(len(raw)<=MAX_LINE,'MCP line bound exceeded; full offending frame retained')
        obj=strict_frame_json(raw)
        require(isinstance(obj,dict) and obj.get('jsonrpc')=='2.0','invalid MCP message')
        if 'id' in obj:
            require('method' not in obj and (('result' in obj)!=('error' in obj)),'response must have exactly one result/error')
        else:
            require(isinstance(obj.get('method'),str) and 'result' not in obj and 'error' not in obj,'notification requires method and no result/error')
            require('params' not in obj or isinstance(obj['params'],(dict,list)),'notification params must be an object or array')
        return obj,raw
    def send(self,method,params,request_id=None):
        obj=dict(jsonrpc='2.0',method=method,params=params)
        if request_id is not None:obj['id']=request_id
        raw=json.dumps(obj,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
        self.log('sent',raw)
        view=memoryview(raw)
        while view:
            wrote=self.process.stdin.write(view)
            require(wrote is not None and wrote>0,'MCP input write failed')
            view=view[wrote:]
    def request(self,method,params):
        request_id=self.next;self.next+=1;self.send(method,params,request_id)
        deadline=time.monotonic()+30
        while True:
            obj,raw=self.receive_frame(max(0,deadline-time.monotonic()))
            if 'id' not in obj:continue
            require(type(obj['id']) is int and obj['id']==request_id,'unexpected/duplicate response ID')
            self.last_response_raw=raw
            return obj
    def initialize(self):
        result=self.request('initialize',dict(protocolVersion='2026-07-28',capabilities={},clientInfo=dict(name='hepta-rea-independent-eof-oracle',version='5')))
        require('result' in result,'MCP initialize failed')
        self.send('notifications/initialized',{});save(self.out/'initialize.json',result)
    def call(self,name,arguments):return self.request('tools/call',dict(name=name,arguments=arguments))
    def drain(self,seconds):
        deadline=time.monotonic()+seconds
        while not self.stdout_eof or self.buffer:
            try:
                obj,_=self.receive_frame(max(0,deadline-time.monotonic()))
                if 'id' in obj:self.protocol_errors.append('unmatched trailing response ID '+str(obj['id']))
            except EOFError:break
            except BaseException as error:
                self.protocol_errors.append(type(error).__name__+': '+str(error));break
    def close(self):
        if self.closed:return self.close_result
        errors=[];forced=[];code=None;owner_exited=False;group_gone=False
        try:
            if self.process is not None:
                try:
                    if not self.process.stdin.closed:self.process.stdin.close()
                except BaseException as error:errors.append('stdin-close: '+repr(error))
                try:
                    self.drain(15)
                    try:code=self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # wait timed out: child is unreaped, retaining PID/PGID custody.
                        forced.append('SIGTERM');os.killpg(self.process.pid,signal.SIGTERM)
                        try:code=self.process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            forced.append('SIGKILL');os.killpg(self.process.pid,signal.SIGKILL);code=self.process.wait(timeout=2)
                    # Never signal the numeric process group after wait reaps its leader.
                    group_gone=not group_exists(self.process.pid)
                    if not self.stdout_eof:self.drain(1)
                except BaseException as error:errors.append('owner-cleanup: '+repr(error))
                if self.pidfd is not None:
                    try:owner_exited=bool(select.select([self.pidfd],[],[],0)[0])
                    except BaseException as error:errors.append('pidfd-observe: '+repr(error))
        finally:
            if self.process is not None:
                for stream in (self.process.stdin,self.process.stdout):
                    try:
                        if stream is not None and not stream.closed:stream.close()
                    except BaseException as error:errors.append('stream-close: '+repr(error))
            if self.pidfd is not None:
                try:os.close(self.pidfd);self.pidfd=None
                except BaseException as error:errors.append('pidfd-close: '+repr(error))
            for f in self.handles:
                try:f.close()
                except BaseException as error:errors.append('log-close: '+repr(error))
            self.closed=(self.process is None or self.process.returncode is not None) and all(f.closed for f in self.handles)
            self.close_result=dict(returncode=code,forced_cleanup=forced,reader_stopped=True,stdout_eof=self.stdout_eof,
                                  owner_pidfd_exited=owner_exited,process_group_gone=group_gone,
                                  owner=self.owner,cleanup_errors=errors,trailing_protocol_errors=self.protocol_errors,
                                  capture_truncated=self.capture_truncated,managed_resources_closed=self.closed)
            try:save(self.out/'close.json',self.close_result)
            except BaseException as error:self.close_result['cleanup_errors'].append('close-receipt: '+repr(error))
        return self.close_result


def value(response):
    require(('result' in response)!=('error' in response),'response must have exactly one result/error')
    if 'error' in response:return response.copy()
    result=response.get('result')
    require(isinstance(result,dict),'MCP result must be object')
    content=result.get('content')
    require(isinstance(content,list) and len(content)==1 and content[0].get('type')=='text','unexpected content representation')
    try:parsed=json.loads(content[0]['text'])
    except json.JSONDecodeError:parsed=content[0]['text']
    if 'structuredContent' in result:
        require(not diff(result['structuredContent'],parsed),'structuredContent/text mismatch')
    return {**result,'content':[{**content[0],'text':parsed}]}


def diff(a,b,path='$'):
    if isinstance(a,dict) and isinstance(b,dict):
        result=[]
        for key in sorted(a.keys()|b.keys()):
            if key not in a or key not in b:result.append(dict(path=path+'/'+key,reference_present=key in a,native_present=key in b,reference=a.get(key),native=b.get(key)))
            else:result.extend(diff(a[key],b[key],path+'/'+key))
        return result
    if isinstance(a,list) and isinstance(b,list) and len(a)==len(b):
        return [d for i,(x,y) in enumerate(zip(a,b)) for d in diff(x,y,path+'/'+str(i))]
    equal_numeric=not isinstance(a,bool) and not isinstance(b,bool) and isinstance(a,(int,float)) and isinstance(b,(int,float))
    return [] if a==b and (type(a)==type(b) or equal_numeric) else [dict(path=path,reference=a,native=b)]


NODE_PROGRAM=r'''
import fs from 'node:fs';
import crypto from 'node:crypto';
const corpus=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
const rows=corpus.cases.map(c=>{
  const raw=Buffer.from(c.input,'utf8');
  const r={id:c.id,utf8_bytes:raw.length,utf16_code_units:c.input.length,sha256:crypto.createHash('sha256').update(raw).digest('hex')};
  try {r.value=JSON.parse(c.input);r.ok=true;} catch(error) {r.ok=false;r.name=error.name;r.message=error.message;}
  if ('append_to_complete' in c) {
    try {JSON.parse(c.input+c.append_to_complete);r.append_witness_valid=true;}
    catch(error) {r.append_witness_valid=false;r.append_witness_error=error.message;}
  }
  return r;
});
process.stdout.write(JSON.stringify({schema:'hepta.rea.eof-independent-node-observation.v1',node:process.version,cases:rows},null,2)+'\n');
'''


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=['reference','native'])
    ap.add_argument('--output-dir',type=Path,required=True)
    ap.add_argument('--corpus',type=Path)
    ap.add_argument('--reference-package',type=Path)
    ap.add_argument('--reference-tarball',type=Path)
    ap.add_argument('--node',type=Path)
    ap.add_argument('--reference-dir',type=Path)
    ap.add_argument('--reference-report-sha256')
    ap.add_argument('--node-observations-sha256')
    ap.add_argument('--binary',type=Path)
    ap.add_argument('--binary-sha256')
    ap.add_argument('--repo',type=Path)
    ap.add_argument('--source-commit')
    ap.add_argument('--build-binding',type=Path)
    ap.add_argument('--build-binding-sha256')
    args=ap.parse_args()
    paths=[x for x in vars(args).values() if isinstance(x,Path)]
    require(all(p.is_absolute() for p in paths),'all paths must be absolute')
    out=args.output_dir
    if args.mode=='native' and args.repo is not None:
        require(not out.is_relative_to(args.repo),'evidence output cannot be inside source worktree')
    if args.mode=='reference' and args.reference_package is not None:
        require(not out.is_relative_to(args.reference_package),'evidence output cannot be inside reference package')
    out.mkdir(mode=0o700,parents=False,exist_ok=False)
    report=dict(schema='hepta.rea.eof-independent-public-observation.v1',mode=args.mode,runner_revision=5,qualified=False,
                global_status='HOLD/NO_GO',denominator=DENOMINATOR,cases=[],errors=[],comparisons=[],
                coverage=dict(cancellation='NOT_TESTED: synchronous small-file diagnostics cannot establish active cancellation parity',
                              lifecycle='MCP stdin EOF close only; no controller restart or cross-host recovery claim',
                              format='UTF-8 JSON files under 8 MiB; no large-file/streaming or arbitrary diagnostic closure'),
                started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    client=None;before={};after={};source_before=None
    signals=[]
    def interrupted(n,_):signals.append(n)
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,interrupted)
    def checkpoint():require(not signals,'interrupted by signal '+str(signals))
    try:
        before['runner']=identity(Path(__file__).resolve())
        write(out/'runner.py',read_regular(Path(__file__).resolve()))
        if args.mode=='reference':
            require(all([args.corpus,args.reference_package,args.reference_tarball,args.node]),'reference arguments missing')
            corpus_path=args.corpus
            before['node']=identity(args.node.resolve());require(before['node']['sha256']==NODE_SHA,'Node hash mismatch')
            observed=subprocess.check_output([str(args.node),'--version'],text=True).strip()
            require(observed==NODE_VERSION,'Node version mismatch')
            before['package']=package_identity(args.reference_package,args.reference_tarball)
            workspace=out/'workspace';workspace.mkdir(mode=0o700)
        else:
            require(all([args.reference_dir,args.reference_report_sha256,args.node_observations_sha256,args.binary,args.binary_sha256,args.repo,args.source_commit,args.build_binding,args.build_binding_sha256]),'native arguments missing')
            reference_raw=read_regular(args.reference_dir/'observation.json')
            require(hashlib.sha256(reference_raw).hexdigest()==args.reference_report_sha256,'fixed reference report hash mismatch')
            reference_report=json.loads(reference_raw)
            require(reference_report.get('runner_revision')==5,'reference must use runner revision 5 with strict frame parsing')
            require(reference_report.get('collection_complete') is True,'reference collection was incomplete')
            before['reference_report']=identity_bytes(args.reference_dir/'observation.json',reference_raw)
            reference_rows={r['id']:r for r in reference_report['cases']}
            require(len(reference_rows)==DENOMINATOR,'reference case identities duplicated or missing')
            corpus_path=args.reference_dir/'corpus.json'
            workspace=args.reference_dir/'workspace'
            before['binary']=identity(args.binary);require(before['binary']['sha256']==args.binary_sha256,'native binary hash mismatch')
            binding_raw=read_regular(args.build_binding)
            before['binding']=identity_bytes(args.build_binding,binding_raw);require(before['binding']['sha256']==args.build_binding_sha256,'build binding hash mismatch')
            binding=json.loads(binding_raw)
            require(binding['source_commit']==args.source_commit,'binding commit differs')
            require(binding['runtime']['sha256']==args.binary_sha256 and binding['runtime']['bytes']==before['binary']['bytes'],'binding binary differs')
            require(Path(binding['runtime']['path'])==args.binary,'binding runtime path differs')
            source_before=source_identity(args.repo)
            require(source_before['commit']==args.source_commit and source_before['clean'],'native source not clean expected commit')
            before['source']=source_before
            write(out/'build-binding.original.json',binding_raw)
            report['source_monitor_boundary']='Before/after trusted source snapshot only; no hostile-filesystem or transient-edit protection claimed'
            report['build_consumption']='Exact opaque build receipt hash, source commit, clean tracked source snapshot and runtime identity checked. This runner does not replace the existing full build-matrix consumer.'
        corpus_raw=read_regular(corpus_path)
        require(hashlib.sha256(corpus_raw).hexdigest()==CORPUS_SHA,'independent corpus changed')
        corpus=json.loads(corpus_raw);require(corpus['denominator']==DENOMINATOR and len(corpus['cases'])==DENOMINATOR,'finite denominator differs')
        write(out/'corpus.json',corpus_raw)
        report['group_counts']=corpus['group_counts'];report['workspace']=str(workspace)
        if args.mode=='reference':
            for c in corpus['cases']:
                raw=bytes.fromhex(c['input_hex'])
                require(raw==c['input'].encode('utf-8') and hashlib.sha256(raw).hexdigest()==c['input_sha256'],'corpus input byte mismatch')
                write(workspace/(c['id']+'.json'),raw)
            write(out/'node-program.mjs',NODE_PROGRAM.encode())
            with (out/'node.stdout.json').open('xb') as stdout, (out/'node.stderr.log').open('xb') as stderr:
                proc=subprocess.run([str(args.node),'--input-type=module','-e',NODE_PROGRAM,str(out/'corpus.json')],stdout=stdout,stderr=stderr,timeout=30,check=False)
            require(proc.returncode==0,'direct Node diagnostic collector failed; partial files retained')
            node_raw=read_regular(out/'node.stdout.json')
            report['node_output_identity']=identity_bytes(out/'node.stdout.json',node_raw)
            node=json.loads(node_raw)
            require(node['node']==NODE_VERSION and len(node['cases'])==DENOMINATOR,'direct Node denominator mismatch')
            for c,obs in zip(corpus['cases'],node['cases']):
                require(c['id']==obs['id'] and obs['sha256']==c['input_sha256'] and obs['utf16_code_units']==c['utf16_code_units'],'direct Node identity mismatch')
                if c['group']=='eof':require(obs['ok'] is False and obs['append_witness_valid'] is True,'EOF append witness invalid')
                elif c['group']=='non-eof-invalid':require(obs['ok'] is False,'invalid control unexpectedly valid')
                else:require(obs['ok'] is True,'valid control unexpectedly invalid')
                if 'baseline_node_message' in c:require(obs.get('message')==c['baseline_node_message'],'original baseline diagnostic changed')
        else:
            node_raw=read_regular(args.reference_dir/'node.stdout.json')
            require(hashlib.sha256(node_raw).hexdigest()==args.node_observations_sha256,'fixed Node observations changed')
            require(identity_bytes(args.reference_dir/'node.stdout.json',node_raw)==reference_report['node_output_identity'],'Node output/report binding differs')
            node=json.loads(node_raw)
        require(node['node']==NODE_VERSION and [c['id'] for c in node['cases']]==[c['id'] for c in corpus['cases']],'Node case order or count differs')
        node_by_id={c['id']:c for c in node['cases']}
        config=out/'runtime.json'
        save(config,dict(controller_workspace_roots=[str(workspace)],state_dir=str(out/'state'),
                         hosts={'never-connect':dict(ssh_target='never-connect-invalid',remote_state_dir=str(out/'unused-remote'),allow_execute=False,allow_pty=False,allow_write=False,allow_job_network=False)}))
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','REA_MCP_INPUT_SCHEMA_PROFILE':'full','REA_MCP_OUTPUT_SCHEMA_PROFILE':'full'}
        cmd=([str(args.node),str(args.reference_package/'scripts/rea.mjs'),'mcp'] if args.mode=='reference' else
             [str(args.binary),'mcp','--runtime-config',str(config)])
        client=MCP(cmd,workspace,env,out/'mcp')
        client.initialize();checkpoint()
        prefix='' if args.mode=='reference' else 'rea_'
        initial=value(client.call(prefix+'get_evidence_bundle',{}))
        save(out/'evidence-before.json',initial)
        for c in corpus['cases']:
            checkpoint()
            p=workspace/(c['id']+'.json');obs_id=identity(p)
            require(obs_id['sha256']==c['input_sha256'],'input changed before public call')
            request_args={'path':str(p)}
            t=time.monotonic_ns();response=client.call(prefix+'import_evidence_bundle',request_args);elapsed=time.monotonic_ns()-t
            response_raw=client.last_response_raw
            v=value(response)
            snapshot=value(client.call(prefix+'get_evidence_bundle',{}))
            row=dict(id=c['id'],group=c['group'],original_nine_gap_index=c.get('original_nine_gap_index'),
                     arguments=request_args,input_identity=obs_id,response=response,response_wire_hex=response_raw.hex(),value=v,
                     evidence_after=snapshot,evidence_unchanged=(snapshot==initial),elapsed_ns=elapsed,
                     node_observation=node_by_id[c['id']])
            if c['group'] in ('eof','non-eof-invalid'):
                text=v.get('content',[{}])[0].get('text',{})
                error=text.get('error',{}) if isinstance(text,dict) else {}
                details=error.get('details',{})
                row['json_diagnostic_matches_node']=(v.get('isError') is True and error.get('code')=='evidence_integrity_mismatch'
                  and details.get('reason')=='invalid-json' and any(x.get('message')==node_by_id[c['id']]['message'] for x in details.get('content_issues',[])))
                row['public_error_code']=error.get('code');row['public_error_category']=error.get('category')
                if args.mode=='reference':require(row['json_diagnostic_matches_node'],'original public MCP differs from direct Node diagnostic: '+c['id'])
            artifact=save(out/(c['id']+'.json'),row)
            report['cases'].append(dict(id=c['id'],artifact=artifact,evidence_unchanged=row['evidence_unchanged'],
                                        json_diagnostic_matches_node=row.get('json_diagnostic_matches_node')))
            if args.mode=='native':
                original_path=args.reference_dir/(c['id']+'.json')
                original_raw=read_regular(original_path)
                original_id=identity_bytes(original_path,original_raw)
                require(original_id==reference_rows[c['id']]['artifact'],'reference per-case artifact changed')
                old=json.loads(original_raw)
                require(old['id']==c['id'] and old['arguments']==request_args and old['input_identity']==obs_id,'reference case/input binding mismatch')
                require(old['node_observation']==node_by_id[c['id']],'direct Node aggregate differs from authenticated original case')
                object_diff=diff(old['response'],response)
                wire_equal=(old['response_wire_hex']==response_raw.hex())
                d=diff(old['value'],v)
                state_diff=diff(old['evidence_after'],snapshot)
                report['comparisons'].append(dict(id=c['id'],group=c['group'],original_nine_gap_index=c.get('original_nine_gap_index'),
                    status='PASS' if not d and not state_diff else 'FAIL',comparison_layer='parsed-content type-sensitive field equality',differences=d,evidence_differences=state_diff,unnormalized_object_equal=not object_diff,unnormalized_object_differences=object_diff,raw_frame_bytes_equal=wire_equal,
                    native_error_code=row.get('public_error_code'),native_error_category=row.get('public_error_category')))
            require(identity(p)==obs_id,'input changed during public call')
        report['close']=client.close()
        require(report['close']['returncode']==0 and not report['close']['forced_cleanup'] and report['close']['reader_stopped'] and report['close']['owner_pidfd_exited'] and report['close']['process_group_gone'] and report['close']['stdout_eof'] and not report['close']['cleanup_errors'] and not report['close']['trailing_protocol_errors'] and not report['close']['capture_truncated'],'MCP owner did not close normally')
        checkpoint()
    except BaseException as error:
        report['errors'].append(dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc()))
    finally:
        if client is not None and not client.closed:
            try:report['close']=client.close()
            except BaseException as error:report['errors'].append(dict(phase='cleanup',type=type(error).__name__,message=str(error)))
        for key,call in [('runner',lambda:identity(Path(__file__).resolve()))]+(
            [('node',lambda:identity(args.node.resolve())),('package',lambda:package_identity(args.reference_package,args.reference_tarball))]
            if args.mode=='reference' else
            [('binary',lambda:identity(args.binary)),('binding',lambda:identity(args.build_binding)),('source',lambda:source_identity(args.repo)),('reference_report',lambda:identity(args.reference_dir/'observation.json'))]):
            if key not in before:continue
            try:
                after[key]=call();require(after[key]==before[key],key+' changed during collection')
            except BaseException as error:report['errors'].append(dict(phase='postflight-'+key,type=type(error).__name__,message=str(error)))
    report['identity_boundary']='Trusted-path pre/post snapshots only; no continuous source/package/dependency monitoring or hostile filesystem protection claimed'
    report['before']=before;report['after']=after
    report['collection_complete']=not report['errors'] and len(report['cases'])==DENOMINATOR
    report['counts']=dict(collected=len(report['cases']),comparisons=len(report['comparisons']),
                          exact=sum(r['status']=='PASS' for r in report['comparisons']),different=sum(r['status']=='FAIL' for r in report['comparisons']))
    report['finite_status']=('INCOMPLETE' if not report['collection_complete'] else
                            'REFERENCE_CAPTURED' if args.mode=='reference' else
                            'PARSED_CONTENT_FAIL' if report['counts']['different'] else 'PARSED_CONTENT_PASS')
    report['comparison_layers']=dict(parsed_content_exact=report['counts']['exact'],unnormalized_object_exact=sum(r['unnormalized_object_equal'] for r in report['comparisons']),raw_frame_bytes_exact=sum(r['raw_frame_bytes_equal'] for r in report['comparisons']),denominator=len(report['comparisons']))
    report['comparison_groups']={group:dict(total=sum(r['group']==group for r in report['comparisons']),exact=sum(r['group']==group and r['status']=='PASS' for r in report['comparisons']),different=sum(r['group']==group and r['status']=='FAIL' for r in report['comparisons'])) for group in ('eof','non-eof-invalid','valid-json','valid-evidence')}
    report['original_nine']={status:sum(r.get('original_nine_gap_index') is not None and r['status']==status for r in report['comparisons']) for status in ('PASS','FAIL')}
    report['completed_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    receipt=save(out/'observation.json',report)
    print(json.dumps(dict(finite_status=report['finite_status'],qualified=False,global_status='HOLD/NO_GO',counts=report['counts'],errors=report['errors'],receipt=receipt)),flush=True)
    return 0 if report['collection_complete'] else 2

if __name__=='__main__':raise SystemExit(main())
