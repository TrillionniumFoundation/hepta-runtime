"""Fresh fixed-1.95 full method/SDK capture with actual policy, cache and I/O."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True
TOOL = Path('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
FENCE_KEYS = ('HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')


def pin(path):
    with Path(path).open('rb') as stream: return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
def sha(raw): return hashlib.sha256(raw).hexdigest()
def dump(path, value):
    with Path(path).open('x') as stream: json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False); stream.write('\n')
def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def parse_output(raw):
    assert raw[:8] == b'HFSSO001'; at=8; rows=[]
    while at < len(raw):
        begin=at; assert len(raw)-at>=16
        metadata_len, blob_count=struct.unpack_from('<2Q',raw,at);at+=16;assert metadata_len<=len(raw)-at
        metadata_raw=raw[at:at+metadata_len];meta=json.loads(metadata_raw);metadata_offset=at;at+=metadata_len
        assert type(meta) is dict and meta['kind'] in ('scenario_start','case','scenario_end')
        blobs=[]
        for _ in range(blob_count):
            assert len(raw)-at>=8; length=struct.unpack_from('<Q',raw,at)[0];at+=8;assert length<=len(raw)-at
            body=raw[at:at+length];blobs.append({'offset':at,'bytes':length,'sha256':sha(body)});at+=length
        rows.append({'metadata':meta,'metadata_span':{'offset':metadata_offset,'bytes':metadata_len,'sha256':sha(metadata_raw)},
            'blobs':blobs,'record':{'offset':begin,'bytes':at-begin,'sha256':sha(raw[begin:at])}})
    assert at==len(raw);return rows


def validate_rows(rows, scenarios, raw):
    expected=[]
    for scenario in scenarios:
        expected.append(('scenario_start',scenario['scenario_id'],None))
        expected += [('case',scenario['scenario_id'],step['case_id']) for step in scenario['steps']]
        expected.append(('scenario_end',scenario['scenario_id'],None))
    assert [(r['metadata']['kind'],r['metadata']['scenario_id'],r['metadata'].get('case_id')) for r in rows]==expected
    index={step['case_id']:step for scene in scenarios for step in scene['steps']};markers=[];public=[]
    for row in rows:
        meta=row['metadata'];blobs=row['blobs']
        def body(idx):
            assert type(idx) is int and 0<=idx<len(blobs);span=blobs[idx];return raw[span['offset']:span['offset']+span['bytes']]
        for event in meta['events']:
            assert type(event['marker']) is int and event['marker']>1_000_000_000;markers.append(event['marker'])
        if meta['kind']!='case':continue
        step=index[meta['case_id']];assert meta['name']==step['name'] and meta['domain']==step['domain'] and meta['session']==step['session']
        assert meta['request_context_present_after'] is False
        assert type(meta['outer_call_tool_entries']) is int and type(meta['handler_entries']) is int
        if step['action']['kind']=='public':
            request=body(meta['result']['request_blob']);response=body(meta['result']['response_blob']) if meta['result']['response_blob'] is not None else b''
            expected_request=bytes.fromhex(step['action']['wire_hex']) if 'wire_hex' in step['action'] else json.dumps(step['action']['message'],sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
            assert json.loads(request)==json.loads(expected_request) and request.endswith(b'\n')
            if 'wire_hex' in step['action']:assert request==expected_request
            assert type(meta['result']['request_bytes_written']) is int and 0<=meta['result']['request_bytes_written']<=len(request)
            if meta['result']['transport']=='response':
                assert response.endswith(b'\n') and meta['result']['request_bytes_written']==len(request)
                parsed=json.loads(response);assert parsed['id']==step['case_id']
            else:
                assert meta['result']['transport'] in ('write-error','eof') and not response
                assert meta['outer_call_tool_entries']==meta['handler_entries']==0
                parsed={}
            public.append({'case_id':meta['case_id'],'response_bytes':len(response),'response_sha256':sha(response),
                'outer_calls':meta['outer_call_tool_entries'],'handler_entries':meta['handler_entries'],
                'wire_is_error':'error' in parsed,'string_is_error':parsed.get('result',{}).get('isError'),
                'transport':meta['result']['transport'],'request_bytes_written':meta['result']['request_bytes_written']})
        else:assert meta['outer_call_tool_entries']==meta['handler_entries']==0
    assert markers==list(range(1_000_000_001,1_000_000_001+len(markers)))
    return {'records':len(rows),'cases':len(index),'public_calls':len(public),'markers':len(markers),'public':public}


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output=a.output.absolute();a.output.mkdir(mode=0o700);os.umask(0o077)
    dump(a.output/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'argv':sys.argv})
    source=Path(__file__).absolute().parent;started=time.monotonic();processes=[]
    names=['run.py','cases.py','oracle/Cargo.toml','oracle/Cargo.lock','oracle/verify_sources.py','oracle/src/driver.rs']
    names += ['oracle/original/'+p.name for p in sorted((source/'oracle/original').iterdir()) if p.is_file()]
    source_pins={name:pin(source/name) for name in names}
    def record(name,command,cwd,stdin=None,fence=None):
        env=dict(os.environ);[env.pop(key,None) for key in FENCE_KEYS]
        env_control={'RUSTC':str(TOOL/'rustc'),'CARGO_TARGET_DIR':str(a.output/'target'),'CARGO_BUILD_JOBS':'2',
            'PATH':str(TOOL)+os.pathsep+os.environ.get('PATH',''),'LC_ALL':'C',**{key:None for key in FENCE_KEYS}}
        if fence:env_control.update(fence)
        for key,value in env_control.items():
            if value is None:env.pop(key,None)
            else:env[key]=value
        before=time.monotonic();timed_out=False;child=None;stdout=a.output/(name+'.stdout');stderr=a.output/(name+'.stderr')
        input_file=stdin.open('rb') if stdin else subprocess.DEVNULL
        try:
            with stdout.open('xb') as out,stderr.open('xb') as err:
                child=subprocess.Popen(command,cwd=cwd,stdin=input_file,stdout=out,stderr=err,env=env,start_new_session=True)
                try:child.wait(timeout=180)
                except subprocess.TimeoutExpired:timed_out=True;os.killpg(child.pid,signal.SIGKILL);child.wait()
        finally:
            if stdin:input_file.close()
        receipt={'name':name,'command':command,'cwd':str(cwd),'pid':child.pid,'controlled_env':env_control,'timeout_seconds':180,
            'timed_out':timed_out,'elapsed_seconds':time.monotonic()-before,'exit_code':child.returncode,
            'stdin':{'path':str(stdin),**pin(stdin)} if stdin else None,
            'stdout':{'path':str(stdout),**pin(stdout)},'stderr':{'path':str(stderr),**pin(stderr)}}
        processes.append(receipt);(a.output/'processes.json').write_text(json.dumps(processes,sort_keys=True,indent=2)+'\n')
        assert not timed_out and child.returncode==0,receipt
        return stdout.read_bytes()
    try:
        factory=load(source/'oracle/verify_sources.py','_filesystem_sdk_original_source');materialized,proof=factory.assemble(source/'oracle')
        crate=a.output/'crate'
        for name,raw in materialized.items():
            path=crate/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        dump(a.output/'SOURCE.json',{'source_root':str(source),'source_files':source_pins,'original':proof})
        rustc=record('rustc-version',[str(TOOL/'rustc'),'-Vv'],crate);cargo=record('cargo-version',[str(TOOL/'cargo'),'-Vv'],crate)
        assert rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc and cargo.startswith(b'cargo 1.95.0 ')
        record('strace-version',['/usr/bin/strace','-V'],crate)
        record('locked-build',[str(TOOL/'cargo'),'build','--release','--locked','--manifest-path',str(crate/'Cargo.toml')],crate)
        assert (crate/'Cargo.lock').read_bytes()==materialized['Cargo.lock']
        binary=a.output/'target/release/hepta-filesystem-sdk-original';binary_pin=pin(binary)
        factory=load(source/'cases.py','_filesystem_sdk_cases');fixtures=a.output/'fixtures';fixtures.mkdir(mode=0o700)
        corpus=factory.materialized(fixtures);dump(a.output/'CORPUS.json',corpus)
        for action in corpus['common_setup']:
            assert action['kind']=='mkdir';path=Path(os.fsdecode(bytes.fromhex(action['path_hex'])));assert path.is_relative_to(fixtures);path.mkdir(mode=0o700,parents=True,exist_ok=True)
        dump(a.output/'HOST.json',{'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),
            'uname':list(os.uname()),'status':Path('/proc/self/status').read_text(),'cwd':str(fixtures),'USER':os.environ.get('USER')})
        groups=[]
        for group in corpus['groups']:
            name=group['name'];input_path=a.output/(name+'.input.jsonl');policy_path=a.output/(name+'.policy.json');trace_path=a.output/(name+'.strace')
            with input_path.open('xb') as stream:
                for scenario in group['scenarios']:stream.write(factory.canonical(scenario))
            policy_path.write_bytes(factory.canonical(corpus['policies'][group['policy_id']]))
            output=record(name,['/usr/bin/strace','-f','-qq','-s','4096','-xx','-e','trace=%file,close,write,getpgid,getdents64,flock,fcntl,dup,dup2,dup3',
                '-o',str(trace_path),'--',str(binary),str(fixtures),str(policy_path)],fixtures,input_path,corpus['fence_environments'][group['fence_id']])
            assert not (a.output/(name+'.stderr')).read_bytes()
            rows=parse_output(output);summary=validate_rows(rows,group['scenarios'],output)
            with (a.output/(name+'.observations.jsonl')).open('x') as stream:
                for row in rows:stream.write(json.dumps(row,sort_keys=True,ensure_ascii=True,allow_nan=False)+'\n')
            group_result={'name':name,'policy_id':group['policy_id'],'fence_id':group['fence_id'],**summary,
                'complete_stdout_bytes':len(output),'complete_input_bytes':input_path.stat().st_size,'fulltrace':pin(trace_path)}
            groups.append(group_result);(a.output/'GROUPS.json').write_text(json.dumps(groups,sort_keys=True,indent=2)+'\n')
            for path in (input_path,a.output/(name+'.stdout'),trace_path):
                with path.open('rb') as src,(a.output/(path.name+'.gz')).open('xb') as raw:
                    with gzip.GzipFile(filename='',mode='wb',fileobj=raw,compresslevel=6,mtime=0) as dst:shutil.copyfileobj(src,dst)
        assert pin(binary)==binary_pin and {name:pin(source/name) for name in names}==source_pins
        files={path.name:pin(path) for path in sorted(a.output.iterdir()) if path.is_file()}
        result={'schema':'hepta.runtime.filesystem-sdk-original-capture.v1','status':'PASS','source_root':str(source),'fixture_root':str(fixtures),
            'counts':corpus['counts'],'actual_processes':len(processes),'fresh_locked_builds':1,'actual_replays':len(groups),'version_processes':3,
            'complete_stdout_bytes':sum(g['complete_stdout_bytes'] for g in groups),'complete_input_bytes':sum(g['complete_input_bytes'] for g in groups),
            'marker_events':sum(g['markers'] for g in groups),'actual_sdk_parameters_extractor':True,'actual_sdk_method_adapter':True,
            'original_full_router_executed':False,'original_config_loader_executed':False,'full_configured_fence_acquisition_executed':False,
            'actual_unconfigured_fence_and_early_refusals':True,'actual_request_context_and_cache':True,'actual_local_filesystem_operations':True,
            'remote_io_executed':False,'new_native_calls':0,'source_files_unchanged':True,'trace_string_limit':4096,
            'binary':{'path':str(binary),**binary_pin},'rustc_executable':{'path':str(TOOL/'rustc'),**pin(TOOL/'rustc')},
            'cargo_executable':{'path':str(TOOL/'cargo'),**pin(TOOL/'cargo')},'strace_executable':{'path':'/usr/bin/strace',**pin('/usr/bin/strace')},
            'target_rustc_info':pin(a.output/'target/.rustc_info.json'),'elapsed_seconds':time.monotonic()-started,
            'artifact_sha256':{name:value['sha256'] for name,value in files.items()},'artifact_bytes':{name:value['bytes'] for name,value in files.items()}}
        dump(a.output/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items() if k not in ('artifact_sha256','artifact_bytes')},sort_keys=True))
    except BaseException:
        dump(a.output/'FAILURE.json',{'traceback':traceback.format_exc(),'elapsed_seconds':time.monotonic()-started,'actual_processes':len(processes)});raise


if __name__=='__main__':main()
