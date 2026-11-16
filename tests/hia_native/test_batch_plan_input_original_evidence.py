"""Physical and re-signed refusals plus two real, offline reader processes."""
from pathlib import Path
import copy
import gzip
import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
import venv

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_batch_plan_input_qualification as q
OUTPUT=Path(os.environ['HIA_BATCH_PLAN_INPUT_QUALIFICATION_OUTPUT']).resolve()
CAPTURE=Path(os.environ['HIA_BATCH_PLAN_INPUT_EVIDENCE_CAPTURE_DIR']).resolve()
ALLOW_RENAME=os.environ.get('HIA_BATCH_PLAN_INPUT_ALLOW_ORIGIN_RENAME')=='1'
def save(path,value):path.write_bytes(q.canonical(value))
def replace(path,raw):
    temporary=path.with_name(path.name+'.replacement');temporary.write_bytes(raw);temporary.replace(path)
def clone(source,output,target,proof,links=False):
    new_source,new_output=target/'source',target/'output';new_source.mkdir(parents=True);new_output.mkdir()
    for base,dest,pins in [(source,new_source,proof['source_sha256']),(output,new_output,proof['artifact_sha256'])]:
        for name,digest in pins.items():
            original=base/name;copied=dest/name;copied.parent.mkdir(parents=True,exist_ok=True)
            # Retained mutation fixtures must not add aliases to the source
            # checkout: other owner readers require ordinary single-link files.
            if links and base==output:os.link(original,copied)
            else:shutil.copyfile(original,copied)
    return new_source,new_output
def portable_venv(environment):
    # Retain the actual independent interpreter as ordinary evidence files.
    # venv creates lib64 as an alias even when executable copies are requested.
    venv.EnvBuilder(with_pip=False,symlinks=False).create(environment)
    alias=environment/'lib64'
    if alias.is_symlink():
        q.same(os.readlink(alias),'lib','standard independent interpreter library alias')
        alias.unlink();shutil.copytree(environment/'lib',alias)
    for path in environment.rglob('*'):
        q.need(not path.is_symlink() and (path.is_file() or path.is_dir()),
               'independent interpreter evidence must contain ordinary files and directories')
def repin_native(output):
    original=q.json_value((output/'original/result.json').read_bytes())
    original['native_artifacts_before_and_after']={name:q.pin(output/'native'/name) for name in original['native_artifacts_before_and_after']}
    original['input']=q.pin(output/'native/original-input.jsonl')
    replace(output/'original/result.json',q.canonical(original));replace(output/'original.stdout',q.canonical(original))
    native=q.json_value((output/'native/result.json').read_bytes())
    replace(output/'native.stdout',q.canonical({**native,'skipped':0,'errors':0,'failures':0}))
    for name in ('native','original'):
        path=output/(name+'.process.json');row=q.json_value(path.read_bytes())
        for kind in ('stdout','stderr'):row[kind].update(q.pin(output/row[kind]['path']))
        replace(path,q.canonical(row))
    rows=q.json_value((output/'original/processes.json').read_bytes())
    rows[-1]['stdin'].update(original['input']);replace(output/'original/processes.json',q.canonical(rows))

def mutated(source,output,name):
    if name=='missing-native-index':(output/'native/calls.jsonl').unlink();return
    if name=='changed-native-result':
        path=output/'native/native-results.bin';raw=bytearray(path.read_bytes());raw[32]^=1;replace(path,bytes(raw));return
    if name=='truncated-original-output':
        path=output/'original/original.stdout';replace(path,path.read_bytes()[:-1]);return
    if name=='changed-owner-source':
        path=source/'native/batch_plan_input.hepta';replace(path,path.read_bytes()+b'\n');return
    if name=='changed-image':
        path=output/'build/modules/batch-plan-input-input/module.image.bin';raw=bytearray(path.read_bytes());raw[0]^=1;replace(path,bytes(raw));return
    if name=='changed-compiler-output-tail':
        path=output/'build/modules/batch-plan-input-input/module.output.bin';raw=bytearray(path.read_bytes());raw[-1]^=1;replace(path,bytes(raw));return
    if name=='changed-native-deadline':
        path=output/'native.process.json';row=q.json_value(path.read_bytes());row['timeout_seconds']=181;replace(path,q.canonical(row));return
    if name=='changed-locked-original-command':
        path=output/'original/processes.json';rows=q.json_value(path.read_bytes());rows[2]['command'][3]='--offline';replace(path,q.canonical(rows));return
    if name in ('resigned-missing-case','resigned-duplicate-call'):
        path=output/'native/native-cases.jsonl';rows=[q.json_value(raw) for raw in path.read_bytes().splitlines()]
        if name=='resigned-missing-case':rows.pop()
        else:rows[0]['value_calls'].insert(0,rows[0]['value_calls'][0])
        replace(path,b''.join(q.canonical(row)for row in rows));repin_native(output);return
    if name=='resigned-native-output-magic':
        path=output/'native/calls.bin.gz';index=output/'native/calls.jsonl';rows=[q.json_value(raw)for raw in index.read_bytes().splitlines()]
        temporary=path.with_name('mutated-calls.bin.gz')
        with gzip.open(path,'rb')as original,gzip.open(temporary,'wb',compresslevel=1)as changed:
            header=q.exact_read(original,64);_,_,_,_,n,cap,wcap,_=struct.unpack('<8Q',header)
            record=bytearray(header+q.exact_read(original,n+2*wcap+2*cap));at=64+n+wcap+cap;record[at]^=1
            rows[0]['output_sha256']=q.digest(record[at:at+cap]);rows[0]['record_sha256']=q.digest(record)
            changed.write(record);shutil.copyfileobj(original,changed,1<<20)
        temporary.replace(path);replace(index,b''.join(q.canonical(row)for row in rows));repin_native(output);return
    if name=='resigned-original-input':
        path=output/'native/original-input.jsonl';temporary=path.with_name('mutated-input.jsonl')
        with path.open('rb')as original,temporary.open('xb')as changed:
            row=q.json_value(original.readline());row['raw_json']='{"path":"changed"}'
            changed.write(q.canonical(row));shutil.copyfileobj(original,changed,1<<20)
        temporary.replace(path);repin_native(output);return
    raise AssertionError(name)

CHILD="""from pathlib import Path
import importlib.util,json,os,subprocess,sys
root,output,blocked,emit=Path(sys.argv[1]),Path(sys.argv[2]),json.loads(sys.argv[3]),Path(sys.argv[4])
blocked=[Path(p)for p in blocked];presence=[{'path':str(p),'absent':not p.exists()}for p in blocked]
absent=all(row['absent']for row in presence)
def audit(event,args):
 if event=='subprocess.Popen':raise AssertionError('pure reader started a process')
 if event=='open' and args and isinstance(args[0],(str,bytes)):
  path=Path(args[0].decode()if isinstance(args[0],bytes)else args[0]).absolute()
  if path==emit or path==root or path.is_relative_to(root) or path==output or path.is_relative_to(output):return
  if any(path==p or path.is_relative_to(p)for p in blocked):raise AssertionError('pure reader opened original execution path: '+str(path))
sys.addaudithook(audit);sys.path.insert(0,str(root/'scripts'))
denials=[]
for path in blocked:
 try:
  with (path/'__batch_input_forbidden_probe__').open('rb')as stream:stream.read(1)
 except AssertionError:denials.append(str(path))
 else:raise AssertionError('original execution path was not blocked')
spec=importlib.util.spec_from_file_location('_independent_batch_input_reader',root/'scripts/hia_native_batch_plan_input_qualification.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
result=reader.native_evidence(root,output,original=True);emit.write_bytes(reader.canonical(result))
print(json.dumps({'status':'PASS','all_blocked_roots_absent':absent,'blocked_roots':presence,'actual_open_denials':denials,'complete_evidence':reader.pin(emit),'python':sys.executable,'pid':os.getpid(),'new_native_calls':0,'new_rust_processes':0},sort_keys=True))
"""

def main():
    CAPTURE.mkdir(parents=True,exist_ok=False);began=time.monotonic();baseline=q.native_evidence(ROOT,OUTPUT,original=True)
    save(CAPTURE/'baseline.json',baseline);events=[]
    names=['missing-native-index','changed-native-result','truncated-original-output','changed-owner-source','changed-image',
           'changed-compiler-output-tail','changed-native-deadline','changed-locked-original-command','resigned-missing-case',
           'resigned-duplicate-call','resigned-native-output-magic','resigned-original-input']
    for name in names:
        start=time.monotonic();source,output=clone(ROOT,OUTPUT,CAPTURE/name,baseline,links=True);mutated(source,output,name)
        try:q.native_evidence(source,output,original=True)
        except (ValueError,AssertionError,FileNotFoundError,EOFError)as error:
            events.append({'name':name,'status':'REJECTED','type':type(error).__name__,'message':str(error),'elapsed_seconds':time.monotonic()-start})
            save(CAPTURE/'refusals.json',events)
        else:raise AssertionError('altered full evidence admitted: '+name)
    moved=[clone(ROOT,OUTPUT,CAPTURE/name,baseline)for name in ('relocated-one','relocated-two')]
    environment=CAPTURE/'independent-python';portable_venv(environment)
    interpreters=[Path(sys.executable),environment/'bin/python']
    native=q.json_value((OUTPUT/'native/result.json').read_bytes())
    blocked=list(dict.fromkeys([str(ROOT),str(OUTPUT),native['execution_source_root'],native['execution_output_root']]))
    if ALLOW_RENAME:
        for name in blocked:
            original=Path(name);q.need(not CAPTURE.is_relative_to(original),'controls must be outside every renamed origin')
    renamed=[];records=[]
    try:
        if ALLOW_RENAME:
            for name in sorted(blocked,key=lambda p:len(Path(p).parts),reverse=True):
                path=Path(name)
                if path.exists():
                    destination=path.with_name(path.name+'.absent-for-batch-input-controls');q.need(not destination.exists(),'origin quarantine collision')
                    path.rename(destination);renamed.append((path,destination));save(CAPTURE/'origin-renames.json',[[str(a),str(b)]for a,b in renamed])
        for index,((source,output),python)in enumerate(zip(moved,interpreters)):
            folder=CAPTURE/f'reader-{index+1}';folder.mkdir();emit=folder/'EVIDENCE.json'
            command=[str(python),'-I','-B','-c',CHILD,str(source),str(output),json.dumps(blocked),str(emit)]
            start=time.monotonic();timed=False
            with (folder/'stdout').open('xb')as out,(folder/'stderr').open('xb')as err:
                child=subprocess.Popen(command,cwd=source,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
                try:code=child.wait(timeout=180)
                except subprocess.TimeoutExpired:timed=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=3)
            row={'command':command,'cwd':str(source),'pid':child.pid,'timeout_seconds':180,'timed_out':timed,'exit_code':code,'elapsed_seconds':time.monotonic()-start}
            for kind in ('stdout','stderr'):row[kind]={'path':str((folder/kind).relative_to(CAPTURE)),**q.pin(folder/kind)}
            records.append(row);save(CAPTURE/'reader-processes.json',records)
            q.need(code==0 and not timed,(folder/'stderr').read_text());result=q.json_value((folder/'stdout').read_bytes())
            q.same(result['status'],'PASS','actual relocated reader');q.same(result['complete_evidence'],q.pin(emit),'actual complete relocated evidence')
            q.same(q.json_value(emit.read_bytes()),baseline,'all relocated evidence fields')
            if ALLOW_RENAME:q.same(result['all_blocked_roots_absent'],True,'all original execution roots actually absent')
            if index==0:
                for path in (source,output):
                    unavailable=path.with_name(path.name+'-unavailable');path.rename(unavailable);blocked.append(str(path))
    finally:
        for path,unavailable in reversed(renamed):unavailable.rename(path)
    for base,pins in [(ROOT,baseline['source_sha256']),(OUTPUT,baseline['artifact_sha256'])]:
        for name,digest in pins.items():q.same(q.pin(base/name)['sha256'],digest,'original evidence unchanged after physical controls')
    result={'schema':'hepta.runtime.batch-plan-input-controls.v1','status':'PASS','test_groups':2,'controls':12,'events':events,
            'physical_relocations':2,'actual_reader_processes':2,'original_paths_blocked':True,'original_roots_actually_absent':ALLOW_RENAME,
            'first_relocation_unavailable_during_second':True,'actual_second_venv':True,'complete_objects_equal':True,
            'baseline':q.pin(CAPTURE/'baseline.json'),'source_files':len(baseline['source_sha256']),'artifact_files':len(baseline['artifact_sha256']),
            'source_and_artifacts_unchanged':True,'elapsed_seconds':time.monotonic()-began,'python':sys.executable,'pid':os.getpid(),
            'execution_source_root':str(ROOT),'execution_output_root':str(OUTPUT),'execution_capture_root':str(CAPTURE),
            'new_native_calls':0,'new_rust_processes':0,'public_route_replaced':False,'whole_runtime_replaced':False}
    save(CAPTURE/'result.json',result);print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
