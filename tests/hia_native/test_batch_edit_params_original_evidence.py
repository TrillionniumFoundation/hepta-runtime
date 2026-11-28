#!/usr/bin/env python3
"""Post-original physical receipt controls and offline relocation; no HIA/Rust."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_batch_edit_params_qualification as q

OUTPUT=Path(os.environ['HIA_BATCH_EDIT_PARAMS_QUALIFICATION_OUTPUT']).resolve()
CAPTURE=Path(os.environ.get('HIA_BATCH_EDIT_PARAMS_EVIDENCE_CAPTURE_DIR',str(OUTPUT/'controls'))).resolve()
sha=lambda raw:hashlib.sha256(raw).hexdigest()
canonical=q.canonical

def replace(path,raw):
    path.unlink();path.write_bytes(raw)

def change_json(path,edit):
    value=q.json_value(path.read_bytes());edit(value);replace(path,canonical(value))

def snapshot(folder,baseline):
    source=folder/'source';output=folder/'output'
    for namespace,origin,files in [('source',ROOT,baseline['source_sha256']),('output',OUTPUT,baseline['artifact_sha256'])]:
        for relative,digest in files.items():
            old=origin/relative;new=folder/namespace/relative
            assert sha(old.read_bytes())==digest
            new.parent.mkdir(parents=True,exist_ok=True);os.link(old,new)
    # The global process report is an input object, not a self-referential artifact.
    os.link(OUTPUT/'processes.json',output/'processes.json')
    return source,output

def process_change(output,key,value):
    def edit(rows):
        row=next(r for r in rows if r['name']=='native');row[key]=value
    change_json(output/'processes.json',edit)

def physical_record(output,kind,edit):
    controls=[q.json_value(x) for x in (output/'native/controls.jsonl').read_bytes().splitlines()]
    control=next(r for r in controls if r['kind']==kind)
    indices=[q.json_value(x) for x in (output/'native/calls.jsonl').read_bytes().splitlines()]
    row=indices[control['call']-1]
    path=output/'native/calls.bin.gz';temporary=output/'native/calls.changed.gz'
    with gzip.open(path,'rb') as src,gzip.open(temporary,'wb',compresslevel=6) as dst:
        remaining=row['offset']
        while remaining:
            block=q.exact_read(src,min(1<<20,remaining));dst.write(block);remaining-=len(block)
        raw=bytearray(q.exact_read(src,row['bytes']))
        _,_,_,_,ilen,ocap,wcap,_=struct.unpack_from('<8Q',raw)
        at=64+ilen+wcap+ocap
        edit(raw,at)
        row['output_sha256']=sha(raw[at:at+ocap]);row['record_sha256']=sha(raw)
        dst.write(raw);shutil.copyfileobj(src,dst,1<<20)
    path.unlink();temporary.rename(path)
    replace(output/'native/calls.jsonl',b''.join(canonical(r) for r in indices))

def original_body(output):
    path=output/'original/original.stdout';temporary=path.with_suffix('.changed')
    with path.open('rb') as src,temporary.open('wb') as dst:
        line=src.readline()
        assert b'missing field `operations`' in line
        dst.write(line.replace(b'missing field `operations`',b'missing field `xperations`',1))
        shutil.copyfileobj(src,dst,1<<20)
    path.unlink();temporary.rename(path)
    digest=sha(path.read_bytes())
    change_json(output/'original/result.json',lambda r:r['output'].update(sha256=digest))
    change_json(output/'original/process-receipts.json',lambda rows:rows[2]['stdout'].update(sha256=digest))

WORKER=r'''
from pathlib import Path
import importlib.util,json,sys
source,output,old_source,old_output,result=map(Path,sys.argv[1:])
allowed=(source,output,result.parent)
blocked=(old_source,old_output)
def audit(event,args):
    if event in ('subprocess.Popen','os.system','ctypes.dlopen'):
        raise PermissionError('semantic/child execution forbidden during retained evidence read')
    if event=='open' and args and isinstance(args[0],(str,bytes)):
        path=Path(args[0].decode() if isinstance(args[0],bytes) else args[0]).absolute()
        if any(path==a or a in path.parents for a in allowed):return
        if any(path==a or a in path.parents for a in blocked):
            raise PermissionError('original source/output path read forbidden: '+str(path))
sys.addaudithook(audit)
sys.path.insert(0,str(source/'scripts'))
import hia_native_batch_edit_params_qualification as q
evidence=q.original_evidence(source,output)
result.write_bytes(q.canonical(evidence))
print(json.dumps({'status':'PASS','source':str(source),'output':str(output),'old_path_reads_forbidden':True,
 'semantic_execution_forbidden':True,'new_native_calls':0,'new_rust_processes':0},sort_keys=True))
'''

BASELINE=None;RESULTS=[];PROCESSES=[]

class EvidenceTests(unittest.TestCase):
    def test_01_twelve_physical_or_resigned_refusals(self):
        cases=[]
        cases.append(('boolean-exit',lambda s,o:process_change(o,'exit_code',False)))
        cases.append(('timeout',lambda s,o:process_change(o,'timed_out',True)))
        cases.append(('deadline',lambda s,o:process_change(o,'timeout_seconds',181)))
        def command(source,output):
            change_json(output/'processes.json',lambda rows:next(r for r in rows if r['name']=='native')['command'].__setitem__(3,'/other/test.py'))
        cases.append(('wrong-command',command))
        cases.append(('missing-semantic-case',lambda s,o:change_json(o/'native/result.json',lambda r:r.update(semantic_cases=416))))
        def image(source,output):
            manifest=q.json_value((output/'build/modules/batch-edit-projection/manifest.json').read_bytes())
            path=output/'build/modules/batch-edit-projection'/manifest['image']
            raw=bytearray(path.read_bytes());raw[0]^=1;replace(path,bytes(raw))
        cases.append(('image-bytes',image))
        def missing_call(source,output):
            path=output/'native/calls.jsonl';rows=path.read_bytes().splitlines(keepends=True);replace(path,b''.join(rows[:-1]))
        cases.append(('missing-call',missing_call))
        cases.append(('resigned-refusal-output',lambda s,o:physical_record(o,'malformed-private-frame',lambda raw,at:raw.__setitem__(at,0))))
        def grow(source,output):
            physical_record(output,'output-boundary',lambda raw,at:struct.pack_into('<Q',raw,at+48,struct.unpack_from('<Q',raw,at+48)[0]+1))
        cases.append(('resigned-growth-extent',grow))
        cases.append(('resigned-original-body',lambda s,o:original_body(o)))
        def source_change(source,output):
            path=source/'tests/hia_native/batch_edit_params_oracle/src/original.rs';replace(path,path.read_bytes()+b'\n// changed source\n')
        cases.append(('original-source-bytes',source_change))
        cases.append(('missing-rust-process',lambda s,o:change_json(o/'original/process-receipts.json',lambda rows:rows.pop())))
        self.assertEqual(len(cases),12)
        for name,mutate in cases:
            with self.subTest(name=name),tempfile.TemporaryDirectory(prefix='batch-params-refusal-',dir=OUTPUT.parent) as temporary:
                source,output=snapshot(Path(temporary),BASELINE);mutate(source,output)
                try:q.original_evidence(source,output)
                except (ValueError,AssertionError,OSError,KeyError,TypeError) as error:
                    RESULTS.append({'name':name,'rejected':True,'error_type':type(error).__name__,'error':str(error)})
                else:self.fail(name+' accepted')
    def test_02_two_roots_without_original_path_reads(self):
        for index in range(2):
            with tempfile.TemporaryDirectory(prefix='batch-params-relocated-',dir=OUTPUT.parent) as temporary:
                folder=Path(temporary);source,output=snapshot(folder,BASELINE)
                worker=folder/'worker.py';worker.write_text(WORKER)
                result=folder/'result.json'
                command=[sys.executable,'-I','-B',str(worker),str(source),str(output),str(ROOT),str(OUTPUT),str(result)]
                start=time.monotonic()
                proc=subprocess.run(command,cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
                receipt={'name':'relocated-'+str(index),'command':command,'cwd':str(source),'timeout_seconds':180,'timed_out':False,
                         'exit_code':proc.returncode,'elapsed_seconds':time.monotonic()-start,'worker_sha256':sha(worker.read_bytes())}
                for stream,raw in [('stdout',proc.stdout),('stderr',proc.stderr)]:
                    path=CAPTURE/(str(index)+'.'+stream);path.write_bytes(raw)
                    receipt[stream]={'path':path.name,'bytes':len(raw),'sha256':sha(raw)}
                PROCESSES.append(receipt)
                self.assertEqual(proc.returncode,0,proc.stderr.decode(errors='replace'))
                self.assertEqual(q.json_value(result.read_bytes()),BASELINE)
                evidence=CAPTURE/(str(index)+'.result.json');evidence.write_bytes(result.read_bytes())
                receipt['evidence']={'path':evidence.name,'bytes':evidence.stat().st_size,'sha256':sha(evidence.read_bytes())}
                RESULTS.append({'name':'relocated-'+str(index),'same_complete_object':True,
                                'old_path_reads_forbidden':True,'new_native_calls':0,'new_rust_processes':0})


if __name__=='__main__':
    CAPTURE.mkdir(parents=True,exist_ok=False)
    (CAPTURE/'worker.py').write_text(WORKER)
    BASELINE=q.original_evidence(ROOT,OUTPUT)
    (CAPTURE/'baseline.json').write_bytes(canonical(BASELINE))
    outcome=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    final=q.original_evidence(ROOT,OUTPUT)
    assert final==BASELINE
    (CAPTURE/'controls.json').write_bytes(canonical(RESULTS))
    (CAPTURE/'processes.json').write_bytes(canonical(PROCESSES))
    result={'status':'PASS' if outcome.wasSuccessful() else 'FAIL','test_groups':2,
            'refusal_controls':12,'relocations':2,'completed_controls':len(RESULTS),
            'skipped':len(outcome.skipped),'errors':len(outcome.errors),'failures':len(outcome.failures),
            'test_sha256':sha(Path(__file__).read_bytes()),'reader_sha256':sha(Path(q.__file__).read_bytes()),
            'baseline_sha256':sha(canonical(BASELINE)),'native_cases_added_by_replay':0,'original_processes_added_by_replay':0,
            'original_paths_removed':False,'old_path_reads_forbidden':True}
    (CAPTURE/'result.json').write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
