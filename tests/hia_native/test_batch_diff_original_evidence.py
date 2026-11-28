#!/usr/bin/env python3
"""Physical receipt/stream refusals and offline two-root replay; zero HIA/Rust."""
from pathlib import Path
import gzip
import hashlib
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
import hia_native_batch_diff_qualification as q

OUTPUT=Path(os.environ['HIA_BATCH_DIFF_QUALIFICATION_OUTPUT']).resolve()
CAPTURE=Path(os.environ.get('HIA_BATCH_DIFF_EVIDENCE_CAPTURE_DIR',str(OUTPUT/'batch-diff-controls'))).resolve()
canonical=q.canonical


def sha(raw):return hashlib.sha256(raw).hexdigest()


def pin(path):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):digest.update(block);size+=len(block)
    return {'bytes':size,'sha256':digest.hexdigest()}


def replace(path,raw):
    # All snapshots are private hard links. Never mutate a shared inode.
    path.unlink();path.write_bytes(raw)


def change_json(path,edit):
    value=q.json_value(path.read_bytes());edit(value);replace(path,canonical(value))


def snapshot(folder):
    for namespace,origin,files in [('source',ROOT,BASELINE['source_sha256']),('output',OUTPUT,BASELINE['artifact_sha256'])]:
        for name,digest in files.items():
            old=origin/name;new=folder/namespace/name
            assert pin(old)['sha256']==digest
            new.parent.mkdir(parents=True,exist_ok=True);os.link(old,new)
    return folder/'source',folder/'output'


def physical_call(output,kind,edit):
    folder=output/'batch-diff';indices=[q.json_value(r) for r in (folder/'calls.jsonl').read_bytes().splitlines()]
    index=next(r for r in indices if r['kind']==kind and r['output_bytes']>0)
    path=folder/'calls.bin.gz';temporary=folder/'calls.changed.gz'
    with gzip.open(path,'rb') as src,gzip.open(temporary,'wb',compresslevel=1) as dst:
        remaining=index['stream_offset']
        while remaining:
            block=q.exact_read(src,min(1<<20,remaining));dst.write(block);remaining-=len(block)
        header=q.exact_read(src,64);_,_,_,_,ilen,olen,wlen,_=struct.unpack('<8Q',header)
        wire=q.exact_read(src,ilen);out=bytearray(q.exact_read(src,olen));work=q.exact_read(src,wlen)
        edit(out);index['output_sha256']=sha(out)
        dst.write(header);dst.write(wire);dst.write(out);dst.write(work);shutil.copyfileobj(src,dst,1<<20)
    path.unlink();temporary.rename(path)
    replace(folder/'calls.jsonl',b''.join(canonical(row) for row in indices))


def resigned_original_body(output):
    folder=output/'batch-diff-original';path=folder/'original.stdout';temporary=folder/'original.changed'
    with path.open('rb') as src,temporary.open('wb') as dst:
        magic=q.exact_read(src,8);assert magic==b'HBDIO001';dst.write(magic)
        length=q.exact_read(src,8);body=bytearray(q.exact_read(src,struct.unpack('<Q',length)[0]))
        words=struct.unpack_from('<8Q',body,8);assert words[0]==0 and words[5]>0
        offset=72+sum(words[1:5]);body[offset]^=1
        dst.write(length);dst.write(body);shutil.copyfileobj(src,dst,1<<20)
    path.unlink();temporary.rename(path)
    identity=pin(path)
    change_json(folder/'result.json',lambda row:row.update(original_stdout_sha256=identity['sha256']))
    change_json(folder/'process-receipts.json',lambda rows:rows[2]['stdout'].update(identity))
    result=q.json_value((folder/'result.json').read_bytes())
    replace(output/'original.stdout',canonical(result))
    change_json(output/'original.process.json',lambda row:row['stdout'].update(pin(output/'original.stdout')))


WORKER=r'''
from pathlib import Path
import json,sys
source,output,old_source,old_output,result=map(Path,sys.argv[1:])
allowed=(source,output,result.parent)
native=json.loads((output/'batch-diff/execution.json').read_bytes())
original=json.loads((output/'batch-diff-original/result.json').read_bytes())
blocked=(old_source,old_output,Path(native['source_root']),Path(native['capture_root']).parent,
         Path(original['runtime_root']),Path(original['output_root']).parent)
def audit(event,args):
    if event in ('subprocess.Popen','os.system','ctypes.dlopen'):
        raise PermissionError('semantic or child execution forbidden during retained evidence read')
    if event=='open' and args and isinstance(args[0],(str,bytes)):
        path=Path(args[0].decode() if isinstance(args[0],bytes) else args[0]).absolute()
        if any(path==a or a in path.parents for a in allowed):return
        if any(path==a or a in path.parents for a in blocked):
            raise PermissionError('original source/output read forbidden: '+str(path))
sys.addaudithook(audit)
sys.path.insert(0,str(source/'scripts'))
import hia_native_batch_diff_qualification as q
value=q.original_evidence(source,output)
result.write_bytes(q.canonical(value))
print(json.dumps({'status':'PASS','source':str(source),'output':str(output),'old_path_reads_forbidden':True,
 'semantic_execution_forbidden':True,'new_native_calls':0,'new_rust_processes':0},sort_keys=True))
'''

BASELINE=None;CONTROLS=[];PROCESSES=[]


class EvidenceTests(unittest.TestCase):
    def test_01_twelve_physical_or_resigned_refusals(self):
        def process(key,value):return lambda source,output:change_json(output/'native.process.json',lambda row:row.update({key:value}))
        cases=[('boolean-exit',process('exit_code',False)),('timeout',process('timed_out',True)),('deadline',process('timeout_seconds',181))]
        def command(source,output):
            change_json(output/'native.process.json',lambda row:row['command'].__setitem__(3,'/other/test.py'))
        cases.append(('wrong-command',command))
        cases.append(('missing-semantic-case',lambda s,o:change_json(o/'batch-diff/result.json',lambda row:row.update(case_count=803))))
        def image(source,output):
            path=output/'build/modules/batch-diff-diff/module.image.bin';raw=bytearray(path.read_bytes());raw[0]^=1;replace(path,raw)
        cases.append(('image-bytes',image))
        def missing_call(source,output):
            path=output/'batch-diff/calls.jsonl';replace(path,b''.join(path.read_bytes().splitlines(keepends=True)[:-1]))
        cases.append(('missing-call',missing_call))
        cases.append(('resigned-refusal-output',lambda s,o:physical_call(o,4,lambda raw:raw.__setitem__(0,0))))
        cases.append(('resigned-growth-extent',lambda s,o:physical_call(o,1,lambda raw:struct.pack_into('<Q',raw,48,struct.unpack_from('<Q',raw,48)[0]+1))))
        cases.append(('resigned-original-body',lambda s,o:resigned_original_body(o)))
        def source_bytes(source,output):
            path=source/'src/mcp/fs/text_editing.rs';replace(path,path.read_bytes()+b'\n// changed original bytes\n')
        cases.append(('original-source-bytes',source_bytes))
        cases.append(('missing-rust-process',lambda s,o:change_json(o/'batch-diff-original/process-receipts.json',lambda rows:rows.pop())))
        self.assertEqual(len(cases),12)
        for name,mutate in cases:
            with self.subTest(name=name),tempfile.TemporaryDirectory(prefix='batch-diff-refusal-',dir=OUTPUT.parent) as temporary:
                source,output=snapshot(Path(temporary));mutate(source,output)
                try:q.original_evidence(source,output)
                except (ValueError,AssertionError,OSError,KeyError,TypeError) as error:
                    CONTROLS.append({'name':name,'rejected':True,'error_type':type(error).__name__,'error':str(error)})
                else:self.fail(name+' accepted')

    def test_02_two_roots_without_original_path_reads(self):
        for index in range(2):
            with tempfile.TemporaryDirectory(prefix='batch-diff-relocated-',dir=OUTPUT.parent) as temporary:
                folder=Path(temporary);source,output=snapshot(folder)
                worker=folder/'worker.py';worker.write_text(WORKER);result=folder/'result.json'
                command=[sys.executable,'-I','-B',str(worker),str(source),str(output),str(ROOT),str(OUTPUT),str(result)]
                start=time.monotonic();timeout=False
                try:
                    child=subprocess.run(command,cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
                    code=child.returncode;stdout=child.stdout;stderr=child.stderr
                except subprocess.TimeoutExpired as error:
                    timeout=True;code=None;stdout=error.stdout or b'';stderr=error.stderr or b''
                receipt={'name':'relocated-'+str(index),'command':command,'cwd':str(source),'timeout_seconds':180,'timed_out':timeout,
                         'exit_code':code,'elapsed_seconds':time.monotonic()-start,'worker_sha256':sha(worker.read_bytes())}
                for stream,raw in [('stdout',stdout),('stderr',stderr)]:
                    path=CAPTURE/(str(index)+'.'+stream);path.write_bytes(raw)
                    receipt[stream]={'path':path.name,'bytes':len(raw),'sha256':sha(raw)}
                PROCESSES.append(receipt)
                self.assertFalse(timeout);self.assertEqual(code,0,stderr.decode(errors='replace'))
                self.assertEqual(q.json_value(result.read_bytes()),BASELINE)
                evidence=CAPTURE/(str(index)+'.result.json');evidence.write_bytes(result.read_bytes())
                receipt['evidence']={'path':evidence.name,**pin(evidence)}
                CONTROLS.append({'name':'relocated-'+str(index),'same_complete_object':True,
                                 'old_path_reads_forbidden':True,'new_native_calls':0,'new_rust_processes':0})


if __name__=='__main__':
    CAPTURE.mkdir(parents=True,exist_ok=False)
    (CAPTURE/'worker.py').write_text(WORKER)
    BASELINE=q.original_evidence(ROOT,OUTPUT);(CAPTURE/'baseline.json').write_bytes(canonical(BASELINE))
    before={'test':sha(Path(__file__).read_bytes()),'reader':sha(Path(q.__file__).read_bytes())}
    outcome=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    assert q.original_evidence(ROOT,OUTPUT)==BASELINE
    assert before=={'test':sha(Path(__file__).read_bytes()),'reader':sha(Path(q.__file__).read_bytes())}
    (CAPTURE/'controls.json').write_bytes(canonical(CONTROLS));(CAPTURE/'processes.json').write_bytes(canonical(PROCESSES))
    execution={'source_root':str(ROOT),'output_root':str(OUTPUT),'capture_root':str(CAPTURE),'python':sys.executable,
               'cwd':str(Path.cwd()),'command':[sys.executable,'-I','-B',str(Path(__file__).resolve()),*sys.argv[1:]],
               'sources':{'tests/hia_native/test_batch_diff_original_evidence.py':before['test'],
                          'scripts/hia_native_batch_diff_qualification.py':before['reader']}}
    (CAPTURE/'execution.json').write_bytes(canonical(execution))
    result={'status':'PASS' if outcome.wasSuccessful() else 'FAIL','test_groups':2,'refusal_controls':12,'relocations':2,
            'completed_controls':len(CONTROLS),'skipped':len(outcome.skipped),'errors':len(outcome.errors),'failures':len(outcome.failures),
            'test_sha256':before['test'],'reader_sha256':before['reader'],'baseline_sha256':sha(canonical(BASELINE)),
            'native_cases_added_by_replay':0,'original_processes_added_by_replay':0,
            'original_paths_removed':False,'old_path_reads_forbidden':True}
    (CAPTURE/'result.json').write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
