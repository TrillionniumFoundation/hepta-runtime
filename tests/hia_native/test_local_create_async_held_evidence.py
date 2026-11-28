"""Read-only refusal controls over complete real held-boundary captures."""
from __future__ import annotations
import contextlib
import copy
import gzip
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from evidence_snapshot import copy_evidence_files,unrelated_fixture_guard
from hia_native_local_create_async_qualification import (CONTROL_COUNTS,DRIVERS,FOLDER,SCOPE,TESTS,
    compact,core_native_evidence,decode,pin,reader,sha,source_evidence)

OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
COUNTS={key:0 for key in CONTROL_COUNTS}


def replace(path,data):
    path.unlink();path.write_bytes(data)


def replace_json(path,data):replace(path,compact(data)+b'\n')


@contextlib.contextmanager
def no_execution():
    attempted=[]
    def refuse(*args,**kwargs):
        attempted.append(True)
        raise AssertionError('a read-only held evidence reader attempted execution')
    with contextlib.ExitStack()as stack:
        stack.enter_context(mock.patch.object(subprocess,'Popen',refuse))
        for name in('fork','execve','system','posix_spawn','posix_spawnp'):
            if hasattr(os,name):stack.enter_context(mock.patch.object(os,name,refuse))
        yield
    if attempted:raise AssertionError('read-only control used actual execution')


class LocalCreateHeldEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=decode((OUTPUT/'result.json').read_bytes())
        with no_execution():cls.actual=core_native_evidence(OUTPUT,cls.report,source_root=ROOT)
        cls.sources=source_evidence(ROOT)

    def snapshot(self,with_sources=False):
        temporary=tempfile.TemporaryDirectory(prefix='local-create-held-evidence-',dir=OUTPUT.parent)
        self.addCleanup(temporary.cleanup);target=Path(temporary.name);output=target/'capture'
        with unrelated_fixture_guard(OUTPUT):
            copy_evidence_files(OUTPUT,output,self.actual['artifact_sha256'])
        root=ROOT
        if with_sources:
            root=target/'source'
            copy_evidence_files(ROOT,root,{name:value['sha256']for name,value in self.sources['files'].items()})
        return root,output,copy.deepcopy(self.report)

    @staticmethod
    def process_row(report):
        return next(row for row in report['checks']if row['name']==TESTS[0])

    def refuses(self,root,output,report,kind,*,data_only=False):
        with no_execution():
            with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,OSError,zlib.error)):
                if data_only:
                    reader().capture(output/FOLDER/'native',root/DRIVERS,'native',
                        binary_identity=self.actual['module']['executable_identity'])
                else:core_native_evidence(output,report,source_root=root)
        COUNTS[kind]+=1

    def test_01_actual_and_relocated_complete_capture(self):
        self.assertEqual(self.actual['status'],'PASS');COUNTS['actual_captures']+=1
        root,output,report=self.snapshot(True)
        with no_execution():
            self.assertEqual(core_native_evidence(output,report,source_root=root),self.actual)
        COUNTS['actual_captures']+=1

    def test_02_actual_process_custody_refusals(self):
        for change in('missing','duplicate','exit','boolean-exit','timeout','start','command','stdout','stderr','summary'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();row=self.process_row(report)
                if change=='missing':report['checks'].remove(row)
                elif change=='duplicate':report['checks'].append(copy.deepcopy(row))
                elif change=='exit':row['exit_code']=1
                elif change=='boolean-exit':row['exit_code']=False
                elif change=='timeout':row['timed_out']=True
                elif change=='start':row['start_error']='synthetic missing launch'
                elif change=='command':row['command'].remove('-I')
                elif change in('stdout','stderr'):
                    path=output/(TESTS[0]+'.'+change);replace(path,path.read_bytes()+b'changed\n')
                else:row['summary']['scope']['whole_runtime_replaced']=True
                self.refuses(root,output,report,'process_refusals')

    def test_03_current_source_and_original_function_refusals(self):
        names=('native/local_create_file.hepta','native/local_create_packer.hepta',
               'scripts/hia_native_local_create_async_qualification.py',
               DRIVERS+'/owned_trace.py',DRIVERS+'/held_evidence.py',DRIVERS+'/cases.json',
               DRIVERS+'/reference/src/main.rs',DRIVERS+'/reference/Cargo.lock')
        for name in names:
            with self.subTest(name=name):
                root,output,report=self.snapshot(True);path=root/name
                replace(path,path.read_bytes()+b'\n')
                self.refuses(root,output,report,'source_refusals')

    def test_04_rehashed_streams_custody_and_boundaries(self):
        changes=('case-missing','case-order','case-duplicate','trace-exit','trace-timeout',
                 'trace-count','input','file','payload','stdout','stderr','owned-tree',
                 'unreaped','wait4','close-order','repeat-pending','inject','descriptor',
                 'source-after','scope')
        for change in changes:
            with self.subTest(change=change):
                root,output,report=self.snapshot();base=output/FOLDER/'native'
                summary=decode((base/'summary.json').read_bytes())
                name=('open_ready_close_cancel'if change=='close-order'else
                      'repeat_pending_open'if change=='repeat-pending'else
                      'partial_eintr_cancel'if change=='inject'else'baseline_bytes')
                folder=base/name/'trace';result=decode((folder/'result.json').read_bytes())
                events=[decode(line)for line in(folder/'events.jsonl').read_bytes().splitlines()]
                changed_events=False;changed_result=False
                if change=='case-missing':summary['rows'].pop()
                elif change=='case-order':summary['rows'][0],summary['rows'][1]=summary['rows'][1],summary['rows'][0]
                elif change=='case-duplicate':summary['rows'][1]=copy.deepcopy(summary['rows'][0])
                elif change=='trace-exit':result['exit_codes'][str(result['root_pid'])]=False;changed_result=True
                elif change=='trace-timeout':result['timed_out']=True;changed_result=True
                elif change=='trace-count':result['syscall_counts']['write']=True;changed_result=True
                elif change=='input':
                    path=folder/'stdin.bin.gz';raw=bytearray(gzip.decompress(path.read_bytes()));raw[-1]^=1
                    replace(path,gzip.compress(raw,mtime=0));result['stdin']=pin(raw);changed_result=True
                elif change=='file':
                    path=folder/'file.bin.gz';raw=bytearray(gzip.decompress(path.read_bytes()));raw[-1]^=1
                    replace(path,gzip.compress(raw,mtime=0));result['file']=pin(raw)
                    result['filesystem']['final_entries'][0]['content']=pin(raw);changed_result=True
                elif change=='payload':
                    path=folder/'write-payloads.bin.gz';raw=bytearray(gzip.decompress(path.read_bytes()));raw[8]^=1
                    replace(path,gzip.compress(raw,mtime=0))
                    event=next(event for event in events if event['kind']=='syscall_entry'and event.get('operation')=='write')
                    event['payload']=pin(bytes(raw[8:]));changed_events=True
                elif change in('stdout','stderr'):
                    path=folder/(change+'.bin');raw=path.read_bytes()[:-1];replace(path,raw)
                    result[change]=pin(raw);changed_result=True
                elif change=='owned-tree':
                    child=next(pid for pid in result['owned_pids']if pid!=result['root_pid'])
                    result['owned_pids'].remove(child);result['exit_codes'].pop(str(child));changed_result=True
                elif change=='unreaped':result['unreaped_owned_pids']=[result['root_pid']];changed_result=True
                elif change=='wait4':
                    index=next(i for i,event in enumerate(events)if event['kind']=='mechanism_syscall_exit'
                               and event.get('nr')==61 and event.get('kernel_return',0)>0)
                    events.pop(index);changed_events=True
                elif change=='close-order':
                    close=next(event for event in events if event['kind']=='syscall_exit'and event.get('operation')=='close')
                    publication=next(event for event in events if event['kind']=='stdout_write_entry')
                    events.remove(publication);events.insert(events.index(close),publication);changed_events=True
                elif change=='repeat-pending':
                    wake=next(event for event in events if event['kind']=='forced_wake_signal')
                    pending=next(event for event in events if event['index']>wake['index']and event['kind']=='marker_entry'
                                 and event.get('action')==3 and event.get('life')==3)
                    events.remove(pending);changed_events=True
                    path=folder/'stderr.bin';raw=path.read_bytes();frame=bytes.fromhex(pending['raw_hex'])
                    self.assertIn(frame,raw);raw=raw.replace(frame,b'',1);replace(path,raw);result['stderr']=pin(raw)
                elif change=='inject':
                    event=next(event for event in events if event['kind']=='injection_prepared')
                    event['injection']['value']+=1;changed_events=True
                elif change=='descriptor':
                    event=next(event for event in events if event['kind']=='syscall_exit'and event.get('operation')=='open')
                    event['completion']=-1;changed_events=True
                elif change=='source-after':summary['source_after']['owned_trace.py']['sha256']='0'*64
                else:summary['scope']['whole_runtime_replaced']=True
                if changed_events:
                    mapping={event['index']:index for index,event in enumerate(events)}
                    duration=result['elapsed_seconds']/2
                    for index,event in enumerate(events):
                        event['index']=index;event['elapsed_seconds']=duration*index/max(1,len(events))
                        for field in('event_index','held_event'):
                            if field in event:event[field]=mapping[event[field]]
                    replace(folder/'events.jsonl',b''.join(compact(event)+b'\n'for event in events))
                    result['events']=len(events);changed_result=True
                if changed_result:
                    replace_json(folder/'result.json',result)
                    row=next(row for row in summary['rows']if row['name']==name)
                    row['result_sha256']=sha((folder/'result.json').read_bytes())
                replace_json(base/'summary.json',summary)
                self.refuses(root,output,report,'artifact_refusals',data_only=True)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateHeldEvidenceTests))
    passed=result.wasSuccessful()and result.testsRun==4 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and COUNTS==CONTROL_COUNTS
    summary=dict(schema='hepta.runtime.local-create-held-evidence-controls.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=4,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS,source_inputs=source_evidence(ROOT),
        native_evidence_sha256=sha(compact(getattr(LocalCreateHeldEvidenceTests,'actual',None))),
        new_native_calls=0,synthetic_receipt_controls=True,scope=SCOPE)
    (OUTPUT/FOLDER/'evidence-controls.json').write_bytes(compact(summary)+b'\n')
    print(compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
