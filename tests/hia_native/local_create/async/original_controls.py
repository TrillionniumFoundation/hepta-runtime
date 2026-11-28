"""Read-only controls for the five actual async-reference process receipts."""
from pathlib import Path
import contextlib
import copy
import gzip
import os
import subprocess
import tempfile
import zlib
from unittest import mock

COUNTS=dict(actual_captures=2,process_refusals=10,source_refusals=4,reference_refusals=8,stream_refusals=4)


@contextlib.contextmanager
def no_execution():
    attempted=[]
    def deny(*args,**kwargs):
        attempted.append(True);raise AssertionError('original evidence reader attempted execution')
    with contextlib.ExitStack()as stack:
        stack.enter_context(mock.patch.object(subprocess,'Popen',deny))
        for name in('fork','execve','system','posix_spawn','posix_spawnp'):
            if hasattr(os,name):stack.enter_context(mock.patch.object(os,name,deny))
        yield
    if attempted:raise AssertionError('read-only original control executed a process')


def run(output,report,rustc,helper,source_root):
    from evidence_snapshot import copy_evidence_files,unrelated_fixture_guard
    output=Path(output).resolve();root=Path(source_root).resolve()
    with no_execution():actual=helper.original_capture(output,report,rustc,source_root=root)
    sources=helper.source_evidence(root);counts={key:0 for key in COUNTS}
    counts['actual_captures']+=1

    @contextlib.contextmanager
    def snapshot(with_source=False):
        with tempfile.TemporaryDirectory(prefix='local-create-held-original-control-',dir=output.parent)as folder:
            folder=Path(folder);capture=folder/'capture'
            with unrelated_fixture_guard(output):
                copy_evidence_files(output,capture,actual['artifact_sha256'])
            source=root
            if with_source:
                source=folder/'source'
                copy_evidence_files(root,source,{name:value['sha256']for name,value in sources['files'].items()})
            yield source,capture,copy.deepcopy(report)

    def replace(path,raw):
        path.unlink();path.write_bytes(raw)
    def write_json(path,value):replace(path,helper.compact(value)+b'\n')

    def refusal(source,capture,changed,kind):
        refused=False
        with no_execution():
            try:helper.original_capture(capture,changed,rustc,source_root=source)
            except(ValueError,KeyError,TypeError,AssertionError,OSError,zlib.error):refused=True
        if not refused:raise AssertionError('original evidence mutation was admitted: '+kind)
        counts[kind]+=1

    with snapshot(True)as(source,capture,changed):
        with no_execution():
            helper.exact(helper.original_capture(capture,changed,rustc,source_root=source),actual,
                         'relocated complete original capture differs')
        counts['actual_captures']+=1
    for name in helper.PROCESS_NAMES:
        for change in('missing','boolean-exit'):
            with snapshot()as(source,capture,changed):
                row=next(row for row in changed['checks']if row['name']==name)
                if change=='missing':changed['checks'].remove(row)
                else:row['exit_code']=False
                refusal(source,capture,changed,'process_refusals')
    changes=(('source','reference/src/main.rs'),('source','reference/src/original_function.rs'),
             ('capture','src/original_function.rs'),('capture','Cargo.lock'))
    for kind,name in changes:
        with snapshot(kind=='source')as(source,capture,changed):
            path=(source/helper.DRIVERS/name if kind=='source'else
                  capture/helper.FOLDER/'reference/source'/name)
            replace(path,path.read_bytes()+b'\n')
            refusal(source,capture,changed,'source_refusals')
    for change in('fresh-target','fresh-count','scope','compiler','environment','commands','executable','origin'):
        with snapshot()as(source,capture,changed):
            path=capture/helper.FOLDER/'reference/reference-build.json';receipt=helper.decode(path.read_bytes())
            if change=='fresh-target':receipt['fresh_target_directory']=False
            elif change=='fresh-count':receipt['fresh_locked_builds']=True
            elif change=='scope':receipt['scope']['whole_runtime_replaced']=True
            elif change=='compiler':receipt['compiler_after']['rustc']['sha256']='0'*64
            elif change=='environment':receipt['environment_binding']['selected'].pop('CARGO_ENCODED_RUSTFLAGS')
            elif change=='commands':receipt['commands'][helper.PROCESS_NAMES[-1]].remove('-I')
            elif change=='origin':receipt['execution']['output']+='/invented'
            else:
                binary=capture/receipt['executable']['path'];raw=bytearray(binary.read_bytes());raw[-1]^=1
                replace(binary,raw);receipt['executable'].update(helper.pin(raw))
            write_json(path,receipt)
            refusal(source,capture,changed,'reference_refusals')
    for change in('case-missing','input','stderr','child-exit'):
        with snapshot()as(source,capture,changed):
            base=capture/helper.FOLDER/'original';summary_path=base/'summary.json'
            summary=helper.decode(summary_path.read_bytes())
            if change=='case-missing':summary['rows'].pop()
            else:
                trace=base/'baseline_bytes/trace';path=trace/'result.json';result=helper.decode(path.read_bytes())
                if change=='child-exit':result['exit_codes'][str(result['root_pid'])]=False
                elif change=='input':
                    artifact=trace/'stdin.bin.gz';raw=bytearray(gzip.decompress(artifact.read_bytes()));raw[-1]^=1
                    replace(artifact,gzip.compress(raw,mtime=0));result['stdin']=helper.pin(raw)
                else:
                    artifact=trace/'stderr.bin';raw=artifact.read_bytes()[:-1]
                    replace(artifact,raw);result['stderr']=helper.pin(raw)
                write_json(path,result)
                row=next(row for row in summary['rows']if row['name']=='baseline_bytes')
                row['result_sha256']=helper.sha(path.read_bytes())
            write_json(summary_path,summary)
            refusal(source,capture,changed,'stream_refusals')
    helper.exact(counts,COUNTS,'complete original receipt refusal domain differs')
    result=dict(schema='hepta.runtime.local-create-held-original-controls.v1',status='PASS',
                counts=counts,source_inputs=sources,original_evidence_sha256=helper.sha(helper.compact(actual)),
                new_native_or_rust_processes=0,synthetic_receipt_controls=True,scope=helper.SCOPE)
    path=output/helper.FOLDER/'original-controls.json'
    with path.open('xb')as stream:stream.write(helper.compact(result)+b'\n')
    return result
