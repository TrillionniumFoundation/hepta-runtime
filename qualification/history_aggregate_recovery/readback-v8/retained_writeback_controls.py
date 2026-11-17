"""Pure Python controls for the two exact retained schema write comparisons."""
from __future__ import annotations
import json,sys,tempfile
from pathlib import Path
import retained_writebacks as q

NAMES=['undeclared-summary-writer','undeclared-summary-caller','summary-wrong-root',
 'summary-wrong-order','summary-changed-argument','summary-changed-target',
 'summary-changed-input','summary-omitted-second-write','summary-nonbytes','changed-summary-source']

def fixture(source,text,function,path):
    space={'Path':Path};exec(compile(text,str(source/path),'exec'),space);return space[function]

def run(source):
    source=Path(source).absolute();source_before={name:(source/name).read_bytes() for name in q.PINS}
    # Keep the actual original for-loop caller shape for frame admission.
    writer=fixture(source,"def additional_reference_summary(output,payloads):\n sizes=[]\n for name,raw in payloads:\n  sizes.append((output/name).write_bytes(raw))\n return sizes\n",'additional_reference_summary',q.CALLER[0])
    wrong_writer=fixture(source,"def other_summary(output,payloads):\n for name,raw in payloads:\n  (output/name).write_bytes(raw)\n",'other_summary',q.CALLER[0])
    parent=fixture(source,"def view_reference(callback,output,payloads):\n return callback(output,payloads)\n",'view_reference',q.PARENT[0])
    with tempfile.TemporaryDirectory(prefix='history-schema-write-controls-') as name:
        base=Path(name);capture=base/'capture';folder=capture/'view-call-original';folder.mkdir(parents=True)
        payloads=[(q.OUTPUTS[0],b'{"raw":true}\n'),(q.OUTPUTS[1],b'{"public":true}\n')]
        (folder/q.INPUT).write_bytes(b''.join(raw for _,raw in payloads))
        for filename,raw in payloads:(folder/filename).write_bytes(raw)
        baseline={filename:(folder/filename).read_bytes() for filename in (q.INPUT,*q.OUTPUTS)}
        saved=Path.write_bytes;rows=[];admissions=[];active=[False];execution_attempts=[]
        def audit(event,args):
            if active[0] and (event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty','mmap.__new__'} or event.startswith('ctypes.')):
                execution_attempts.append(event);raise PermissionError('schema controls cannot execute a process or native code')
        sys.addaudithook(audit)
        def installed(call,mutate=None):
            adapter=q.RetainedSchemaWrites(source,capture)
            if mutate is not None:mutate()
            adapter.install()
            try:
                result=call(adapter);adapter.check_complete();return result,adapter
            finally:
                adapter.restore();q.need(Path.write_bytes is saved,'schema writer alias restored')
        def admission():
            result,adapter=installed(lambda _:parent(writer,folder,payloads))
            q.need(result==[len(raw) for _,raw in payloads] and len(adapter.records)==1,'both complete schema writes and byte counts')
            q.need({filename:(folder/filename).read_bytes() for filename in baseline}==baseline,'complete schema fixture unchanged')
            admissions.append(adapter.evidence())
        def refuses(label,call):
            try:call()
            except (ValueError,PermissionError) as error:rows.append({'name':label,'exception':type(error).__name__,'message':str(error)})
            else:raise ValueError('schema write control admitted: '+label)
            q.need(Path.write_bytes is saved,'refusal leaked schema writer alias')
        active[0]=True
        try:
            admission()
            refuses('undeclared-summary-writer',lambda:installed(lambda _:parent(wrong_writer,folder,payloads)))
            refuses('undeclared-summary-caller',lambda:installed(lambda _:writer(folder,payloads)))
            refuses('summary-wrong-root',lambda:installed(lambda _:parent(writer,base,payloads)))
            refuses('summary-wrong-order',lambda:installed(lambda _:parent(writer,folder,list(reversed(payloads)))))
            changed=[(payloads[0][0],payloads[0][1]+b' '),payloads[1]]
            refuses('summary-changed-argument',lambda:installed(lambda _:parent(writer,folder,changed)))
            for filename,label in [(q.OUTPUTS[0],'summary-changed-target'),(q.INPUT,'summary-changed-input')]:
                try:
                    refuses(label,lambda:installed(lambda _:parent(writer,folder,payloads),
                        mutate=lambda:(folder/filename).write_bytes(baseline[filename]+b' ')))
                finally:(folder/filename).write_bytes(baseline[filename])
            refuses('summary-omitted-second-write',lambda:installed(lambda _:parent(writer,folder,payloads[:1])))
            refuses('summary-nonbytes',lambda:installed(lambda _:parent(writer,folder,[(q.OUTPUTS[0],bytearray(payloads[0][1])),payloads[1]])))
            changed_source=base/'changed-source'
            for filename,raw in source_before.items():
                path=changed_source/filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            path=changed_source/q.CALLER[0];path.write_bytes(path.read_bytes()+b'\n')
            refuses('changed-summary-source',lambda:q.RetainedSchemaWrites(changed_source,capture))
            admission()
        finally:active[0]=False
        q.need([row['name'] for row in rows]==NAMES and len(rows)==10,'complete schema refusal controls')
        q.need(not execution_attempts and len(admissions)==2,'two actual mechanical admissions and no execution')
        q.need({filename:(folder/filename).read_bytes() for filename in baseline}==baseline,'all schema fixture bytes restored')
        q.need({name:(source/name).read_bytes() for name in q.PINS}==source_before,'all exact original sources unchanged')
        return {'schema':'hepta.history.retained-schema-writeback-controls.v1','status':'PASS',
            'complete_pair_admissions':2,'complete_files_per_pair':2,'refusals':rows,
            'early_and_late_alias_restoration':True,'control_callers_are_test_owned_python_stubs':True,
            'original_summary_function_modified':False,'actual_original_semantics_replayed':False,
            'native_or_rust_executions':0,'execution_attempts':execution_attempts,
            'source_files_unchanged':True,'fixture_file_bytes_restored':True,'admissions':admissions}
