"""Pure-Python controls for the exact read-only View source reconstruction."""
from __future__ import annotations
import ctypes,hashlib,importlib.util,json,os,shutil,sys,tempfile
from pathlib import Path
import source_reconstruction as q

NAMES=['changed-bound-source','extra-crate-member','missing-crate-member','wrong-temporary-prefix',
 'undeclared-temporary-caller','nested-reconstruction','write-outside-reconstruction',
 'wrong-copy-source','wrong-operation-order','omitted-materialization',
 'write-text-options','changed-captured-copy','changed-captured-generated','aliased-crate-member',
 'wrong-public-temporary-prefix','public-prefix-on-view-caller','undeclared-public-caller',
 'changed-public-bound-source']

def load_source(root):
    path=root/'tests/hia_native/view_call_oracle/verify_sources.py'
    spec=importlib.util.spec_from_file_location('_history_actual_view_source_control',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def fixture(root,text,name,relative=None):
    # Test-owned Python stubs exercise the source-bound I/O adapter. They are
    # not asserted to be the actual original caller or its semantic evidence.
    space={'tempfile':tempfile,'Path':Path,'shutil':shutil}
    path=root/(relative if relative is not None else
               'scripts/hia_native_view_call_qualification.py' if name=='_original_evidence'
               else 'tests/hia_native/view_call_oracle/verify_sources.py')
    exec(compile(text,str(path),'exec'),space)
    return space[name]

def run(source):
    source=Path(source).absolute();original=load_source(source)
    global_before=(tempfile.TemporaryDirectory,shutil.copyfile,Path.mkdir,Path.write_text)
    source_before={name:(source/name).read_bytes() for name in q.PINS}
    actual=fixture(source,"def _original_evidence(callback):\n with tempfile.TemporaryDirectory(prefix='view-original-materialization-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'_original_evidence')
    public_path='scripts/hia_native_runtime_mcp_original.py'
    public=fixture(source,"def view_reference(callback):\n with tempfile.TemporaryDirectory(prefix='runtime-mcp-original-source-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'view_reference',public_path)
    public_wrong=fixture(source,"def view_reference(callback):\n with tempfile.TemporaryDirectory(prefix='view-original-materialization-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'view_reference',public_path)
    view_cross=fixture(source,"def _original_evidence(callback):\n with tempfile.TemporaryDirectory(prefix='runtime-mcp-original-source-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'_original_evidence')
    public_caller=fixture(source,"def view_reference_unadmitted(callback):\n with tempfile.TemporaryDirectory(prefix='runtime-mcp-original-source-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'view_reference_unadmitted',public_path)
    wrong_prefix=fixture(source,"def _original_evidence(callback):\n with tempfile.TemporaryDirectory(prefix='unbound-prefix-') as temporary:\n  return callback(Path(temporary)/'crate')\n",'_original_evidence')
    order=fixture(source,"def materialize(output):\n (output/'src').mkdir()\n",'materialize')
    outside=fixture(source,"def materialize(output):\n (output/'src/main.rs').write_text('not an owned operation')\n",'materialize')
    copy=fixture(source,"def materialize(output,oracle):\n output.mkdir(parents=True,exist_ok=False)\n (output/'src').mkdir()\n shutil.copyfile(oracle/'Cargo.lock',output/'Cargo.toml')\n",'materialize')
    options=fixture(source,"def materialize(output,oracle,text):\n output.mkdir(parents=True,exist_ok=False)\n (output/'src').mkdir()\n shutil.copyfile(oracle/'Cargo.toml',output/'Cargo.toml')\n shutil.copyfile(oracle/'Cargo.lock',output/'Cargo.lock')\n (output/'src/main.rs').write_text(text,encoding='utf-8')\n",'materialize')
    with tempfile.TemporaryDirectory(prefix='history-source-reconstruction-controls-') as directory:
        base=Path(directory);capture=base/'capture';(capture/'view-call-original').mkdir(parents=True)
        crate=capture/'view-call-original/crate';summary=original.materialize(source,crate)
        baseline={name:(crate/name).read_bytes() for name in q.FILES}
        rows=[];admissions=[];execution_attempts=[];active=[False]
        def audit(event,args):
            if active[0] and (event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty','mmap.__new__'} or event.startswith('ctypes.')):
                execution_attempts.append(event);raise PermissionError('source reconstruction controls do not execute native/Rust/processes')
        sys.addaudithook(audit)
        def installed(call):
            adapter=q.SourceReconstructionReads(source,capture);adapter.install()
            try:return call(adapter),adapter
            finally:
                adapter.restore()
                q.need((tempfile.TemporaryDirectory,shutil.copyfile,Path.mkdir,Path.write_text)==global_before,'all adapter aliases restored')
        def admission(caller):
            value,adapter=installed(lambda _:caller(lambda output:original.materialize(source,output)))
            q.need(value==summary and len(adapter.records)==1 and adapter.records[0]['status']=='PASS'
                and len(adapter.records[0]['operations'])==10 and adapter.violations==[],'complete actual generator read/compare')
            q.need({name:(crate/name).read_bytes() for name in q.FILES}==baseline,'all fixture file bytes unchanged')
            admissions.append(adapter.evidence())
        def refusal(name,call):
            try:call()
            except (AssertionError,PermissionError,ValueError,FileNotFoundError) as error:
                rows.append({'name':name,'exception':type(error).__name__,'message':str(error)})
            else:raise ValueError('source reconstruction control was admitted: '+name)
            q.need((tempfile.TemporaryDirectory,shutil.copyfile,Path.mkdir,Path.write_text)==global_before,'refusal leaked a patched alias')
        active[0]=True
        try:
            admission(actual);admission(public)
            changed=base/'changed-source';changed.mkdir()
            for relative in q.PINS:
                path=changed/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(source_before[relative])
            first=changed/next(iter(q.PINS));first.write_bytes(first.read_bytes()+b'\n')
            refusal('changed-bound-source',lambda:q.SourceReconstructionReads(changed,capture))
            extra=crate/'unadmitted.rs';extra.write_bytes(b'kept control\n')
            try:refusal('extra-crate-member',lambda:q.SourceReconstructionReads(source,capture))
            finally:extra.unlink()
            missing=crate/'src/bin/view_call_info_sdk.rs';saved=missing.read_bytes();missing.unlink()
            try:refusal('missing-crate-member',lambda:q.SourceReconstructionReads(source,capture))
            finally:missing.write_bytes(saved)
            refusal('wrong-temporary-prefix',lambda:installed(lambda _:wrong_prefix(lambda _:None)))
            refusal('undeclared-temporary-caller',lambda:installed(lambda _:tempfile.TemporaryDirectory(prefix='view-original-materialization-')))
            refusal('nested-reconstruction',lambda:installed(lambda _:actual(lambda _:actual(lambda _:None))))
            refusal('write-outside-reconstruction',lambda:installed(lambda _:outside(crate)))
            refusal('wrong-copy-source',lambda:installed(lambda _:actual(lambda output:copy(output,original.ROOT))))
            refusal('wrong-operation-order',lambda:installed(lambda _:actual(order)))
            refusal('omitted-materialization',lambda:installed(lambda _:actual(lambda _:None)))
            text=baseline['src/main.rs'].decode()
            refusal('write-text-options',lambda:installed(lambda _:actual(lambda output:options(output,original.ROOT,text))))
            for name,label in [('Cargo.lock','changed-captured-copy'),('src/main.rs','changed-captured-generated')]:
                path=crate/name;path.write_bytes(baseline[name]+b'\n')
                try:refusal(label,lambda:installed(lambda _:actual(lambda output:original.materialize(source,output))))
                finally:path.write_bytes(baseline[name])
            link=crate/'src/bin/view_call_info_sdk.rs';saved=link.read_bytes();link.unlink();link.symlink_to('../main.rs')
            try:refusal('aliased-crate-member',lambda:q.SourceReconstructionReads(source,capture))
            finally:link.unlink();link.write_bytes(saved)
            refusal('wrong-public-temporary-prefix',lambda:installed(lambda _:public_wrong(lambda _:None)))
            refusal('public-prefix-on-view-caller',lambda:installed(lambda _:view_cross(lambda _:None)))
            refusal('undeclared-public-caller',lambda:installed(lambda _:public_caller(lambda _:None)))
            first.write_bytes(source_before[next(iter(q.PINS))])
            public_changed=changed/public_path
            public_changed.write_bytes(public_changed.read_bytes()+b'\n')
            refusal('changed-public-bound-source',lambda:q.SourceReconstructionReads(changed,capture))
            admission(actual);admission(public)
        finally:active[0]=False
        q.need([row['name'] for row in rows]==NAMES and len(rows)==18,'complete source reconstruction refusal domain')
        q.need([(row['records'][0]['caller_source'],row['records'][0]['caller_function'],
                 row['records'][0]['temporary_prefix']) for row in admissions]==list(q.CALLERS)*2,
               'both exact caller/prefix pairs before and after refusals')
        q.need(not execution_attempts,'source reconstruction controls attempted native execution')
        q.need({name:(source/name).read_bytes() for name in q.PINS}==source_before,'bound original source changed')
        q.need({name:(crate/name).read_bytes() for name in q.FILES}==baseline,'source control fixture bytes not restored')
        return {'schema':'hepta.history.source-reconstruction-controls.v2','status':'PASS',
            'complete_generator_admissions':4,'generated_files_per_admission':7,'operations_per_admission':10,
            'exact_caller_prefix_pairs':[list(row) for row in q.CALLERS],
            'original_materialize_source_sha256':q.PINS['tests/hia_native/view_call_oracle/verify_sources.py'][1],
            'refusals':rows,'early_and_late_alias_restoration':True,
            'control_callers_are_test_owned_python_stubs':True,
            'original_materialize_function_modified':False,'actual_original_semantics_replayed':False,
            'native_or_rust_executions':0,'execution_attempts':execution_attempts,
            'source_files_unchanged':True,'fixture_file_bytes_restored':True,
            'actual_generator_summary':summary,'admissions':admissions}
