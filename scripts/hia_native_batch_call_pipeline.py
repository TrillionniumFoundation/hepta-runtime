"""Main Batch producers retain their actual child PIDs and complete streams."""
from __future__ import annotations
from pathlib import Path
import hashlib,importlib,json,math,os,re,shutil,signal,stat,subprocess,sys,time,traceback

KEY='batch_call'
FOLDER='batch-call'
MANIFEST=FOLDER+'/graph-v1/native/manifest.json'
NATIVE_TEST='test_batch_call_native.py'
PACKING_TEST='test_batch_call_packing.py'
ASYNC_TEST='test_batch_call_async.py'
ORIGINAL_FOLDER='tests/hia_native/batch_call_oracle/original'
ASYNC_DRIVER='tests/hia_native/batch_call_oracle/async_lock_controls.py'
CONTROLS_DRIVER='tests/hia_native/batch_call_oracle/evidence_controls.py'
READER_FOLDER='tests/hia_native/batch_call_oracle/readers'
PRIVATE_READER='scripts/hia_native_batch_call_controls.py'
PARTITIONS=('small','wide','async')

def need(value,message):
    if not value:raise ValueError(message)
def canonical(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def regular_path(path):
    path=Path(path).absolute()
    need(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),
         'Batch evidence path crosses a symlink or is not a regular file')
    return path
def pin(path):
    path=regular_path(path)
    with path.open('rb') as stream:value=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':value}
def write_new(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(canonical(value))
def object_at(path):
    from hia_native_runtime_mcp_evidence import decode
    value=decode(regular_path(path).read_bytes());canonical(value);return value
def exact(actual,expected,message):need(canonical(actual)==canonical(expected),message)
def inside(root,name):
    root=Path(root);part=Path(name)
    need(not part.is_absolute() and '..' not in part.parts,'relative owned artifact path')
    cursor=root;need(not cursor.is_symlink(),'symlinked owned root')
    for piece in part.parts:
        cursor=cursor/piece;need(not cursor.is_symlink(),'symlinked owned artifact')
    return root/part

def process(root,folder,name,command,*,plain_stream_names=False,record_name=True):
    root,folder=Path(root),Path(folder);folder.mkdir(parents=True,exist_ok=True)
    paths={kind:folder/(kind if plain_stream_names else name+'.'+kind) for kind in ('stdout','stderr')}
    started=time.monotonic_ns();pid=None;code=None;timed=False;error=None
    with paths['stdout'].open('xb') as stdout,paths['stderr'].open('xb') as stderr:
        try:
            child=subprocess.Popen(command,cwd=root,stdin=subprocess.DEVNULL,
                                   stdout=stdout,stderr=stderr,start_new_session=True)
            pid=child.pid
            try:code=child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed=True
                try:os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                code=child.wait(timeout=10)
        except BaseException:error=traceback.format_exc()
    finished=time.monotonic_ns()
    row={'command':list(command),'cwd':str(root),'pid':pid,'exit_code':code,
         'timed_out':timed,'start_error':error,'timeout_seconds':180,
         'started_monotonic_ns':started,'finished_monotonic_ns':finished,
         'elapsed_seconds':(finished-started)/1e9,'stdout':pin(paths['stdout']),'stderr':pin(paths['stderr'])}
    if not plain_stream_names and record_name:row['name']=name
    write_new(folder/('PROCESS.json' if plain_stream_names else name+'.process.json'),row)
    need(code==0 and not timed and error is None,'actual Batch '+name+' failed; complete evidence retained')
    need(paths['stderr'].read_bytes()==b'','unexpected actual Batch '+name+' stderr')
    return row

def verify_sources(root,table):
    need(type(table) is dict and table,'nonempty source closure')
    for name,digest in table.items():
        need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'source digest')
        exact(pin(inside(root,name))['sha256'],digest,'source changed: '+name)

def build(hepta,output,*,source_root,source_sha256):
    root=Path(source_root).resolve();output=Path(output).resolve();base=output/FOLDER
    base.mkdir(parents=True,exist_ok=False);manifest=output/MANIFEST
    verify_sources(root,source_sha256);write_new(base/'SOURCE-FILES.json',source_sha256)
    command=[sys.executable,'-I','-B',str(root/'scripts/hia_native_batch_call_build.py'),
             '--hepta',str(Path(hepta).resolve()),'--output',str(manifest.parent),'--source',str(root)]
    row=process(root,base,'build',command);verify_sources(root,source_sha256)
    need(manifest.is_file(),'actual source-owned Batch builder produced no manifest')
    write_new(base/'prepared.json',{'schema':'hepta.runtime.batch-call-main-prepared.v1',
              'source_root':str(root),'output_root':str(base),'python':sys.executable,
              'manifest':str(manifest),'manifest_pin':pin(manifest),'build_process':row,
              'source_table_pin':pin(base/'SOURCE-FILES.json'),'fresh_original_comparison_complete':False})
    return manifest

def module(output,report):
    item=report['modules'][KEY]
    exact([item.get('source'),item.get('builder'),item.get('manifest')],
          ['native/batch_call.hepta',KEY,MANIFEST],'registered Batch component')
    path=inside(output,MANIFEST);exact(pin(path)['sha256'],item['sha256'],'registered Batch bundle bytes')
    return path

def environment(root,output,report):
    manifest=module(Path(output),report)
    return {'HIA_BATCH_CALL_MANIFEST':str(manifest),'HIA_BATCH_CALL_CAPTURE_ROOT':str(Path(output)/FOLDER)}

def execution_environment():
    root=Path(__file__).resolve().parents[1];base=Path(os.environ['HIA_BATCH_CALL_CAPTURE_ROOT']).absolute()
    manifest=Path(os.environ['HIA_BATCH_CALL_MANIFEST']).absolute();prepared=object_at(base/'prepared.json')
    exact([prepared['source_root'],prepared['output_root'],prepared['manifest'],prepared['python']],
          [str(root),str(base),str(manifest),sys.executable],'actual prepared Batch origin and interpreter')
    exact(pin(manifest),prepared['manifest_pin'],'prepared actual native graph')
    exact(pin(base/'SOURCE-FILES.json'),prepared['source_table_pin'],'prepared source closure')
    verify_sources(root,object_at(base/'SOURCE-FILES.json'))
    return root,base,manifest,prepared

def reader_at(root):
    folder=Path(root)/READER_FOLDER
    for name in ('capture_format','native_predecessor','trace_evidence','retained_comparison',
                 'strict_reference','async_evidence','qualification','final_evidence'):
        old=sys.modules.get(name)
        if old is not None:need(Path(old.__file__).resolve()==(folder/(name+'.py')).resolve(),'different Batch reader imported')
    sys.path.insert(0,str(folder));return importlib.import_module('qualification')

def admit_native(root,base,prepared):
    root,base=Path(root),Path(base);old_source=Path(prepared['source_root']);old_base=Path(prepared['output_root'])
    return reader_at(root).native_evidence(native_source=old_source,native_run=old_base,
        build_source=old_source,manifest=Path(prepared['manifest']),
        origins=[(old_source,root),(old_base,base)],private_reader=old_source/PRIVATE_READER)

def run_native():
    root,base,manifest,prepared=execution_environment();rows=[prepared['build_process']]
    command=[sys.executable,'-I','-B',str(root/'tests/hia_native/test_batch_call_state.py'),
             '--manifest',str(manifest),'--output',str(base/'state-controls')]
    rows.append(process(root,base,'private-state',command))
    for part in PARTITIONS:
        command=[sys.executable,'-I','-B',str(root/'tests/hia_native/test_batch_call.py'),
                 '--manifest',str(manifest),'--output',str(base/('output-'+part)),'--partition',part]
        rows.append(process(root,base,part,command))
    verify_sources(root,object_at(base/'SOURCE-FILES.json'));write_new(base/'PROCESSES.json',rows)
    write_new(base/'RESULT.json',{'status':'PASS','processes':rows,'source_unchanged':True,
              'original_reference_status':'NOT_RUN','public_handler_replaced':False,
              'whole_runtime_replaced':False,'native_manifest':str(manifest),
              'native_manifest_sha256':pin(manifest)['sha256']})
    admitted=admit_native(root,base,prepared);write_new(base/'native-admission.json',admitted)
    summary={'schema':'hepta.runtime.batch-call-main-native.v1','status':'PASS','test_groups':4,
             'cases':215,'post_cancel_followups':2,'private_state_controls':52,
             'native_admission':pin(base/'native-admission.json'),
             'execution_source_root':str(root),'execution_output_root':str(base),
             'original_comparison_complete':False,'public_handler_replaced':False,'whole_runtime_replaced':False,
             'errors':0,'failures':0,'skipped':0}
    write_new(base/'native-wrapper.json',summary);print(json.dumps(summary,sort_keys=True))

def run_packing():
    root,base,manifest,prepared=execution_environment();out=base/'packaging';out.mkdir()
    test=root/'tests/hia_native/test_batch_call_build.py'
    command=[sys.executable,'-I','-B',str(test),'--source',str(root),
             '--manifest',str(manifest),'--output',str(out/'capture')]
    row=process(root,out,'packing',command,plain_stream_names=True)
    verify_sources(root,object_at(base/'SOURCE-FILES.json'))
    write_new(out/'RESULT.json',{'status':'PASS','process':row,'source_unchanged':True,
              'new_batch_semantic_cases':0,'new_original_rust_processes':0})
    reader=reader_at(root);files=reader.Files([(root,root),(base,base)])
    helper=reader.load_private(files,root/PRIVATE_READER)
    admitted=helper.packer_evidence(files,root,manifest,out,python_executable=sys.executable,test_source=test)
    write_new(out/'admission.json',admitted)
    summary={'schema':'hepta.runtime.batch-call-main-packing.v1','status':'PASS','test_groups':2,
             'native_packer_calls':14,'source_contract_refusals':6,'admission':pin(out/'admission.json'),
             'execution_source_root':str(root),'execution_output_root':str(base),
             'new_batch_semantic_cases':0,'new_original_rust_processes':0,
             'errors':0,'failures':0,'skipped':0}
    write_new(base/'packing-wrapper.json',summary);print(json.dumps(summary,sort_keys=True))

def run_async():
    root,base,manifest,prepared=execution_environment()
    test=root/ASYNC_DRIVER;out=base/'async-controls';producer=base/'async-process'
    command=[sys.executable,'-I','-B',str(test),'--source',str(root),
             '--native-run',str(base),'--output',str(out)]
    process(test.parent,producer,'async-controls',command,plain_stream_names=True)
    verify_sources(root,object_at(base/'SOURCE-FILES.json'))
    reader=reader_at(root);files=reader.Files([(root,root),(base,base)])
    admitted=reader.async_evidence.control_evidence(files,out,producer,test,base,root,manifest)
    admitted['artifact_sha256']={path:value['sha256'] for path,value in sorted(files.artifacts.items())}
    write_new(base/'async-admission.json',admitted)
    summary={'schema':'hepta.runtime.batch-call-main-async.v1','status':'PASS','test_groups':1,
             'controls':2,'actual_elf_processes':2,'new_original_semantic_cases':0,
             'admission':pin(base/'async-admission.json'),'execution_source_root':str(root),
             'execution_output_root':str(base),'public_handler_replaced':False,
             'whole_runtime_replaced':False,'errors':0,'failures':0,'skipped':0}
    write_new(base/'async-wrapper.json',summary);print(json.dumps(summary,sort_keys=True))

def native_evidence(root,output,report,completed=None):
    root,output=Path(root),Path(output);manifest=module(output,report);base=output/FOLDER
    prepared=object_at(base/'prepared.json')
    old_root,old_base=Path(prepared['source_root']),Path(prepared['output_root'])
    need(old_root.is_absolute() and old_base.is_absolute(),'absolute native execution origins')
    exact(prepared['manifest'],str(old_base/'graph-v1/native/manifest.json'),'prepared registered manifest origin')
    exact(prepared['manifest_pin'],pin(manifest),'prepared complete registered manifest')
    exact(prepared['source_table_pin'],pin(base/'SOURCE-FILES.json'),'prepared complete source table')
    exact(prepared['build_process'],object_at(base/'build.process.json'),'actual retained build producer')
    raw=admit_native(root,base,prepared)
    exact(raw,object_at(base/'native-admission.json'),'retained complete native Batch admission')
    reader=reader_at(root);files=reader.Files([(old_root,root),(old_base,base)])
    helper=reader.load_private(files,old_root/PRIVATE_READER)
    packing=helper.packer_evidence(files,old_root,Path(prepared['manifest']),old_base/'packaging',
        python_executable=prepared['python'],test_source=old_root/'tests/hia_native/test_batch_call_build.py')
    exact(packing,object_at(base/'packaging/admission.json'),'retained complete actual packing admission')
    late_files=reader.Files([(old_root,root),(old_base,base)])
    late=reader.async_evidence.control_evidence(late_files,old_base/'async-controls',old_base/'async-process',
        old_root/ASYNC_DRIVER,old_base,old_root,Path(prepared['manifest']))
    late['artifact_sha256']={path:value['sha256'] for path,value in sorted(late_files.artifacts.items())}
    exact(late,object_at(base/'async-admission.json'),'complete actual late-worker lock admission')
    sources={};artifacts={};all_artifacts=dict(raw['artifact_sha256'])
    for name,digest in {**packing['artifact_sha256'],**late['artifact_sha256']}.items():
        if name in all_artifacts:exact(all_artifacts[name],digest,'Batch evidence changed between readers')
        all_artifacts[name]=digest
    for name,digest in all_artifacts.items():
        path=Path(name)
        if path.is_relative_to(old_base):artifacts[FOLDER+'/'+str(path.relative_to(old_base))]=digest
        elif path.is_relative_to(old_root):sources[str(path.relative_to(old_root))]=digest
        else:raise ValueError('unmapped admitted Batch origin')
    for test,summary_file in ((NATIVE_TEST,'native-wrapper.json'),(PACKING_TEST,'packing-wrapper.json'),
                              (ASYNC_TEST,'async-wrapper.json')):
        summary=object_at(base/summary_file)
        expected=[prepared['python'],'-I','-B',str(old_root/'tests/hia_native'/test)]
        rows=[row for row in report['checks'] if row['name']==test]
        need(len(rows)==1,'one actual registered Batch wrapper');row=rows[0]
        exact(row['command'],expected,'registered Batch wrapper argv')
        elapsed=row['elapsed_seconds']
        need(type(row['exit_code']) is int and row['exit_code']==0 and row['timed_out'] is False
             and not row.get('start_error') and row['timeout_seconds']==180
             and type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<elapsed<=180,'actual Batch wrapper gate')
        for kind in ('stdout','stderr'):
            parent=inside(output,report.get('check_artifact_directories',{}).get(test,'.'))
            path=inside(parent,test+'.'+kind);value=path.read_bytes()
            exact({'bytes':len(value),'sha256':sha(value)},
                  {'bytes':row[kind+'_bytes'],'sha256':row[kind+'_sha256']},'complete main wrapper stream')
            exact(json.loads(value) if kind=='stdout' else value.decode(),summary if kind=='stdout' else '',
                  'actual main wrapper result')
            artifacts[str(path.relative_to(output))]=sha(value)
        exact(row.get('summary'),summary,'retained main Batch wrapper summary')
        if completed is not None:exact(list(completed(output,report,test)),[row,summary],'main completed callback')
        artifacts[FOLDER+'/'+summary_file]=pin(base/summary_file)['sha256']
    for name in ('prepared.json','build.process.json','native-admission.json','SOURCE-FILES.json',
                 'packaging/admission.json','async-admission.json'):
        artifacts[FOLDER+'/'+name]=pin(base/name)['sha256']
    for name in ('scripts/hia_native_batch_call_pipeline.py','tests/hia_native/'+NATIVE_TEST,
                 'tests/hia_native/'+PACKING_TEST,'tests/hia_native/'+ASYNC_TEST,ASYNC_DRIVER,
                 'scripts/hia_native_batch_call_fixtures.py','scripts/hia_native_runtime_mcp_fixtures.py',
                 'scripts/hia_native_runtime_mcp_evidence.py'):
        sources[name]=pin(root/name)['sha256']
    exact({name:report['source_sha256'].get(name) for name in sources},sources,'registered Batch source closure')
    return {'schema':'hepta.runtime.batch-call-pipeline-native.v1','status':'PASS','native':raw,'packing':packing,'async_controls':late,
            'source_sha256':dict(sorted(sources.items())),'artifact_sha256':dict(sorted(artifacts.items())),
            'execution_source_root':str(old_root),'execution_output_root':str(old_base.parent),
            'fresh_original_comparison_complete':False,'public_handler_replaced':False,'whole_runtime_replaced':False}

def fixture_retirement(root,output,report,completed=None,*,create=False,native=None):
    import hia_native_batch_call_fixtures as fixtures
    if native is None:native=native_evidence(root,output,report,completed)
    return fixtures.retirement(output,native,create=create)

def qualification_request(root,base,prepared):
    old_root,old_base=Path(prepared['source_root']),Path(prepared['output_root'])
    return {'reference':{'original_source':str(old_root/ORIGINAL_FOLDER),'original_output':str(old_base/'original'),
                        'native_source':str(old_root),'native_run':str(old_base),'build_source':str(old_root),
                        'manifest':prepared['manifest'],'outer_receipt':str(old_base/'original.process.json')},
            'private_reader':str(old_root/PRIVATE_READER),'packaging_run':str(old_base/'packaging'),
            'packaging_test':str(old_root/'tests/hia_native/test_batch_call_build.py'),
            'python_executable':prepared['python'],'async_run':str(old_base/'async-controls'),
            'async_process':str(old_base/'async-process'),'async_test':str(old_root/ASYNC_DRIVER),
            'reader_root':str(old_root/READER_FOLDER),'origins':[[str(old_root),str(root)],[str(old_base),str(base)]]}

def original_command(root,base,prepared,rustc,strace):
    source=Path(root)/ORIGINAL_FOLDER;rustc=Path(rustc).absolute()
    return [prepared['python'],'-I','-B',str(source/'run.py'),'--source',str(source),
            '--native-source',str(root),'--native-run',str(base),'--build-source',str(root),
            '--native-manifest',prepared['manifest'],'--output',str(base/'original'),
            '--cargo',str(rustc.parent/'cargo'),'--rustc',str(rustc),'--strace',str(strace)]

def retained_original(root,output,report,completed=None):
    import hia_native_batch_call_fixtures as fixtures
    root,output=Path(root),Path(output);base=output/FOLDER
    native=native_evidence(root,output,report,completed)
    exact(native,report['batch_call_evidence'],'sealed native Batch evidence before/after original')
    retired=fixtures.retirement(output,native)
    exact(retired,report['batch_call_fixture_retirement'],'sealed native Batch fixture archive')
    prepared=object_at(base/'prepared.json');request=qualification_request(root,base,prepared)
    saved=object_at(base/'QUALIFICATION-ARGS.json')
    exact({k:v for k,v in request.items()if k!='origins'},
          {k:v for k,v in saved.items()if k!='origins'},'actual original qualification origins')
    reader_at(root);final=importlib.import_module('final_evidence')
    old_root,old_base=Path(prepared['source_root']),Path(prepared['output_root'])
    value=final.evidence(qualification_request=request,controls_run=old_base/'evidence-controls',
          controls_process=old_base/'evidence-process',controls_test=old_root/CONTROLS_DRIVER,
          reader_source=old_root/READER_FOLDER/'final_evidence.py')
    exact(value,object_at(base/'final-evidence.json'),'whole qualified native/original/control evidence')
    recon=fixtures.reconstruction_evidence(output,native,retired)
    toolchain=object_at(base/'original/TOOLCHAIN.json')
    rust=report['rust_compiler']
    exact([toolchain['rustc']['invocation'],toolchain['rustc']['sha256']],
          [rust['invocation_path'],rust['invocation_executable_sha256']],'same explicitly selected original Rust toolchain')
    sources={};artifacts={**retired['artifact_sha256'],**recon['artifact_sha256']}
    for name,digest in value['artifact_sha256'].items():
        path=Path(name)
        if path.is_relative_to(old_base):artifacts[FOLDER+'/'+str(path.relative_to(old_base))]=digest
        elif path.is_relative_to(old_root):sources[str(path.relative_to(old_root))]=digest
        else:raise ValueError('unmapped qualified Batch artifact')
    for name in ('final-evidence.json','qualified-evidence.json','QUALIFICATION-ARGS.json','original.process.json'):
        artifacts[FOLDER+'/'+name]=pin(base/name)['sha256']
    for name in ('scripts/hia_native_batch_call_pipeline.py','scripts/hia_native_batch_call_fixtures.py',CONTROLS_DRIVER):
        sources[name]=pin(root/name)['sha256']
    exact({name:report['source_sha256'].get(name) for name in sources},sources,'complete original Batch source closure')
    return {'schema':'hepta.runtime.batch-call-pipeline-original.v1','status':'PASS',
            'native_original':value,'fixture_retirement':recon,'source_sha256':dict(sorted(sources.items())),
            'artifact_sha256':dict(sorted(artifacts.items())),'fresh_original_comparison_complete':True,
            'original_inner_execute_batch_edit_executed':True,'original_outer_batch_method_executed':False,
            'original_sdk_executed':False,'public_handler_replaced':False,'whole_runtime_replaced':False}

def execute_original(root,output,report,rustc,*,record_check=None,completed=None,qualification_env=None):
    import hia_native_batch_call_fixtures as fixtures
    root,output=Path(root).resolve(),Path(output).resolve();base=output/FOLDER
    native=native_evidence(root,output,report,completed)
    exact(native,report['batch_call_evidence'],'complete native-first Batch admission')
    retired=fixtures.retirement(output,native)
    exact(retired,report['batch_call_fixture_retirement'],'complete native archive before original execution')
    prepared=object_at(base/'prepared.json')
    exact([str(root),str(base)],[prepared['source_root'],prepared['output_root']],
          'normal original replay requires actual source and fixture origins')
    need(not (base/'original').exists(),'original Batch replay already attempted')
    strace=shutil.which('strace');need(strace is not None,'actual original syscall observer unavailable')
    rustc=Path(rustc).absolute();need(rustc.is_file() and (rustc.parent/'cargo').is_file(),'selected fixed original toolchain')
    with fixtures.original_fixture(output,native,retired):
        command=original_command(root,base,prepared,rustc,Path(strace).resolve())
        process(root,base,'original',command,record_name=False)
        verify_sources(root,object_at(base/'SOURCE-FILES.json'))
        request=qualification_request(root,base,prepared)
        write_new(base/'QUALIFICATION-ARGS.json',request)
        reader=reader_at(root);qualified=reader.evidence(**request)
        write_new(base/'qualified-evidence.json',qualified)
        test=root/CONTROLS_DRIVER;controls=base/'evidence-controls'
        command=[prepared['python'],'-I','-B',str(test),'--reader-source',str(root/READER_FOLDER),
                 '--request',str(base/'QUALIFICATION-ARGS.json'),'--expected',str(base/'qualified-evidence.json'),
                 '--output',str(controls)]
        process(test.parent,base/'evidence-process','evidence-controls',command,plain_stream_names=True)
        final=importlib.import_module('final_evidence')
        value=final.evidence(qualification_request=request,controls_run=controls,controls_process=base/'evidence-process',
              controls_test=test,reader_source=root/READER_FOLDER/'final_evidence.py')
        write_new(base/'final-evidence.json',value)
        verify_sources(root,object_at(base/'SOURCE-FILES.json'))
    return retained_original(root,output,report,completed)
