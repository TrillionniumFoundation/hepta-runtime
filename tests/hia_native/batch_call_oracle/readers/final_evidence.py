"""Final offline admission of complete Batch captures and real refusal controls."""
from pathlib import Path
import math,stat
from capture_format import Files,actual_process,canonical,fields,need,same,sha,strict_json,uint
import qualification

CONTROL_SOURCE={'bytes': 20796, 'sha256': '8bfd00267f2f580a86527f96161806e2a82462c9cee88806491322523f5cb19f'}
CONTROL_ORDER=[["typed-json","duplicate-member","ValueError"],["typed-json","nan-token","ValueError"],["typed-json","infinity-token","ValueError"],["typed-json","overflow-float","ValueError"],["typed-json","surrogate-string","UnicodeEncodeError"],["typed-json","boolean-integer","ValueError"],["actual-process","missing-start-error","ValueError"],["actual-process","missing-timeout-result","ValueError"],["actual-process","boolean-pid","ValueError"],["actual-process","changed-deadline","ValueError"],["actual-process","changed-cwd","ValueError"],["actual-process","changed-command","ValueError"],["actual-process","zero-interval","ValueError"],["actual-process","resigned-over-deadline","ValueError"],["origin-source","symlink-root","ValueError"],["origin-source","parent-traversal","ValueError"],["origin-source","unmapped-live-fallback","ValueError"],["origin-source","missing-retained-stream","FileNotFoundError"],["origin-source","changed-whole-module","ValueError"],["origin-source","omitted-whole-module","ValueError"],["complete-record","inflated-original-sdk","ValueError"],["complete-record","different-original-case","ValueError"],["complete-record","resigned-typed-body","ValueError"],["complete-record","resigned-final-body","ValueError"],["complete-record","history-byte-accounting","ValueError"],["complete-record","resigned-cache-value","ValueError"],["complete-record","hardlink-inode-relationship","ValueError"],["complete-record","context-boolean-type","ValueError"],["trace-lifecycle","trace-truncated-final-line","ValueError"],["trace-lifecycle","trace-unknown-line","ValueError"],["trace-lifecycle","trace-missing-marker","ValueError"],["trace-lifecycle","trace-duplicate-marker","ValueError"],["trace-lifecycle","trace-unfinished-tail","ValueError"],["trace-lifecycle","trace-unpaired-close","ValueError"],["trace-lifecycle","trace-unclosed-descriptor","ValueError"],["trace-lifecycle","cancel-drop-order","ValueError"],["native-wire-buffers","unindexed-private-tail","ValueError"],["native-wire-buffers","resigned-refused-output","ValueError"],["native-wire-buffers","resigned-refused-workspace","ValueError"],["native-wire-buffers","resigned-refusal-code","ValueError"],["native-wire-buffers","child-ack-sequence","ValueError"],["native-wire-buffers","resigned-held-after-cancel","ValueError"]]
GROUPS={'typed-json':6,'actual-process':8,'origin-source':6,'complete-record':8,'trace-lifecycle':8,'native-wire-buffers':6}

def controls_evidence(files,run,process_run,test_source,qualified,reader_root,request):
    run,process_run,test_source,reader_root=map(Path,(run,process_run,test_source,reader_root))
    artifacts={}
    def raw(path):
        path=str(path);value=files.raw(path);artifacts[path]=sha(value);return value
    def js(path):return strict_json(raw(path))
    def pin(path):
        value=raw(path);return {'bytes':len(value),'sha256':sha(value)}
    same(pin(test_source),CONTROL_SOURCE,'actual bound 42-refusal test source')
    result=js(run/'RESULT.json')
    fields(result,('schema','status','test_groups','controls','group_counts','baseline','new_native_calls',
                  'new_rust_processes','physical_files','results','reader_sources','test_source','elapsed_seconds'),
           'complete physical refusal summary')
    same(result['schema'],'hepta.runtime.batch-call-evidence-controls.v1','refusal schema')
    for name,value in [('status','PASS'),('test_groups',6),('controls',42),('new_native_calls',0),('new_rust_processes',0)]:
        same(result[name],value,'complete refusal result '+name)
    same(result['test_source'],CONTROL_SOURCE,'executed physical refusal source')
    same(result['group_counts'],GROUPS,'meaningful exact refusal groups')
    baseline=raw(run/'BASELINE.json')
    same(baseline,canonical(qualified),'full qualified native/original predecessor of actual refusal tests')
    same(result['baseline'],{'bytes':len(baseline),'sha256':sha(baseline)},'whole baseline evidence identity')
    source=js(run/'SOURCE.json');same(source,result['reader_sources'],'actual test reader source snapshot')
    for name,value in source.items():
        need(type(name)is str and Path(name).name==name,'test reader source basename')
        same(pin(run/'source'/name),value,'actual test reader preserved source '+name)
        same(pin(reader_root/name),value,'actual test and admitted reader source equal '+name)
    for name,pin_value in qualified['reader_sources'].items():same(source[name],pin_value,'all source-owned qualified readers tested')
    results=js(run/'CONTROLS.json');same(results,result['results'],'complete actual negative results')
    same([[r['group'],r['name'],r['type']]for r in results],CONTROL_ORDER,'exact meaningful controls and exception types')
    for row in results:
        fields(row,('group','name','rejected','type','error','elapsed_seconds'),'complete actual rejection observation')
        need(row['rejected']is True and type(row['error'])is str and row['error'],'missing actual rejection')
        elapsed=row['elapsed_seconds'];need(type(elapsed)in(int,float)and math.isfinite(elapsed)and 0<=elapsed<180,
                                            'actual control elapsed')
    physical=result['physical_files']
    need(type(physical)is dict and physical,'complete actual mutation file set')
    # Content-addressed async blobs can coincide in one real execution and
    # differ in another. Bind the exact source-derived closure, not a previous
    # invocation's number of distinct blobs.
    expected_physical={str(run/'retired-symlinks.json')}
    mutation=run/'mutations'
    for group,label,_ in CONTROL_ORDER:
        if group=='typed-json':
            expected_physical.add(str(mutation/label/('value.json'if label=='boolean-integer'else'raw.bin')))
        elif group=='actual-process' or label=='omitted-whole-module':
            expected_physical.add(str(mutation/label/'value.json'))
        elif group=='complete-record':
            expected_physical.add(str(mutation/label/'raw.bin'))
        elif group=='trace-lifecycle':
            expected_physical.add(str(mutation/label/('raw.bin'if label=='cancel-drop-order'else'raw.bin.gz')))
        elif label in ('unindexed-private-tail','resigned-refused-output','resigned-refused-workspace','resigned-refusal-code'):
            expected_physical.update(str(mutation/label/'state-controls'/name)
                                     for name in ('RESULT.json','complete.bin.gz','index.jsonl'))
        elif label=='child-ack-sequence':expected_physical.add(str(mutation/label/'raw.bin.gz'))
    expected_physical.update(str(mutation/'changed-whole-module/source'/name)
                             for name in qualification.strict_reference.SOURCE_PINS)
    copied=mutation/'resigned-held-after-cancel'
    for recorded in qualified['artifact_sha256']:
        path=Path(recorded)
        for key,destination in [('async_run','run'),('async_process','process')]:
            origin=Path(request[key])
            if path.is_relative_to(origin):expected_physical.add(str(copied/destination/path.relative_to(origin)))
    forged=js(copied/'run/CONTROLS.json')[0]['lock_after_cancel']['response']
    body_path=Path(forged['artifact'])
    need(not body_path.is_absolute()and'..'not in body_path.parts,'forged control blob path escaped its owner')
    expected_physical.add(str(copied/'run'/body_path))
    same(sorted(physical),sorted(expected_physical),'complete source-derived physical mutation file closure')
    for name,expected in physical.items():
        path=Path(name)
        need(path.is_relative_to(run/'mutations')or path==run/'retired-symlinks.json','physical mutation outside owned root')
        same(pin(path),expected,'complete physical/re-signed mutation bytes')
    retired=js(run/'retired-symlinks.json')
    need(len(retired)==1,'actual symlink negative cleanup count')
    row=retired[0];fields(row,('path','target','dev','ino','mode','absent_after'),'actual symlink refusal retirement')
    same(row['path'],str(run/'mutations/symlink-root/source-link'),'owned rejected symlink')
    same(row['target'],str(reader_root),'actual symlink source target')
    need(stat.S_ISLNK(row['mode'])and row['absent_after']is True and uint(row['ino'],'retired symlink inode')>0,
         'actual symlink negative was not retired')
    process=js(process_run/'PROCESS.json')
    fields(process,('command','cwd','pid','started_monotonic_ns','finished_monotonic_ns','elapsed_seconds',
                    'timeout_seconds','timed_out','start_error','exit_code','stdout','stderr'),'actual physical suite process fields')
    python=process['command'][0]
    arguments=[str(test_source),'--reader-source',str(reader_root),
               '--request',str(run.parent/'QUALIFICATION-ARGS.json'),
               '--expected',str(run.parent/'qualified-evidence.json'),'--output',str(run)]
    actual_process(process,[python,'-I','-B',*arguments],test_source.parent)
    stdout=raw(process_run/'stdout');stderr=raw(process_run/'stderr')
    same(process['stdout'],{'bytes':len(stdout),'sha256':sha(stdout)},'complete refusal process stdout')
    same(process['stderr'],{'bytes':len(stderr),'sha256':sha(stderr)},'complete refusal process stderr')
    same(stderr,b'','actual refusal process stderr')
    same(strict_json(stdout),{'status':'PASS','controls':42,'elapsed_seconds':result['elapsed_seconds'],
                              'result':pin(run/'RESULT.json')},'actual refusal process full terminal stdout')
    remote=js(run/'remote-process.json')
    fields(remote,('pid','argv','cwd','cgroup','started_monotonic_ns'),'actual rejection producer identity')
    same(remote['pid'],process['pid'],'actual refusal producer PID')
    same(remote['argv'],arguments,'actual refusal interpreter argv')
    same(remote['cwd'],process['cwd'],'actual refusal process cwd')
    need(type(remote['cgroup'])is str and remote['cgroup'].endswith('\n'),'actual refusal cgroup text')
    need(process['started_monotonic_ns']<remote['started_monotonic_ns']<process['finished_monotonic_ns'],
         'actual refusal producer clock')
    need(type(result['elapsed_seconds'])in(int,float)and math.isfinite(result['elapsed_seconds'])and
         0<result['elapsed_seconds']<process['elapsed_seconds'],'actual refusal suite duration')
    return {'schema':'hepta.runtime.batch-call-evidence-refusals.v1','status':'PASS','test_groups':6,'controls':42,
            'group_counts':GROUPS,'actual_python_processes':1,'new_native_calls':0,'new_rust_processes':0,
            'physical_mutation_files':len(physical),'source':CONTROL_SOURCE,'results':results,
            'artifact_sha256':dict(sorted(artifacts.items()))}

def evidence(*,qualification_request,controls_run,controls_process,controls_test,reader_source):
    qualified=qualification.evidence(**qualification_request)
    files=Files(qualification_request['origins'])
    recorded_request=files.json(str(Path(controls_run).parent/'QUALIFICATION-ARGS.json'))
    same({key:value for key,value in recorded_request.items()if key!='origins'},
         {key:value for key,value in qualification_request.items()if key!='origins'},
         'exact source-owned request executed by physical refusal suite')
    same(files.raw(str(Path(controls_run).parent/'qualified-evidence.json')),canonical(qualified),
         'complete separately retained original/native qualification before controls')
    controls=controls_evidence(files,controls_run,controls_process,controls_test,qualified,
                               qualification_request['reader_root'],qualification_request)
    reader=files.raw(str(reader_source));artifacts=dict(qualified['artifact_sha256'])
    for path,value in files.artifacts.items():
        if path in artifacts:same(artifacts[path],value['sha256'],'artifact changed during final admission')
        artifacts[path]=value['sha256']
    return {'schema':'hepta.runtime.batch-call-final-evidence.v1','status':'PASS',
            'qualification':qualified,'evidence_controls':controls,
            'complete_native_original_comparison':True,'original_cases':215,'subordinate_followups':2,
            'separate_linux_controls':2,'new_native_calls':0,'new_rust_processes':0,
            'public_handler_replaced':False,'whole_runtime_replaced':False,
            'final_reader':{'bytes':len(reader),'sha256':sha(reader)},
            'artifact_sha256':dict(sorted(artifacts.items()))}
