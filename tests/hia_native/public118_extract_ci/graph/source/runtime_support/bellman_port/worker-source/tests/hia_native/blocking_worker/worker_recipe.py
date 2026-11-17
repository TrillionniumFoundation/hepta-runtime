"""Fresh private worker qualification, or a strictly readonly complete replay."""
from __future__ import annotations
import argparse,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_common import BASE,SOURCE_PINS,read,put,document,encoded,sha,require,source_evidence,tree_files,process_evidence
from worker_build_evidence import verify_build
from worker_buffer_evidence import DOMAINS,verify_buffers
from worker_group_evidence import GROUPS,verify_group
from worker_export_evidence import verify_export_controls
from worker_reference_evidence import pair_reference,original_evidence

CI_BASE='tests/hia_native/blocking_worker_ci'
REPORTS={'ARTIFACTS.json','QUALIFICATION.json'}

def commands(context):
    root=Path(context['source_root']);capture=Path(context['capture']);python=context['python']
    build=capture/'native-build';native=capture/'native';bridge=build/'bridge'
    result={'build':[python,'-B',str(root/BASE/'worker_build.py'),'--source-root',str(root),'--hepta',context['hepta'],'--capture',str(build),'--source-pins-sha256',context['source_pins_sha256']]}
    if context['bootstrap_cache']:result['build']+=['--bootstrap-cache',context['bootstrap_cache']]
    for name,(driver,_,_,_) in DOMAINS.items():
        result[name]=[python,'-B',str(root/BASE/driver),'--source-root',str(root),'--build',str(build/'build'),'--output',str(native/name)]
        if name=='timed-commitment':result[name]+=['--trace',str(capture/'retained-trace'),'--all-timeouts']
    for group in GROUPS:
        result['worker-'+group]=[python,'-B',str(root/BASE/'diagnose_worker.py'),'--bridge',str(bridge),'--output',str(native/'groups'/group),'--group',group]
    result['controls']=[python,'-B',str(root/BASE/'diagnose_worker_exports.py'),'--bridge',str(bridge),'--output',str(native/'export/capture')]
    result['original']=[python,'-B',str(root/CI_BASE/'capture_worker_reference.py'),'--source-root',str(root),'--output',str(capture/'original')]
    return result

def native_evidence(capture,root,pins):
    source_evidence(root,pins);context=document(capture/'recipe.json');origin=Path(context['capture'])
    require(context['schema']=='hepta.runtime.bellman-worker-recipe.v1' and context['source_pins_sha256']==pins,'recipe source identity changed')
    require(type(context['pid']) is int and context['pid']>0,'recipe process missing');plan=commands(context)
    expected_labels={'build',*DOMAINS,*('worker-'+g for g in GROUPS),'original'}
    actual_labels={p.stem for p in (capture/'processes').glob('*.json')}
    require(actual_labels in (expected_labels,expected_labels-{'original'}),'unexpected qualification process')
    build_receipt=process_evidence(capture,'build',plan['build'],300)
    require(build_receipt['parent_pid']==context['pid'] and build_receipt['cwd']==str(origin),'build parent custody changed')
    build=verify_build(capture/'native-build',root,pins)
    build_record=document(capture/'native-build/native-build.json')
    require(build_record['pid']==build_receipt['pid'],'compiler builder process changed')
    require(json.loads(read(capture/'processes/build.stdout'))=={k:v for k,v in build_record.items() if k!='compiler_source_identity'},'actual build stdout differs')
    require(read(capture/'processes/build.stderr')==b'','unexpected build stderr')
    for name,body in {'writer.inputs.jsonl':read(root/CI_BASE/'writer-cases.jsonl'),
                      'processes/writer-trace.stdout':read(root/CI_BASE/'retained-writer-trace.stdout')}.items():
        require(read(capture/'retained-trace'/name)==body,'retained actual Serde trace changed')
    native=capture/'native';buffers={};groups={}
    for name in DOMAINS:
        receipt=process_evidence(capture,name,plan[name],60);require(receipt['parent_pid']==context['pid'] and receipt['cwd']==str(origin),'native domain parent changed')
        report=document(native/name/'report.json');printed=json.loads(read(capture/'processes'/(name+'.stdout')))
        expected=report if name=='timed-core-controls' else {k:v for k,v in report.items() if k not in ('rows','results')}
        require(printed==expected,'actual buffer driver stdout changed')
        require(read(capture/'processes'/(name+'.stderr'))==b'','unexpected native domain stderr')
        buffers[name]=verify_buffers(native/name,root,capture/'native-build/build',name,trace=capture/'retained-trace')
    component=document(capture/'native-build/bridge/component.json')
    for group in GROUPS:
        label='worker-'+group;receipt=process_evidence(capture,label,plan[label],60)
        require(receipt['parent_pid']==context['pid'] and receipt['cwd']==str(origin),'worker fixture parent changed')
        inner=document(native/'groups'/group/'process.json')
        require(inner['parent_pid']==receipt['pid'] and inner['argv']==[str(origin/'native-build/bridge/bellman-worker.elf')] and inner['cwd']==str(origin/'native/groups'/group),'actual worker launch differs')
        groups[group]=verify_group(native/'groups'/group,root,component,group)
        require(json.loads(read(capture/'processes'/(label+'.stdout')))==document(native/'groups'/group/'report.json'),'actual worker driver stdout changed')
        require(read(capture/'processes'/(label+'.stderr'))==b'','unexpected worker driver stderr')
    export=process_evidence(native/'export','controls',plan['controls'],60)
    require(export['parent_pid']==context['pid'] and export['cwd']==str(origin/'native/export'),'actual export parent changed')
    controls=verify_export_controls(native/'export',component)
    return {'status':'NATIVE_READ_ONLY_PASS','source_pins_sha256':pins,'build':build,'buffers':buffers,'groups':groups,'exports':controls,
            'actual_jobs':sum(v['jobs'] for v in groups.values()),'actual_clock_calls':sum(v['clock_calls'] for v in groups.values()),
            'actual_stream_bytes':sum(v['complete_stream_bytes'] for v in groups.values()),'public_handler_qualified':False}

def conclusion(capture,pins,native):
    return {'schema':'hepta.runtime.bellman-worker-qualification.v1','status':'COMPLETE_PRIVATE_WORKER_PASS','source_pins_sha256':pins,
            'artifact_manifest_sha256':sha(read(capture/'ARTIFACTS.json')),'actual_jobs':native['actual_jobs'],'actual_clock_calls':native['actual_clock_calls'],
            'graph_cases':363,'graph_successes':338,'graph_refusals':25,'actual_original_processes':12,'duration_cases':1292,'writer_boundaries':452,
            'export_calls':161,'export_atomic_refusals':26,'numerical_clock_control_calls':265,'numerical_atomic_refusals':157,
            'runtime_implementation_images':5,'actual_packer_images':1,'fresh_compilation':True,
            'matching_source_cold_qualified':False,'serialized_host_exports_qualified':True,'concurrent_host_entry_qualified':False,
            'public_handler_qualified':False,'whole_runtime_replaced':False}

def verify(capture,root,pins):
    source_evidence(root,pins);actual=tree_files(capture);seal=document(capture/'ARTIFACTS.json')
    require({k:v for k,v in actual.items() if k not in REPORTS}==seal['files'],'complete artifact file set/bytes changed')
    require(seal['schema']=='hepta.runtime.bellman-worker-artifacts.v1' and seal['source_pins_sha256']==pins,'artifact source binding changed')
    require(tree_files(capture/'source')==tree_files(root),'relocated admitted source copy differs')
    native=native_evidence(capture,root,pins);require(read(capture/'native-evidence.json')==encoded(native),'native evidence report changed')
    context=document(capture/'recipe.json');receipt=process_evidence(capture,'original',commands(context)['original'],480)
    require(receipt['parent_pid']==context['pid'] and receipt['cwd']==context['capture'],'fresh original parent changed')
    require(document(capture/'original/processes/rustc-version.json')['parent_pid']==receipt['pid'],'fresh original subprocess parent changed')
    require(json.loads(read(capture/'processes/original.stdout'))==document(capture/'original/RESULT.json'),'actual original supervisor stdout differs')
    require(read(capture/'processes/original.stderr')==b'','unexpected original supervisor stderr')
    original,_=original_evidence(capture/'original',root)
    require(read(capture/'original/processes/writer-trace.stdout')==read(capture/'retained-trace/processes/writer-trace.stdout'),'new original Write boundaries differ')
    require(read(capture/'original/writer-trace.inputs')==read(capture/'retained-trace/writer.inputs.jsonl'),'new original Write inputs differ')
    comparison=pair_reference(capture/'native',capture/'original',root,{g:capture/'native/groups'/g for g in GROUPS})
    require(read(capture/'original-evidence.json')==encoded(original) and read(capture/'comparison.json')==encoded(comparison),'full original/paired report changed')
    expected=conclusion(capture,pins,native);require(read(capture/'QUALIFICATION.json')==encoded(expected),'qualification conclusion changed')
    return expected

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','capture']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-pins-sha256',required=True);p.add_argument('--hepta',type=Path);p.add_argument('--bootstrap-cache',type=Path)
    p.add_argument('--phase',choices=['all','verify'],required=True);a=p.parse_args()
    root=a.source_root.resolve();capture=a.capture.resolve();pins=a.source_pins_sha256
    if a.phase=='verify':print(json.dumps(verify(capture,root,pins),sort_keys=True));return
    source_evidence(root,pins);require(a.hepta is not None,'compiler checkout required');capture.mkdir(mode=0o700)
    for name in [*document(root/SOURCE_PINS)['files'],SOURCE_PINS]:put(capture/'source'/name,read(root/name))
    context={'schema':'hepta.runtime.bellman-worker-recipe.v1','pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgid(0),
             'source_root':str(root),'capture':str(capture),'hepta':str(a.hepta.resolve()),'python':sys.executable,
             'bootstrap_cache':str(a.bootstrap_cache.resolve()) if a.bootstrap_cache else None,'source_pins_sha256':pins}
    put(capture/'recipe.json',context)
    sys.path.insert(0,str(root/CI_BASE));from capture_writer_trace import run
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0');plan=commands(context)
    run(capture,'build',plan['build'],env,limit=300)
    put(capture/'retained-trace/writer.inputs.jsonl',read(root/CI_BASE/'writer-cases.jsonl'))
    put(capture/'retained-trace/processes/writer-trace.stdout',read(root/CI_BASE/'retained-writer-trace.stdout'))
    (capture/'native/groups').mkdir(parents=True);(capture/'native/export').mkdir()
    for name in DOMAINS:run(capture,name,plan[name],env,limit=60)
    for group in GROUPS:run(capture,'worker-'+group,plan['worker-'+group],env,limit=60)
    run(capture/'native/export','controls',plan['controls'],env,limit=60)
    native=native_evidence(capture,root,pins);put(capture/'native-evidence.json',native)
    run(capture,'original',plan['original'],env,limit=480)
    original,_=original_evidence(capture/'original',root);put(capture/'original-evidence.json',original)
    # The original collector already retained and checked every registry
    # archive/source, generated module and executable. Its reproducible Cargo
    # cache is not part of the admitted evidence; preserve it outside the
    # archive, without deleting any captured original observation.
    cache=capture/'original-build-work';retired=capture.parent.parent/('bellman-worker-rust-build-'+capture.parent.name)
    require(cache.is_dir() and not retired.exists(),'owned original cache retirement collision')
    cache.rename(retired)
    comparison=pair_reference(capture/'native',capture/'original',root,{g:capture/'native/groups'/g for g in GROUPS});put(capture/'comparison.json',comparison)
    put(capture/'ARTIFACTS.json',{'schema':'hepta.runtime.bellman-worker-artifacts.v1','source_pins_sha256':pins,'files':tree_files(capture)})
    put(capture/'QUALIFICATION.json',conclusion(capture,pins,native));print(json.dumps(verify(capture,root,pins),sort_keys=True))

if __name__=='__main__':main()
