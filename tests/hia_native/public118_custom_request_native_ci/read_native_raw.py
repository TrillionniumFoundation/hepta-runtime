"""Full real-stdio differential and the original physical controls, strictly read-only."""
from pathlib import Path
import json
import archive_stream,read_stdio,restore_native_raw
from receipt_support import PIN,regular
CONFIG=restore_native_raw.CONFIG
def need(ok,text):
    if not ok:raise ValueError(text)
def prior_controls(prior):
    prior=Path(prior);report=json.loads((prior/'reader-controls/REPORT.json').read_bytes())
    need(report['status']=='RAW_STDIO_READER_PHYSICAL_CONTROLS_PASS' and report['refusals']==4 and report['guard_probes']==44 and report['native_or_rust_executions']==0,'all original physical controls')
    for row in report['cases']:
        case=prior/'reader-controls'/row['name'];need(json.loads((case/'CONTROL.json').read_bytes())==row and archive_stream.pin(case/'GUARD.json')==row['guard'],'original complete physical case')
        guard=json.loads((case/'GUARD.json').read_bytes());need(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']==row['refusal'],'original actual guard')
        clone=case/'capture';need(archive_stream.pin(clone/row['changed_path'])==row['changed_bytes'],'original physical changed bytes')
        try:read_stdio.read(clone,prior/'source',CONFIG['prior_profile'])
        except (ValueError,AssertionError,OSError) as error:actual={'rejected':True,'type':type(error).__name__,'message':str(error)}
        else:raise ValueError('original physical mutation was accepted')
        need(actual==row['refusal'],'same complete original physical refusal')
    return report
def read(root,source,profile):
    root,source=Path(root),Path(source);rows=read_stdio.source_check(source,profile)
    need((root/'source/PACKAGE.json').read_bytes()==(source/'PACKAGE.json').read_bytes(),'whole new native source snapshot')
    for name in rows:need((root/'source'/name).read_bytes()==(source/name).read_bytes(),'whole recorded native source '+name)
    run=json.loads((root/'RUN.json').read_bytes());domain=run['domain'];need(run['original_semantics_replayed'] is False and run['native_build_replayed'] is False and run['source_profile']==profile,'native-only actual domain')
    custody=restore_native_raw.verify(root/'retained',domain);prior=root/'retained/prior'
    original=read_stdio.read(prior,prior/'source',CONFIG['prior_profile']);need(original==json.loads((prior/'READONLY.json').read_bytes())['evidence'],'complete same original read')
    controls=prior_controls(prior);binary={k:CONFIG['binary'][k] for k in ('bytes','sha256')}
    native=read_stdio.read_capture(root/'native',side='native',binary=binary)
    need(original['domain']==native['domain']==domain and original['actual_processes']==native['actual_processes'],'same complete raw input processes')
    for index,(left,right) in enumerate(zip(original['pairs'],native['pairs'],strict=True)):
        need(set(left)==set(right),'complete actual comparison fields')
        for key in left:need(left[key]==right[key],'actual raw scenario '+str(index)+' '+left['name']+' differs in '+key)
    need(original['pairs']==native['pairs'],'complete actual raw stdio comparison')
    return {'status':'COMPLETE_NATIVE_ORIGINAL_RAW_STDIO_DIFFERENTIAL_PASS','domain':domain,'actual_process_pairs':native['actual_processes'],'complete_stdout_lines_per_side':native['all_stdout_lines'],'original_semantics_replayed':False,'native_or_rust_executions':0,'prior_physical_refusals':controls['refusals'],'custody':custody,'full_async_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
