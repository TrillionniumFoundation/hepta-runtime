"""Read each complete raw public capture; preserve the existing failed differential verbatim."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,importlib,json,stat,sys,shutil
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
PROFILE='573600848749692ad1da7f54648999d18e4640c9473b419df69c27e19f451171'
EXPECTED_FAILURE='actual raw scenario 25 legacy-sdk-params-null differs in stdout'
def need(ok,text):
    if not ok:raise ValueError(text)
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def check_controls(capture,source,reader):
    root=capture/'reader-controls';report=json.loads((root/'REPORT.json').read_bytes())
    need(report['status']=='COMPLETE_RAW_DIFFERENTIAL_PHYSICAL_CONTROLS_PASS' and report['refusals']==4 and report['guard_probes']==44 and report['native_or_rust_executions']==0,'complete native physical controls')
    for row in report['cases']:
        case=root/row['name'];need(json.loads((case/'CONTROL.json').read_bytes())==row and archive_stream.pin(case/'GUARD.json')==row['guard'],'native physical control receipt')
        guard=json.loads((case/'GUARD.json').read_bytes());need(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']==row['refusal'],'native original physical guard')
        clone=case/'capture';need(archive_stream.pin(clone/row['changed_path'])==row['changed_file'],'complete actual native mutation')
        try:reader.read(clone,source,PROFILE)
        except (ValueError,AssertionError,OSError) as error:actual={'rejected':True,'type':type(error).__name__,'message':str(error)}
        else:raise ValueError('native physical mutation accepted')
        need(actual==row['refusal'],'same exact physical rejection')
    return report
def examine(capture,identity):
    source=capture/'source';sys.path.insert(0,str(source));sys.path.insert(1,str(source/'peer'));sys.path.insert(2,str(source/'capture'))
    reader=importlib.import_module('read_native_raw');stdio=importlib.import_module('read_stdio');restore=importlib.import_module('restore_native_raw')
    need(Path(reader.__file__).resolve()==source/'read_native_raw.py','actual captured reader module')
    run=json.loads((capture/'RUN.json').read_bytes());need(run['source']==identity['source'] and run['run']==str(identity['run']) and run['source_profile']==PROFILE and run['status']==identity['expected_status'],'retained actual run identity and terminal')
    try:qualification=reader.read(capture,source,PROFILE)
    except (ValueError,AssertionError,OSError) as error:
        failure={'type':type(error).__name__,'message':str(error)}
        need(identity['expected_status']=='FAIL' and failure=={'type':'ValueError','message':EXPECTED_FAILURE} and all(run['failure'][k]==v for k,v in failure.items()),'same unchanged actual failed gate')
        prior=capture/'retained/prior';original=stdio.read(prior,prior/'source',restore.CONFIG['prior_profile'])
        binary={k:restore.CONFIG['binary'][k] for k in ('bytes','sha256')};native=stdio.read_capture(capture/'native',side='native',binary=binary)
        need(original['actual_processes']==native['actual_processes']==48 and run['actual_native_processes']==48,'all 48 actual legacy protocol processes complete')
        differences=[]
        for i,(left,right) in enumerate(zip(original['pairs'],native['pairs'],strict=True)):
            need(set(left)==set(right),'complete paired field set')
            for key in left:
                if left[key]!=right[key]:
                    row={'index':i,'name':left['name'],'field':key,'original':left[key],'native':right[key]}
                    if key in ('stdout','stderr','attempted_stdin','accepted_stdin'):
                        row['original_utf8']=bytes.fromhex(left[key]).decode('utf-8',errors='backslashreplace')
                        row['native_utf8']=bytes.fromhex(right[key]).decode('utf-8',errors='backslashreplace')
                    differences.append(row)
        need(differences and differences[0]['index']==25 and differences[0]['field']=='stdout','same observed first difference')
        return {'status':'COMPLETE_FAILED_RAW_CAPTURE_READ_WITH_SAME_REFUSAL','semantic_gate_passed':False,'original_failure':failure,'actual_process_pairs':48,'all_field_differences':differences,'fresh_semantic_executions':0,'original_semantics_replayed':False}
    else:
        need(identity['expected_status']!='FAIL','failed gate cannot silently pass')
        old=json.loads((capture/'READONLY.json').read_bytes());need(old['before']==old['after'] and len(old['probes'])==11 and old['reader_writes']==old['native_or_rust_executions']==0 and old['evidence']==qualification,'same complete raw qualification')
        controls=check_controls(capture,source,reader);need(run['controls']==controls,'complete producer controls retained')
        return {'status':'COMPLETE_SUCCESSFUL_RAW_CAPTURE_INDEPENDENT_READ_PASS','semantic_gate_passed':True,'qualification':qualification,'native_physical_controls_rechecked':controls['refusals'],'original_physical_controls_rechecked':4,'fresh_semantic_executions':0,'original_semantics_replayed':False}
def main():
    p=argparse.ArgumentParser()
    for name in ('input','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--domain',required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==a.profile,'frozen pure reader profile');rows=json.loads(raw)['files']
    need({p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'complete reader source')
    for name,row in rows.items():need(archive_stream.pin(ROOT/name)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/name).stat().st_mode)==0o644,'reader source bytes and mode')
    identity=json.loads((ROOT/'ARCHIVES.json').read_bytes())[a.domain];meta=json.loads((a.input.parent/'artifact.json').read_bytes())
    need(meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'],'fixed complete raw artifact')
    out=a.output.resolve();out.mkdir(exist_ok=False);proof=out/'proof';proof.mkdir();shutil.copytree(ROOT,proof/'reader-source')
    capture=out/'capture';full=archive_stream.archive(a.input,identity,lambda name:True,output=capture);put(proof/'FULL_ARCHIVE_READ.json',full)
    source=capture/'source';sys.path[:0]=[str(source),str(source/'peer'),str(source/'capture')]
    for name in ('read_native_raw','read_stdio','restore_native_raw'):importlib.import_module(name)
    for name in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(name)
    need(gzip.decompress(gzip.compress(b'',mtime=0))==b'','preload codecs')
    guard=read_only_guard.guarded(lambda:examine(capture,identity),roots=[capture,ROOT],foreign_path='/proc/self/status');put(proof/'READONLY.json',guard)
    result={'producer':identity,'domain':a.domain,'full_archive_files':full['files'],'fresh_guard_probes':11,**guard['evidence'],'full_async_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
    put(proof/'RESULT.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
