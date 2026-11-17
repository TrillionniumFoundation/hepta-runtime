"""Reopen every byte of the same failed catalog capture; compare original recorded streams only."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,importlib,json,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
SOURCE_PROFILE='c3feb6dbe199c17470c1117cc93e05f7ec704268bed79548b34f956af23a1b53'
EXPECTED={'type':'ValueError','message':'rebuilt Batch evidence: actual public wire/state/filesystem difference at 0: actual-installed-catalog-0'}
def need(ok,text):
    if not ok:raise ValueError(text)
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def serial(value):
    if isinstance(value,bytes):return {'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),'hex':value.hex(),'utf8':value.decode('utf-8',errors='backslashreplace')}
    if isinstance(value,(list,tuple)):return [serial(v) for v in value]
    if isinstance(value,dict):return {k:serial(v) for k,v in value.items()}
    return value
def examine(capture,source,identity,domain):
    import read_gate,read_public,source_check,restore
    source_identity=source_check.check(source,SOURCE_PROFILE)
    run=json.loads((capture/'RUN.json').read_bytes())
    need(run['status']=='FAIL' and run['source_profile']==SOURCE_PROFILE and run['source_commit']==identity['source'] and run['run_id']==str(identity['run']) and run['domain']==domain,'exact failed producer identity')
    need({k:run['failure'][k] for k in EXPECTED}==EXPECTED,'exact preserved catalog failure')
    build=restore.verify_ready(capture/'retained',domain)
    admitted=read_gate.admit_original(capture,source,domain)
    need(admitted==json.loads((capture/'ORIGINAL_ADMISSION.json').read_bytes()),'unchanged complete original admission')
    binaries={role:{k:restore.BINARIES['native-private' if role=='native' else 'original'][k] for k in ('bytes','sha256')} for role in ('native','original')}
    try:read_public.compare(capture/'native',capture/'original',source,native_binary=binaries['native'],original_binary=binaries['original'])
    except (ValueError,AssertionError,OSError) as error:failure={'type':type(error).__name__,'message':str(error)}
    else:raise ValueError('recorded catalog failure unexpectedly passed')
    need(failure==EXPECTED,'strict original reader must reproduce the exact semantic failure')
    left=read_public.Capture(capture/'native',source,expected_binary=binaries['native'])
    right=read_public.Capture(capture/'original',source,expected_binary=binaries['original'])
    left_begin=list(left.begin());right_begin=list(right.begin())
    need(left_begin==right_begin,'full actual initialization bytes')
    native=list(left.records());original=list(right.records())
    complete_native=left.finish();complete_original=right.finish()
    need(len(native)==len(original)==(5 if domain.endswith('modern') else 6),'all original and native rows')
    differences=[]
    for i,(a,b) in enumerate(zip(native,original,strict=True)):
        need(set(a)==set(b),'complete field set')
        for field in a:
            if a[field]!=b[field]:differences.append({'index':i,'name':a['name'],'field':field,'native':serial(a[field]),'original':serial(b[field])})
    need(differences and differences[0]['index']==0,'same observed first difference')
    for role in ('native','original'):
        lane=json.loads((capture/(role+'.lane.json')).read_bytes())
        need(lane['status']=='PASS' and lane['domain']==domain and lane['outer_lane_deadline_seconds']==180 and lane['per_exchange_deadline_seconds']==60 and lane['alarm_fired'] is False,'retained complete lane budgets')
    return {'status':'COMPLETE_CATALOG_FAILURE_RETAINED_READ_PASS','semantic_gate_passed':False,'same_original_failure':failure,'domain':domain,'source':source_identity,'original_admission':admitted,'complete_native':complete_native,'complete_original':complete_original,'complete_initialization':serial(left_begin),'complete_native_rows':serial(native),'complete_original_rows':serial(original),'all_field_differences':differences,'runtime_config':{role:json.loads((capture/role/'result.json').read_bytes())['runtime_config'] for role in ('native','original')},'fresh_semantic_executions':0,'original_semantics_replayed':False,'native_semantics_replayed':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
def main():
    p=argparse.ArgumentParser()
    for n in ('input','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--domain',required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==a.profile,'frozen diagnostic source')
    rows=json.loads(raw)['files'];need({p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'complete diagnostic source')
    for n,r in rows.items():need(archive_stream.pin(ROOT/n)=={k:r[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/n).stat().st_mode)==0o644,'exact diagnostic file bytes and mode')
    identity=json.loads((ROOT/'ARCHIVES.json').read_bytes())[a.domain];meta=json.loads((a.input.parent/'artifact.json').read_bytes())
    need(meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'],'exact failed full artifact')
    out=a.output.resolve();out.mkdir(exist_ok=False);proof=out/'proof';proof.mkdir();shutil.copytree(ROOT,proof/'reader-source')
    capture=out/'capture';full=archive_stream.archive(a.input,identity,lambda name:True,output=capture);put(proof/'FULL_ARCHIVE_READ.json',full)
    source=capture/'source';sys.path.insert(0,str(source))
    for module in ('read_gate','read_public','source_check','restore'):importlib.import_module(module)
    for encoding in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(encoding)
    need(gzip.decompress(gzip.compress(b'',mtime=0))==b'','codec warmup')
    guard=read_only_guard.guarded(lambda:examine(capture,source,identity,a.domain),roots=[capture,ROOT],foreign_path='/proc/self/status')
    put(proof/'READONLY.json',guard);put(proof/'RESULT.json',guard['evidence'])
    result=guard['evidence'];print(json.dumps({k:result[k] for k in ('status','domain','semantic_gate_passed','same_original_failure','fresh_semantic_executions')},sort_keys=True))
    print(json.dumps({'files':full['files'],'guard_probes':len(guard['probes']),'differences':[{'index':r['index'],'field':r['field'],'name':r['name']} for r in result['all_field_differences']]},sort_keys=True))
if __name__=='__main__':main()
