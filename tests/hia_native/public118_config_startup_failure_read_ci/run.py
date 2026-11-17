"""Read the complete terminal configuration-startup failures; never execute a binary."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,importlib,json,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
PROFILE='3c79f8fb87a341c3b6fcad2284745fccca90306c8449d90494a3834b1781af5e'
def need(ok,text):
    if not ok:raise ValueError(text)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def examine(root,identity,domain):
    import source_check,read_gate
    source=root/'source';admitted=source_check.check(source,PROFILE)
    run=json.loads((root/'RUN.json').read_bytes());need(run['status']=='FAIL' and run['source_commit']==identity['source'] and run['run_id']==str(identity['run']) and run['domain']==domain and run['source_profile']==PROFILE,'same complete failed run')
    old=read_gate.admit_original(root,source,domain);need(old==json.loads((root/'ORIGINAL_ADMISSION.json').read_bytes()),'same unchanged original admission')
    native=json.loads((root/'native/result.json').read_bytes());process=json.loads((root/'native/process/process.json').read_bytes());started=json.loads((root/'native/process/started.json').read_bytes())
    need(native['status']=='FAIL' and native['process']==process and all(started[k]==process[k] for k in started if k!='observer_fd'),'complete failed actual process custody')
    streams={}
    for name,row in process['streams'].items():
        raw=(root/'native/process'/(name+'.bin.gz')).read_bytes();decoded=gzip.decompress(raw)
        need(pin(raw)==row['compressed'] and pin(decoded)==row['uncompressed'],'complete raw failed process stream')
        streams[name]={**pin(decoded),'utf8':decoded.decode('utf-8',errors='backslashreplace'),'hex':decoded.hex()}
    return {'status':'COMPLETE_CONFIG_STARTUP_FAILURE_READ_PASS','semantic_gate_passed':False,'producer':identity,'domain':domain,'source':admitted,'run_failure':run['failure'],'completed_cases':native['completed_cases'],'native_process':process,'complete_native_streams':streams,'original_admission':old,'fresh_semantic_executions':0,'original_semantics_replayed':False,'native_semantics_replayed':False}
def main():
    p=argparse.ArgumentParser()
    for n in ('input','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--domain',required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==a.profile,'frozen reader profile')
    rows=json.loads(raw)['files'];need({p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'complete reader source')
    for n,r in rows.items():need(archive_stream.pin(ROOT/n)=={k:r[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/n).stat().st_mode)==0o644,'complete reader bytes/mode')
    identity=json.loads((ROOT/'ARCHIVES.json').read_bytes())[a.domain];meta=json.loads((a.input.parent/'artifact.json').read_bytes())
    need(meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'],'exact complete artifact')
    out=a.output.resolve();out.mkdir(exist_ok=False);proof=out/'proof';proof.mkdir();shutil.copytree(ROOT,proof/'reader-source')
    capture=out/'capture';full=archive_stream.archive(a.input,identity,lambda name:True,output=capture);put(proof/'FULL_ARCHIVE_READ.json',full)
    sys.path.insert(0,str(capture/'source'))
    for name in ('source_check','read_gate'):importlib.import_module(name)
    for name in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(name)
    need(gzip.decompress(gzip.compress(b'',mtime=0))==b'','codec warmup')
    guard=read_only_guard.guarded(lambda:examine(capture,identity,a.domain),roots=[capture,ROOT],foreign_path='/proc/self/status')
    put(proof/'READONLY.json',guard);put(proof/'RESULT.json',guard['evidence']);r=guard['evidence']
    print(json.dumps({k:r[k] for k in ('status','domain','run_failure','completed_cases','native_process','complete_native_streams','fresh_semantic_executions')},sort_keys=True))
if __name__=='__main__':main()
