"""Independently read complete native-domain archives and repeat the unchanged strict reader."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,importlib,json,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
SOURCE_PROFILE='ecb3c3dd6589cdd3de25535b842f5fad5a132418ecc19669df700a5fb28858ff'
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser()
    for n in ('input','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--domain',required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==a.profile
    rows=json.loads(raw)['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for n,r in rows.items():assert archive_stream.pin(ROOT/n)=={k:r[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/n).stat().st_mode)==0o644
    identity=json.loads((ROOT/'ARCHIVES.json').read_bytes())[a.domain];meta=json.loads((a.input.parent/'artifact.json').read_bytes())
    assert meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source']
    out=a.output.resolve();out.mkdir(exist_ok=False);proof=out/'proof';proof.mkdir();shutil.copytree(ROOT,proof/'reader-source')
    capture=out/'capture';full=archive_stream.archive(a.input,identity,lambda name:True,output=capture);put(proof/'FULL_ARCHIVE_READ.json',full)
    package=capture/'source';assert archive_stream.pin(package/'PACKAGE.json')['sha256']==SOURCE_PROFILE
    sys.path.insert(0,str(package));reader=importlib.import_module('read_gate');controls=importlib.import_module('reader_controls')
    assert Path(reader.__file__).resolve()==package/'read_gate.py' and Path(controls.__file__).resolve()==package/'reader_controls.py'
    run=json.loads((capture/'RUN.json').read_bytes());assert run['status']=='PASS' and run['source_commit']==identity['source'] and run['run_id']==str(identity['run']) and run['domain']==a.domain
    for name in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(name)
    assert gzip.decompress(gzip.compress(b'',mtime=0))==b''
    guard=reader.guarded(capture,package,SOURCE_PROFILE);put(proof/'READONLY.json',guard)
    old=json.loads((capture/'READONLY.json').read_bytes());assert old['before']==old['after'] and len(old['probes'])==11 and old['reader_writes']==old['native_or_rust_executions']==0
    assert guard['evidence']==old['evidence'] and guard['native_or_rust_executions']==0 and guard['reader_writes']==0
    qualification=guard['evidence'];count=json.loads((package/'INPUTS.json').read_bytes())['domains'][a.domain]['operations'];assert qualification['comparison']['actual_rows_per_provider']==count
    physical=None
    if a.domain=='typed-legacy':
        old_guard=read_only_guard.guarded(lambda:controls.verify(capture/'controls'),roots=[capture,package,ROOT],foreign_path='/proc/self/status');put(proof/'ORIGINAL_CONTROLS_READONLY.json',old_guard)
        assert old_guard['evidence']==json.loads((capture/'CONTROLS.json').read_bytes())
        physical=controls.run(capture,proof/'repeated-physical-controls');assert physical['refusals']==12 and physical['guard_probes']==132
    native=json.loads((capture/'native.lane.json').read_bytes());original=json.loads((capture/'original.lane.json').read_bytes())
    result={'status':'INDEPENDENT_COMPLETE_PUBLIC_EXTRACT_DOMAIN_READ_PASS','producer':identity,'domain':a.domain,'full_archive_files':full['files'],'actual_operations_per_provider':count,'native_lane_seconds':native['elapsed_seconds'],'original_lane_seconds':original['elapsed_seconds'],'lane_deadline_seconds':180,'fresh_semantic_executions':0,'original_semantics_replayed':False,'fresh_guard_probes':11+(143 if physical is not None else 0),'physical_controls_repeated':12 if physical else 0,'full_async_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
    put(proof/'RESULT.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
