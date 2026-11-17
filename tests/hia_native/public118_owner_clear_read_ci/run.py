"""Purely read the complete retained owner-clear capture and four physical refusals."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
IDENTITY={'artifact':14296810163,'bytes':430533602,'sha256':'ad076fa128d4a505e373af26bd7c3c86405ca5662422f1e8b79c91b2d1fc250c','source':'7cc3382e0d17b33866d52e958a4a5a15932d45b9','run':44009813863}
PROFILE='8641a51d6392af82f4a1c6ae199647e95a37e00d31d001cd17b0179e91b0f1f1'
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def choose(name):return True
def valid_guard(path):
    g=json.loads(path.read_bytes())
    assert g['schema']=='hepta.runtime.owner-export-readonly.v1' and g['native_or_rust_executions']==0 and g['reader_writes']==0
    assert g['source_bound_guard'] is True and g['before']==g['after'] and len(g['probes'])==11
    assert len({p['name'] for p in g['probes']})==11 and all(p['refusal'] and p['guard_event'] for p in g['probes'])
    return g
def inspect(folder,read_pairs):
    archive_stream.verify_selection(folder,IDENTITY,choose)
    run=json.loads((folder/'RUN.json').read_bytes())
    assert run['status']=='CALLER_CLEAR_SOURCE_AND_COMPLETE_BUFFERS_PASS' and run['source_commit']==IDENTITY['source'] and run['run_id']==str(IDENTITY['run'])
    assert run['source_profile']==PROFILE and run['runtime_rust_executions']==0 and run['old_production_owner_recompiled'] is False and run['full_public_domain_qualified'] is False
    assert archive_stream.pin(folder/'source/PACKAGE.json')['sha256']==PROFILE
    proof=read_pairs.read(folder,folder/'source')
    assert proof==valid_guard(folder/'READONLY.json')['evidence']==run['paired_read']
    assert proof['image_after']=={'bytes':129692,'sha256':'0aa7cb9da671e5844188f633812e930984361372745e0cdfc9b372b41822f9fb'}
    report=json.loads((folder/'reader-controls/REPORT.json').read_bytes());assert report==run['controls']
    assert report['status']=='CALLER_CLEAR_READER_PHYSICAL_CONTROLS_PASS' and report['refusals']==4 and report['guard_probes']==44 and report['native_or_rust_executions']==0
    labels=['source-byte','complete-buffer','trap-prefix','actual-return']
    assert [r['case'] for r in report['cases']]==labels
    for row in report['cases']:
        base=folder/'reader-controls'/row['case'];clone=base/'capture'
        assert json.loads((base/'CONTROL.json').read_bytes())==row and archive_stream.pin(base/'GUARD.json')==row['guard']
        original=valid_guard(base/'GUARD.json');assert original['evidence']==row['refusal'] and row['refusal']['rejected'] is True and row['guard_probes']==11 and row['native_or_rust_executions']==0
        assert archive_stream.pin(clone/row['changed_path'])==row['changed_complete_file']
    return proof
def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==a.profile;rows=json.loads(raw)['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for name,row in rows.items():
        path=ROOT/name;assert archive_stream.pin(path)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(path.stat().st_mode)==0o644 and not path.is_symlink()
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'reader-source');folder=out/'capture'
    full=archive_stream.archive(a.archive,IDENTITY,choose,output=folder);put(out/'FULL_ARCHIVE_READ.json',full)
    sys.path.insert(0,str(folder/'source/base'));sys.path.insert(0,str(folder/'source'))
    import read_pairs
    good=read_only_guard.guarded(lambda:inspect(folder,read_pairs),roots=[folder,ROOT],foreign_path='/proc/self/status');put(out/'READONLY.json',good)
    controls=[]
    for label in ('source-byte','complete-buffer','trap-prefix','actual-return'):
        base=folder/'reader-controls'/label;clone=base/'capture'
        def reject():
            try:read_pairs.read(clone,folder/'source')
            except (ValueError,AssertionError) as error:return {'rejected':True,'error_type':type(error).__name__,'message':str(error)}
            raise RuntimeError('retained physical mutation accepted: '+label)
        g=read_only_guard.guarded(reject,roots=[folder,ROOT],foreign_path='/proc/self/status')
        expected=json.loads((base/'CONTROL.json').read_bytes())['refusal'];assert g['evidence']==expected
        put(out/('REFUSAL-'+label+'.json'),g);controls.append({'case':label,'evidence':g['evidence'],'guard_probes':len(g['probes'])})
    result={'status':'INDEPENDENT_COMPLETE_OWNER_CLEAR_READ_PASS','producer':IDENTITY,'complete_archive_files':full['files'],'pairs':good['evidence']['pairs'],'actual_native_calls_retained':70,'actual_trap_pairs':good['evidence']['actual_trap_pairs'],'fresh_native_or_rust_executions':0,'physical_controls':controls,'guard_probes':55,'full_public_domain_qualified':False,'after_source':good['evidence']['source_after'],'after_image':good['evidence']['image_after']}
    put(out/'RESULT.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
