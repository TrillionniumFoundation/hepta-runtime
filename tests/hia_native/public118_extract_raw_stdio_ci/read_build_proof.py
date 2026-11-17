"""Read every byte of the retained independent build proof and publish actual image pins."""
from pathlib import Path
import argparse,codecs,hashlib,json,stat,sys,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
from receipt_support import PIN,regular,require
CONFIG={'native':{'artifact':14297256599,'run':44011881780,'source':'ee25e2eb24553d67d92c285900d1ff2655cd69c1','bytes':787832332,'sha256':'ecf31afc326fd5197c3f182b7a4eb09b037221e380dedd19b4e1c4f85500b102'},'source_binding':'dd5af0b52523e7652ca4a763fef0f8c1865b773b07f2cf6dd05b42e9e5c66438'}
PROOF={'artifact':14296594349,'run':44012641156,'source':'71dc955bf694f598b29f7ccfc1dc6554a5b2128e','bytes':53693608,'sha256':'fb8928ddbfec62be2146463c3d061987497a15c1bfa5676937de771e57cb033f'}
def proof_extract(path,output):
    output=Path(output);require(not output.exists(),'proof output exists');output.mkdir()
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None,'proof full ZIP CRC');seen=set()
        for info in z.infolist():
            archive_stream.safe(info.filename);require(info.filename not in seen and not info.is_dir() and not stat.S_ISLNK(info.external_attr>>16),'unique regular proof file');seen.add(info.filename)
            target=output/info.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(info.filename));target.chmod((info.external_attr>>16)&0o777 or 0o644)
def proof_verify(path,folder):
    folder=Path(folder)
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None and set(z.namelist())=={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()},'complete proof member inventory')
        for info in z.infolist():require(regular(folder/info.filename)==z.read(info.filename),'complete proof bytes')
    guards=list(folder.rglob('READONLY.json'));require(len(guards)==1,'one independent full native read')
    g=json.loads(regular(guards[0]));require(g['before']==g['after'] and len(g['probes'])==11 and g['reader_writes']==g['native_or_rust_executions']==0 and g['source_bound_guard'] is True,'complete native guarded read')
    e=g['evidence'];pin=CONFIG['native'];require(e['status']=='COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS' and e['artifact']==pin['artifact'] and e['source']==pin['source'] and e['run']==pin['run'] and e['zip']=={k:pin[k] for k in ('bytes','sha256')},'exact repaired native build read')
    q=e['build_qualification'];require(q['status']=='FRESH_PUMP_GRAPH_BUILD_READBACK_PASS' and q['source']['graph_source_binding']==CONFIG['source_binding'] and q['runtime_hia_images']==118 and q['fresh_direct_members']==110 and q['packed_hia_members']==8,'full actual native source/build qualification')
    reports=list(folder.rglob('complete-physical-controls/REPORT.json'));require(len(reports)==1,'complete physical prerequisite gate');control_root=reports[0].parent;report=json.loads(regular(reports[0]))
    require(report['status']=='COMPLETE_PHYSICAL_BUILD_READER_CONTROLS_PASS' and report['refusals']==4 and report['guard_probes']==44 and report['complete_baseline_guard_probes']==11 and report['semantic_executions']==0 and report['complete_mutated_bytes_retained'] is True,'full physical read controls')
    require(PIN(regular(control_root/'FULL_SOURCE_INVENTORY.json'))==report['complete_source_inventory'] and PIN(regular(control_root/'BASELINE_GUARD.json'))==report['baseline_guard'],'full baseline identities')
    baseline=json.loads(regular(control_root/'BASELINE_GUARD.json'));require(baseline['before']==baseline['after'] and len(baseline['probes'])==11 and baseline['reader_writes']==baseline['native_or_rust_executions']==0,'complete unmutated clone gate')
    for row in report['cases']:
        case=control_root/row['case'];require(json.loads(regular(case/'CONTROL.json'))==row and PIN(regular(case/'GUARD.json'))==row['guard'],'complete physical case identity');cg=json.loads(regular(case/'GUARD.json'))
        require(cg['before']==cg['after'] and len(cg['probes'])==11 and cg['reader_writes']==cg['native_or_rust_executions']==0 and cg['evidence']==row['rejection'] and row['rejection']['rejected'] is True,'actual physical refusal')
        changed=case/'changed'/row['changed_path'];node=cg['before']['0:'+row['changed_path']]
        require(PIN(regular(changed))=={k:row['after'][k] for k in ('bytes','sha256')} and {k:node[k] for k in ('bytes','sha256')}=={k:row['after'][k] for k in ('bytes','sha256')} and stat.S_IMODE(node['mode'])==row['after']['mode'] and row['before']!=row['after'],'full physical mutation bytes and original guarded mode')
    return {'build':q,'controls':report,'native_or_rust_executions':0}
def main():
    p=argparse.ArgumentParser();p.add_argument('--zip',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert archive_stream.pin(a.zip)=={k:PROOF[k] for k in ('bytes','sha256')}
    a.output.mkdir(exist_ok=False);folder=a.output/'complete';proof_extract(a.zip,folder)
    for name in ('cp437','utf-8'):codecs.lookup(name)
    g=read_only_guard.guarded(lambda:proof_verify(a.zip,folder),roots=[folder,ROOT,a.zip.absolute().parent],foreign_path='/proc/self/status')
    (a.output/'READONLY.json').write_text(json.dumps(g,sort_keys=True,indent=2)+'\n')
    result={'status':'FULL_INDEPENDENT_BUILD_PROOF_ZIP_READ_PASS','producer':PROOF,'build_producer':CONFIG['native'],'source_binding':CONFIG['source_binding'],'actual_images':g['evidence']['build']['entries'],'fresh_native_or_rust_executions':0,'fresh_guard_probes':11,'retained_physical_refusals':g['evidence']['controls']['refusals']}
    (a.output/'RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
