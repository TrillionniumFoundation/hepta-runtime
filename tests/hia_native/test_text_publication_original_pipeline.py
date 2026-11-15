"""Physical original-wrapper refusals and two actual absent-root readbacks.

This suite never loads native code, rebuilds Rust, or recreates a live fixture.
Only its private hardlinks, mutation files and admitted source snapshots change.
"""
from pathlib import Path
import argparse,copy,hashlib,json,os,shutil,subprocess,sys,time,traceback

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import qualify_hia_runtime_native as main
import hia_native_text_publication_pipeline as p
import hia_native_text_publication_qualification as q
import hia_native_text_publication_reference as reference

CONTROL_NAMES=('input-native-binding','group-pid','group-stdout','compiler-binding',
  'resigned-omitted-grant','archive-body','resigned-extra-root','same-byte-input-symlink',
  'duplicate-input-json','live-original-root','retained-original-object','resigned-link-target')


def pin(path):return p.file_pin(path)
def save(path,value):p.write_new(path,value)
def replace(path,raw):
    path=Path(path)
    if os.path.lexists(path):path.unlink()
    with path.open('xb')as f:f.write(raw)


def snapshot(source,output,report,baseline,destination):
    new_source=destination/'source';new_output=destination/'output'
    new_source.mkdir(parents=True);new_output.mkdir()
    artifacts=dict(report['text_publication_evidence']['artifact_sha256'])
    artifacts.update(report['text_publication_fixture_retirement']['artifact_sha256'])
    artifacts.update(baseline['artifact_sha256'])
    for old,base,names in ((source,new_source,report['source_sha256']), (output,new_output,artifacts)):
        for name,sha in sorted(names.items()):
            path=p.contained(old,name);q.same(pin(path)['sha256'],sha,'snapshot complete admitted pin')
            target=base/name;target.parent.mkdir(parents=True,exist_ok=True);os.link(path,target)
    save(new_output/'result.json',report)
    return new_source,new_output


def read_worker(args):
    source=args.repo.absolute();output=args.output.absolute()
    for path in args.absent:q.require(not os.path.lexists(path),'original execution/read root must actually be absent')
    report=p.read_json(output/'result.json')
    actual=reference.original_evidence(source,output,report,main.completed_test_summary)
    expected=p.read_json(args.expected)
    q.same(actual,expected,'complete registered original object after source/output relocation')
    save(args.result,{'status':'PASS','evidence':q.pin(p.encoded(actual)),
        'actual_absent_paths':[str(path)for path in args.absent], 'native_calls':0,'rust_processes':0})
    print(json.dumps({'status':'PASS','evidence':q.pin(p.encoded(actual))},sort_keys=True))


def execute(args):
    source=args.repo.absolute();output=args.output.absolute();controls=args.controls.absolute()
    controls.mkdir(parents=True,exist_ok=False)
    report=p.read_json(args.report)
    baseline=reference.original_evidence(source,output,report,main.completed_test_summary)
    save(controls/'BASELINE.json',baseline);save(controls/'REPORT.json',report)
    save(controls/'SOURCE.json',{name:pin(source/name)for name in reference.source_pins(source,report)})
    workspace=output.with_name(output.name+'-text-original-controls')
    workspace.mkdir(exist_ok=False)
    save(workspace/'BASELINE.json',baseline)
    _,trial=snapshot(source,output,report,baseline,workspace/'mutation-snapshot')
    initial=copy.deepcopy(report);rows=[]
    folder=reference.FOLDER
    archive_name=folder+'/fixture-archive/archive.json'
    receipt_name=folder+'/fixture-archive/retired.json'
    def changed_json(name,change):
        value=p.read_json(trial/name);change(value);replace(trial/name,p.encoded(value));return name
    for name in CONTROL_NAMES:
        at=time.monotonic_ns();changed=[];current=copy.deepcopy(initial);special=[]
        record=controls/name;record.mkdir()
        try:
            if name=='input-native-binding':
                changed.append(changed_json(folder+'/INPUT.json',lambda x:x['native_evidence'].update(sha256='0'*64)))
            elif name=='group-pid':
                row=next(r for r in current['checks']if r['name']==reference.CHECK);row['pid']+=1
            elif name=='group-stdout':
                path=trial/(reference.CHECK+'.stdout');replace(path,path.read_bytes()[:-1]);changed.append(reference.CHECK+'.stdout')
            elif name=='compiler-binding':
                changed.append(changed_json(folder+'/INPUT.json',lambda x:x['tools']['rustc'].update(sha256='0'*64)))
            elif name in ('resigned-omitted-grant','resigned-extra-root','resigned-link-target'):
                index=p.read_json(trial/archive_name)
                if name=='resigned-omitted-grant':
                    tree=next(t for t in index['roots']if t['permission_grants']);tree['permission_grants']=[]
                elif name=='resigned-extra-root':
                    index['roots'].append(copy.deepcopy(index['roots'][-1]));index['roots'][-1]['root']+='-extra'
                else:
                    node=next(n for t in index['roots']for n in t['nodes']if n['kind']=='symlink');node['target_base64']=q.b64(b'other-target')
                replace(trial/archive_name,p.encoded(index));changed.append(archive_name)
                changed.append(changed_json(receipt_name,lambda x:x.update(archive=pin(trial/archive_name))))
            elif name=='archive-body':
                index=p.read_json(trial/archive_name);node=next(n for t in index['roots']for n in t['nodes']if n.get('data',{}).get('bytes',0)>0)
                path=folder+'/fixture-archive/'+node['data']['file'];raw=(trial/path).read_bytes()
                replace(trial/path,bytes([raw[0]^1])+raw[1:]);changed.append(path)
            elif name=='same-byte-input-symlink':
                path=trial/(folder+'/INPUT.json');target=record/'same-bytes.json';target.write_bytes(path.read_bytes())
                path.unlink();path.symlink_to(target);changed.append(folder+'/INPUT.json')
                special.append({'path':folder+'/INPUT.json','symlink_target':str(target),'identity':list(path.lstat()[:3])})
            elif name=='duplicate-input-json':
                path=trial/(folder+'/INPUT.json');raw=path.read_bytes();replace(path,b'{"schema":"duplicate",'+raw[1:]);changed.append(folder+'/INPUT.json')
            elif name=='live-original-root':
                index=p.read_json(trial/archive_name);path=trial/index['roots'][0]['root'];path.mkdir(parents=True)
                special.append({'live_root':index['roots'][0]['root'],'dev':path.stat().st_dev,'ino':path.stat().st_ino})
            elif name=='retained-original-object':
                changed.append(changed_json(folder+'/group/EVIDENCE.json',lambda x:x.update(ordinary_cases=98)))
            mutations={}
            for i,item in enumerate(changed):
                if (trial/item).is_symlink():continue
                raw=(trial/item).read_bytes();dest=record/('mutation-'+str(i)+'.bin');dest.write_bytes(raw)
                mutations[item]={'file':str(dest.relative_to(controls)),**pin(dest)}
            save(record/'REPORT.json',current)
            rejected=False
            try:reference.original_evidence(source,trial,current,main.completed_test_summary)
            except (ValueError,KeyError,FileNotFoundError,UnicodeError)as error:
                rejected=True;exception=type(error).__name__;message=str(error)
            q.require(rejected,'physically corrupt evidence was accepted: '+name)
            row={'name':name,'status':'REJECTED','exception':exception,'message':message,
                 'mutations':mutations,'special':special,'report':pin(record/'REPORT.json'),
                 'elapsed_seconds':(time.monotonic_ns()-at)/1e9}
            save(record/'RESULT.json',row);rows.append(row)
        finally:
            for item in changed:
                path=trial/item
                if os.path.lexists(path):path.unlink()
                os.link(output/item,path)
            for item in special:
                if 'live_root'in item:(trial/item['live_root']).rmdir()
    q.same(reference.original_evidence(source,output,report,main.completed_test_summary),baseline,'baseline unchanged after physical controls')
    relocated=[snapshot(source,output,report,baseline,workspace/('relocation-'+str(i)))for i in (1,2)]
    source_identity=list(source.stat()[:3]);output_identity=list(output.stat()[:3])
    hidden_source=source.with_name(source.name+'.text-original-retained')
    hidden_output=output.with_name(output.name+'.text-original-retained')
    q.require(not os.path.lexists(hidden_source)and not os.path.lexists(hidden_output),'owned absence names unused')
    moved=[];processes=[]
    try:
        source.rename(hidden_source);moved.append((hidden_source,source))
        output.rename(hidden_output);moved.append((hidden_output,output))
        for i,(new_source,new_output)in enumerate(relocated,1):
            absent=[source,output]
            if i==2:
                for first in relocated[0]:
                    hidden=first.with_name(first.name+'.retained');first.rename(hidden);moved.append((hidden,first));absent.append(first)
            command=[sys.executable,'-I','-B',str(new_source/'tests/hia_native'/Path(__file__).name),
                '--read','--repo',str(new_source),'--output',str(new_output),'--expected',str(workspace/'BASELINE.json'),
                '--result',str(workspace/('read-'+str(i)+'.json'))]
            for path in absent:command+=['--absent',str(path)]
            process=p.child_process(new_source,workspace,'relocation-'+str(i),command)
            processes.append(process)
    finally:
        for old,new in reversed(moved):old.rename(new)
    q.same(list(source.stat()[:3]),source_identity,'same source inode restored')
    q.same(list(output.stat()[:3]),output_identity,'same output inode restored')
    q.same(reference.original_evidence(source,output,report,main.completed_test_summary),baseline,'entire baseline unchanged after actual absence')
    for i in (1,2):
        for name in ('relocation-'+str(i)+'.stdout','relocation-'+str(i)+'.stderr',
                     'relocation-'+str(i)+'.process.json','read-'+str(i)+'.json'):
            shutil.copyfile(workspace/name,controls/name)
            q.same(pin(workspace/name),pin(controls/name),'complete actual relocation stream retained')
    for name in ('mutation-snapshot','relocation-1','relocation-2'):
        shutil.rmtree(workspace/name)
    result={'status':'PASS','controls':12,'rows':rows,'actual_absent_root_reads':2,'read_processes':processes,
        'baseline':pin(controls/'BASELINE.json'),'source':pin(controls/'SOURCE.json'),'report':pin(controls/'REPORT.json'),
        'source_restored_identity':source_identity,'output_restored_identity':output_identity,
        'private_snapshot_directories_retired':True,'new_native_calls':0,'new_rust_processes':0,
        'public_handler_complete':False,'whole_runtime_replaced':False}
    save(controls/'RESULT.json',result)
    print(json.dumps({k:v for k,v in result.items()if k not in ('rows','read_processes')},sort_keys=True))


def main_entry():
    parser=argparse.ArgumentParser();parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--report',type=Path);parser.add_argument('--controls',type=Path);parser.add_argument('--read',action='store_true')
    parser.add_argument('--expected',type=Path);parser.add_argument('--result',type=Path);parser.add_argument('--absent',type=Path,action='append',default=[])
    args=parser.parse_args()
    if args.read:read_worker(args)
    else:execute(args)
if __name__=='__main__':main_entry()
