"""Read each uploaded proof ZIP in full without executing captured owners."""
from pathlib import Path,PurePosixPath
import argparse,codecs,hashlib,json,shutil,stat,sys,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import read_only_guard
def need(ok,text):
    if not ok:raise ValueError(text)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def inspect(folder,identities):
    reports=[];catalog=[]
    for identity in identities:
        artifact=identity['artifact'];path=folder/(str(artifact)+'.zip')
        need(pin(path.read_bytes())=={k:identity[k] for k in ('bytes','sha256')},'complete uploaded proof ZIP')
        meta=json.loads((folder/(str(artifact)+'.json')).read_bytes())
        need(meta['id']==artifact and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'] and meta['digest']=='sha256:'+identity['sha256'],'exact producer proof identity')
        seen=set();files={};selected={}
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                p=PurePosixPath(info.filename)
                need(not p.is_absolute() and '..' not in p.parts and info.filename not in seen and '\x00' not in info.filename,'unique safe proof member')
                seen.add(info.filename);need(not (info.flag_bits&1),'unencrypted proof member')
                if info.is_dir():continue
                raw=z.read(info);need(len(raw)==info.file_size,'complete proof member')
                files[info.filename]={**pin(raw),'mode':(info.external_attr>>16)&0xffff}
                if info.filename in ('RESULT.json','READONLY.json','FULL_ARCHIVE_READ.json','reader-source/PACKAGE.json'):selected[info.filename]=raw
        need(set(selected)=={'RESULT.json','READONLY.json','FULL_ARCHIVE_READ.json','reader-source/PACKAGE.json'},'all original proof reports')
        result=json.loads(selected['RESULT.json']);guard=json.loads(selected['READONLY.json']);full=json.loads(selected['FULL_ARCHIVE_READ.json'])
        need(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0,'complete original strict read-only evidence')
        package=json.loads(selected['reader-source/PACKAGE.json'])
        source_files={n.removeprefix('reader-source/'):v for n,v in files.items() if n.startswith('reader-source/') and n!='reader-source/PACKAGE.json'}
        need(set(source_files)==set(package['files']),'complete original reader source')
        for n,row in package['files'].items():need({k:source_files[n][k] for k in ('bytes','sha256')}=={k:row[k] for k in ('bytes','sha256')},'exact original reader file')
        reports.append({'identity':identity,'files':files,'result_status':result['status'],'reader_package':pin(selected['reader-source/PACKAGE.json']),'complete_capture_files':full['files'],'original_guard_probes':len(guard['probes'])})
        if result['status']=='COMPLETE_CATALOG_FAILURE_RETAINED_READ_PASS':
            observations=[]
            for row in result['all_field_differences']:
                need(row['field']=='wire','actual observed catalog difference field')
                a=json.loads(row['native']['utf8']);b=json.loads(row['original']['utf8'])
                na=a.get('result',{}).get('tools',[]);nb=b.get('result',{}).get('tools',[])
                ma={x['name']:x for x in na};mb={x['name']:x for x in nb}
                aa=json.loads(row['native']['utf8']);bb=json.loads(row['original']['utf8'])
                if 'result' in aa:aa['result'].pop('tools',None)
                if 'result' in bb:bb['result'].pop('tools',None)
                observations.append({'index':row['index'],'name':row['name'],'native_tool_names':[x['name'] for x in na],'original_tool_names':[x['name'] for x in nb],'common_tools_equal':all(ma[n]==mb[n] for n in set(ma)&set(mb)),'outer_except_tools_equal':aa==bb,'native_wire':{k:row['native'][k] for k in ('bytes','sha256')},'original_wire':{k:row['original'][k] for k in ('bytes','sha256')}})
            catalog.append({'artifact':artifact,'domain':result['domain'],'runtime_config':result['runtime_config'],'all_rows':observations})
    return {'status':'COMPLETE_UPLOADED_PROOF_ARCHIVES_READ_PASS','artifact_count':len(reports),'archives':reports,'actual_catalog_observations':catalog,'fresh_semantic_executions':0,'native_or_rust_executions':0,'public_wait_qualified':False,'whole_runtime_replaced':False}
def main():
    p=argparse.ArgumentParser()
    for name in ('input','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PACKAGE.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==a.profile,'frozen reader profile')
    rows=json.loads(raw)['files'];need({p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'complete reader source')
    for name,row in rows.items():need(pin((ROOT/name).read_bytes())=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/name).stat().st_mode)==0o644,'reader source bytes/mode')
    identities=json.loads((ROOT/'ARCHIVES.json').read_bytes())
    expected={str(r['artifact'])+suffix for r in identities for suffix in ('.zip','.json')}
    need({p.name for p in a.input.iterdir()}==expected,'all and only frozen proof artifacts')
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'reader-source')
    for encoding in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(encoding)
    guard=read_only_guard.guarded(lambda:inspect(a.input,identities),roots=[a.input,ROOT],foreign_path='/proc/self/status')
    put(out/'READONLY.json',guard);put(out/'RESULT.json',guard['evidence'])
    print(json.dumps({'status':guard['evidence']['status'],'artifact_count':len(identities),'guard_probes':len(guard['probes']),'fresh_semantic_executions':0},sort_keys=True))
    print(json.dumps({'actual_catalog_observations':guard['evidence']['actual_catalog_observations']},sort_keys=True))
if __name__=='__main__':main()
