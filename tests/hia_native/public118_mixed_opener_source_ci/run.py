"""Recover the exact locked SDK source and already captured diagnostic bytes only."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,io,json,os,stat,sys,tarfile,urllib.request,zipfile,shutil
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n')
def fetch(url):
    with urllib.request.urlopen(url,timeout=60) as r:return r.read()
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    meta=json.loads((ROOT/'PACKAGE.json').read_bytes());assert pin((ROOT/'PACKAGE.json').read_bytes())['sha256']==a.profile
    assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(meta['files'])|{'PACKAGE.json'}
    for n,r in meta['files'].items():assert pin((ROOT/n).read_bytes())==r
    inputs=json.loads((ROOT/'INPUTS.json').read_bytes());out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'reader-source')
    want=inputs['rmcp'];raw=fetch(want['url']);assert pin(raw)['sha256']==want['sha256'];(out/'rmcp-3.9.0.crate').write_bytes(raw)
    files={};selected=[]
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
        for m in t:
            path=PurePosixPath(m.name);assert not path.is_absolute() and '..' not in path.parts
            if m.isdir():continue
            assert m.isfile() and m.name not in files
            value=t.extractfile(m).read();assert len(value)==m.size;files[m.name]={**pin(value),'mode':m.mode}
            if m.name.endswith('.rs') and any(needle in value for needle in (b'initialize request',b'Missing required metadata',b'pub async fn serve_server',b'expect initialized notification')):
                text=value.decode();target=out/'sdk-source'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(value);target.chmod(m.mode)
                row={'path':m.name,**pin(value),'content':text};selected.append({k:v for k,v in row.items() if k!='content'});print('LOCKED_SDK_SOURCE '+json.dumps(row,sort_keys=True))
    assert selected;put(out/'SDK_FILES.json',files);proofs={}
    for name,want in inputs['diagnostic_proofs'].items():
        b=(a.input/(name+'.zip')).read_bytes();actual=json.loads((a.input/(name+'.json')).read_bytes())
        assert pin(b)=={k:want[k] for k in ('bytes','sha256')} and actual['id']==want['artifact'] and actual['digest']=='sha256:'+want['sha256'] and actual['workflow_run']['head_sha']==want['source'] and actual['workflow_run']['id']==want['run']
        (out/(name+'.zip')).write_bytes(b);seen={};result=None
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            assert z.testzip() is None
            for m in z.infolist():
                path=PurePosixPath(m.filename);assert not path.is_absolute() and '..' not in path.parts and not m.is_dir() and not stat.S_ISLNK(m.external_attr>>16) and m.filename not in seen
                value=z.read(m);seen[m.filename]={**pin(value),'mode':m.external_attr>>16}
                if path.name=='RESULT.json':
                    assert result is None;result=json.loads(value);(out/(name+'-RESULT.json')).write_bytes(value)
        assert result and result['status']=='COMPLETE_FAILED_RAW_CAPTURE_READ_WITH_SAME_REFUSAL' and result['semantic_gate_passed'] is False and result['actual_process_pairs']==71
        put(out/(name+'-ZIP_FILES.json'),seen);proofs[name]={'artifact':want,'files':len(seen),'differences':len(result['all_field_differences'])}
        for d in result['all_field_differences']:
            if d['field']=='stdout':
                print('RETAINED_STDOUT_DIFFERENCE '+json.dumps({'domain':name,**d},sort_keys=True))
    report={'status':'LOCKED_SDK_AND_COMPLETE_RETAINED_DIAGNOSTIC_READ_PASS','source':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID'],'profile':a.profile,'sdk_crate':pin(raw),'sdk_files':len(files),'selected':selected,'diagnostic_proofs':proofs,'native_or_rust_executions':0,'original_failure_preserved':True}
    put(out/'RESULT.json',report);print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
