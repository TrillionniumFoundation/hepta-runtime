"""Pure complete read of one terminal failed build; no semantic execution."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,json,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream as stream
import read_only_guard as guard
IDENTITY={"artifact":14304250580,"run":44027182429,"source":"8db0ff70049c5bcfea07b803fec63e844e0facad","bytes":178785819,"sha256":"9dc4b6bf5ad2289c866a67305eb71aad668146809a7a557b3522c462db6288e0"}
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def choose(name):
    return name.endswith(('.stderr','.stdout')) or name.startswith('processes/') or name in ('BUILD_ORIGIN.json','BUILD_PASS.json')
def main():
    p=argparse.ArgumentParser()
    for n in ('input','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--profile',required=True);a=p.parse_args()
    raw=(ROOT/'PROFILE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==a.profile
    rows=json.loads(raw)['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PROFILE.json'}
    for name,row in rows.items():assert stream.pin(ROOT/name)==row and stat.S_IMODE((ROOT/name).stat().st_mode)==0o644
    meta=json.loads((a.input.parent/'artifact.json').read_bytes())
    assert meta['id']==IDENTITY['artifact'] and meta['digest']=='sha256:'+IDENTITY['sha256'] and meta['workflow_run']['id']==IDENTITY['run'] and meta['workflow_run']['head_sha']==IDENTITY['source']
    out=a.output.resolve();out.mkdir(exist_ok=False);proof=out/'proof';proof.mkdir()
    selected=out/'capture';first=stream.archive(a.input,IDENTITY,choose,output=selected);put(proof/'FULL_ARCHIVE_READ.json',first)
    for name in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(name)
    assert gzip.decompress(gzip.compress(b'',mtime=0))==b''
    def read():
        actual=stream.archive(a.input,IDENTITY,choose,verify_root=selected);assert actual==first
        stream.verify_selection(selected,IDENTITY,choose)
        rows={};errors=[]
        for path in sorted(selected.rglob('*')):
            if not path.is_file():continue
            rel=path.relative_to(selected).as_posix()
            if path.suffix=='.stderr':
                data=path.read_bytes()
                if data:errors.append({'path':rel,**stream.pin(path),'text':data.decode('utf-8',errors='backslashreplace')})
            elif rel.startswith('processes/') and path.suffix=='.json':
                rows[rel]=json.loads(path.read_bytes())
        return {'status':'COMPLETE_TERMINAL_FAILED_BUILD_READ_PASS','producer':IDENTITY,'full_archive_files':first['files'],'processes':rows,'nonempty_stderr':errors,'semantic_gate_passed':False,'semantic_executions':0}
    checked=guard.guarded(read,roots=[selected,ROOT,a.input.parent.resolve()],foreign_path='/proc/self/status')
    assert checked['before']==checked['after'] and len(checked['probes'])==11 and checked['reader_writes']==checked['native_or_rust_executions']==0
    put(proof/'READONLY.json',checked);put(proof/'RESULT.json',checked['evidence']);shutil.copytree(ROOT,proof/'reader-source')
    shutil.copytree(selected,proof/'selected')
    result=checked['evidence']
    print('FAILED_PROCESS_ROWS '+json.dumps(result['processes'],sort_keys=True))
    for row in result['nonempty_stderr']:print('CAPTURED_STDERR '+json.dumps(row,sort_keys=True))
    print('RESULT '+json.dumps({k:v for k,v in result.items() if k not in ('processes','nonempty_stderr')},sort_keys=True))
if __name__=='__main__':main()
