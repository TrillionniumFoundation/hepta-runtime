"""Pure source authoring and independent byte reproduction; no HIA or Rust execution."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def pin(p):
    raw=Path(p).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def put(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser()
    for n in ('baseline','hepta','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--profile',required=True);x=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true';assert pin(ROOT/'PACKAGE.json')['sha256']==x.profile
    rows=json.loads((ROOT/'PACKAGE.json').read_bytes())['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for n,r in rows.items():assert pin(ROOT/n)=={k:r[k] for k in ('bytes','sha256')} and stat.S_IMODE((ROOT/n).stat().st_mode)==0o644
    inputs=json.loads((ROOT/'authoring/INPUTS.json').read_bytes())
    for p,commit,tree in ((x.hepta,inputs['hepta_commit'],inputs['hepta_tree']),):
        assert subprocess.check_output(['git','-C',str(p),'rev-parse','HEAD']).decode().strip()==commit
        assert subprocess.check_output(['git','-C',str(p),'rev-parse','HEAD^{tree}']).decode().strip()==tree
    output=x.output.resolve();output.mkdir(exist_ok=False);shutil.copytree(ROOT,output/'source')
    spec=importlib.util.spec_from_file_location('custom_request_author',ROOT/'authoring/author.py');author=importlib.util.module_from_spec(spec);spec.loader.exec_module(author)
    first=output/'graph/source';first.parent.mkdir();shutil.copytree(x.baseline,first);result=author.apply(first,x.hepta);put(output/'AUTHOR.json',result)
    second=output/'reproduction';shutil.copytree(x.baseline,second);again=author.apply(second,x.hepta)
    assert again==result
    for n,r in result['source_files'].items():assert pin(first/n)==pin(second/n)==r and (first/n).read_bytes()==(second/n).read_bytes()
    assert len(result['source_files'])==436 and len(result['changed_files'])==7
    summary={'status':'TYPED_CUSTOM_REQUEST_SOURCE_REPRODUCED','source_files':436,'changed_files':7,'runtime_hia_images':118,'descriptor_slots':64,'installed_handlers':10,'source_binding_sha256':result['source_binding_sha256'],'native_or_rust_executions':0,'producer':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID']}
    put(output/'RESULT.json',summary);print('AUTHOR_RESULT '+json.dumps(summary,sort_keys=True))
    for n in sorted(result['changed_files']):print('SOURCE_FILE '+json.dumps({'path':n,**result['changed_files'][n]['after'],'content':(first/n).read_text()},sort_keys=True))
    print('AUTHOR_FILE '+json.dumps({'path':'AUTHOR.json',**pin(output/'AUTHOR.json'),'content':(output/'AUTHOR.json').read_text()},sort_keys=True))
if __name__=='__main__':main()
