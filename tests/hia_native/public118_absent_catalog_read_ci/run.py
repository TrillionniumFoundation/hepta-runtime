"""Read the complete qualified catalog capture and select actual flags-zero assets."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,importlib.util,io,json,os,shutil,stat,struct,sys,tarfile,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def filepin(p):
    with p.open('rb') as f:return {'bytes':p.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def put(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser()
    for n in ('input','output','capture'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--profile',required=True);a=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    manifest=json.loads((ROOT/'PACKAGE.json').read_bytes());assert filepin(ROOT/'PACKAGE.json')['sha256']==a.profile
    assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(manifest['files'])|{'PACKAGE.json'}
    for n,w in manifest['files'].items():assert filepin(ROOT/n)==w
    want=json.loads((ROOT/'INPUTS.json').read_bytes())
    zpath=a.input/'catalog.zip';meta=json.loads((a.input/'catalog.json').read_bytes())
    assert filepin(zpath)==want['archive'] and meta['id']==14201568537 and meta['digest']=='sha256:'+want['archive']['sha256']
    assert meta['workflow_run']['head_sha']==want['source'] and meta['workflow_run']['id']==43813791993
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'reader-source')
    capture=a.capture.resolve();capture.mkdir(exist_ok=False);files={};outer={}
    with zipfile.ZipFile(zpath) as z:
        assert z.testzip() is None
        gz=[m for m in z.infolist() if m.filename.endswith('.tar.gz')]
        assert len(gz)==1
        for m in z.infolist():
            n=PurePosixPath(m.filename);assert not n.is_absolute() and '..' not in n.parts and not m.is_dir() and not stat.S_ISLNK(m.external_attr>>16)
            with z.open(m) as stream:
                h=hashlib.sha256();count=0
                while block:=stream.read(1<<20):h.update(block);count+=len(block)
            outer[m.filename]={'bytes':count,'sha256':h.hexdigest()}
        assert outer[gz[0].filename]==want['tar']
        with z.open(gz[0]) as stream,tarfile.open(fileobj=stream,mode='r|gz') as t:
            for m in t:
                n=PurePosixPath(m.name);assert not n.is_absolute() and '..' not in n.parts and str(n)==m.name
                if m.isdir():continue
                assert m.isfile() and m.name not in files
                dst=capture/n;dst.parent.mkdir(parents=True,exist_ok=True)
                h=hashlib.sha256();count=0
                with t.extractfile(m) as src,dst.open('xb') as target:
                    while block:=src.read(1<<20):h.update(block);count+=len(block);target.write(block)
                assert count==m.size;dst.chmod(m.mode)
                files[m.name]={'bytes':count,'sha256':h.hexdigest(),'mode':m.mode}
    assert len(files)==want['complete_archive_files'],len(files)
    candidates=[]
    for path in capture.rglob('result.json'):
        try:value=json.loads(path.read_bytes())
        except (ValueError,UnicodeError):continue
        if type(value) is dict and value.get('schema')=='hepta.runtime.catalog-policy-recipe.v2':candidates.append(path.parent)
    assert len(candidates)==1;recipe=candidates[0]
    assert filepin(recipe/'source/read_catalog.py')==want['reader']
    assert filepin(recipe/'source/run_recipe.py')==want['recipe_reader']
    sys.path.insert(0,str(recipe/'source'))
    import run_recipe,read_catalog
    # Warm only the original pure Python readers, then repeat inside the guard.
    warm=run_recipe.verify(recipe)
    spec=importlib.util.spec_from_file_location('catalog_absent_guard',ROOT/'read_only_guard.py')
    guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
    guarded=guard.guarded(lambda:run_recipe.verify(recipe),roots=[capture,ROOT],foreign_path=Path('/etc/hostname'))
    assert guarded['evidence']==warm and warm['status']=='PASS' and warm['process_launches']==0
    rows=json.loads((recipe/'native/result.json').read_bytes())['shapes']
    selected=[r for r in rows if r['flags']==0];assert len(selected)==2 and {r['modern'] for r in selected}=={0,1}
    installed=set(want['installed'])
    assets={};shapes={}
    for row in selected:
        label='modern' if row['modern'] else 'ordinary'
        typed=read_catalog.Reader(recipe/'native').compressed(row['name']+'.typed-json.gz')
        document=json.loads(typed);assert document['resultType']=='complete' and len(document['tools'])==row['count']
        names=[x['name'] for x in document['tools']]
        text=typed.decode();decoder=json.JSONDecoder();at=text.index('"tools":[')+len('"tools":[');parts=[]
        while at<len(text) and text[at]!=']':
            item,end=decoder.raw_decode(text,at)
            if item['name'] in installed:parts.append((item['name'],text[at:end].encode()))
            if text[end]==']':at=end
            else:assert text[end]==',';at=end+1
        assert [n for n,_ in parts]==[n for n in names if n in installed]
        assert set(n for n,_ in parts)==installed-{'effective_config','execution_shadow_admit','host_list'}
        subset=b'['+b','.join(b for _,b in parts)+b']'
        for name,b in (('actual/'+label+'.typed.json',typed),('selected/'+label+'.tools.json',subset)):
            dst=out/'assets'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(b)
            assets[name]=pin(b);print('ACTUAL_ASSET '+json.dumps({'path':name,**pin(b),'content':b.decode()},sort_keys=True))
        shapes[label]={'flags':0,'modern':row['modern'],'shape':row['name'],'actual_count':row['count'],'selected_names':[n for n,_ in parts],'calls':row['calls'],'serde':row['serde'],'sdk':row['sdk'],'typed':pin(typed),'selected':pin(subset)}
    asset={'schema':'hepta.runtime.public118.catalog-absent-actual-assets.v1','status':'ACTUAL_NATIVE_FLAGS_ZERO_ASSETS_READ','source':want['source'],'run':43813791993,'artifact':14201568537,'archive':want['archive'],'declared_input_tools':136,'shapes':shapes,'files':assets,'native_or_rust_executions':0,'source_of_literal':'retained actual policy -> serde Value -> SDK typed Tool bytes','expected_wires_used_as_implementation':False}
    put(out/'assets/ASSETS.json',asset);print('ACTUAL_ASSET '+json.dumps({'path':'ASSETS.json',**filepin(out/'assets/ASSETS.json'),'content':(out/'assets/ASSETS.json').read_text()},sort_keys=True))
    put(out/'READONLY.json',guarded);put(out/'ARCHIVE_FILES.json',files);put(out/'ZIP_FILES.json',outer)
    result={'status':'COMPLETE_CATALOG_ABSENT_ASSETS_READ_PASS','complete_archive_files':len(files),'source':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID'],'recipe_capture_source':want['source'],'profile':a.profile,'archive':want['archive'],'original_reader_full_pass':True,'actual_native_calls_previously_captured':warm['matrix_native_calls']+warm['control_native_calls'],'guard_probes':len(guarded['probes']),'guard_before_equals_after':guarded['before']==guarded['after'],'assets':filepin(out/'assets/ASSETS.json'),'native_or_rust_executions':0}
    put(out/'RESULT.json',result);print('ABSENT_ASSET_RESULT '+json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
