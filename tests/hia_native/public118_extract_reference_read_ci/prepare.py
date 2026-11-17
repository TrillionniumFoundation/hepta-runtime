"""Extract the one retained failed producer archive, without rebuilding or executing it."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, shutil, sys, types, zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def pin(p):
    h=hashlib.sha256();size=0
    with Path(p).open('rb') as f:
        while chunk:=f.read(1<<20):h.update(chunk);size+=len(chunk)
    return {'bytes':size,'sha256':h.hexdigest()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--original-package',type=Path,required=True);a=p.parse_args()
    assert not a.output.exists();a.output.mkdir(parents=True)
    assert pin(a.input)=={'bytes':483684477,'sha256':'f48324b3842de7654c1cd220e895be824688961a592d590f9aeaba1a49bf5fda'}
    manifest=a.original_package/'PACKAGE.json';assert pin(manifest)['sha256']=='fec98075c21e5761ae344d786d457144c5fb01aa48ab7427bb65748b26ea9e22'
    source=json.loads(manifest.read_bytes());assert set(source['files'])|{'PACKAGE.json'}=={x.relative_to(a.original_package).as_posix() for x in a.original_package.rglob('*') if x.is_file()}
    for name,row in source['files'].items():
        raw=(a.original_package/name).read_bytes();assert pin(a.original_package/name)=={k:row[k] for k in ('bytes','sha256')};assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
    with zipfile.ZipFile(a.input) as z:
        assert z.namelist()==['archive.json','capture.tar.gz'] and z.testzip() is None
        for name in z.namelist():
            with z.open(name) as src,(a.output/name).open('xb') as dst:shutil.copyfileobj(src,dst,1<<20)
    assert pin(a.output/'capture.tar.gz')=={'bytes':483683508,'sha256':'4f6a812c4bb614e936e4b616dd59326de4d7a89d3f656efbb9009416202c1466'}
    sys.path.insert(0,str(a.original_package/'ci'))
    path=a.original_package/'ci/archive.py';module=types.ModuleType('retained_archive');module.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec',dont_inherit=True),module.__dict__)
    module.extract(argparse.Namespace(archive=a.output/'capture.tar.gz',receipt=a.output/'archive.json',output=a.output/'capture'))
    proof=a.output/'proof';proof.mkdir();shutil.copytree(ROOT,proof/'reader-source')
    selected=['FAILURE.json','CORE_READY.json','ORIGIN.json','CI_SOURCE_DECLARATION.json','artifact-manifest.json','original/BUILD.json','reader-controls/report.json','driver.stdout','driver.stderr','processes/reader.stdout','processes/reader.stderr']
    retained=[]
    for name in selected:
        source=a.output/'capture'/name
        if source.is_file():
            destination=proof/'original'/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination);retained.append({'path':name,**pin(source)})
    result={'status':'SAME_REFERENCE_ARCHIVE_COMPLETE_EXTRACTION_PASS','original_run':43988628108,'original_artifact':14286891582,'original_conclusion':'FAIL','original_zip':pin(a.input),'archive':pin(a.output/'capture.tar.gz'),'selected_full_files':retained,'native_or_rust_executions':0,'runtime_recompiled':False,'source_mutated':False}
    (proof/'EXTRACTION.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
