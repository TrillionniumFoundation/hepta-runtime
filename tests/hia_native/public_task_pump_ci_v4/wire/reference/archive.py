"""Retain complete success or failure bytes without selecting favorable records."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,tarfile
ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--driver-prefix',type=Path,required=True);a=p.parse_args()
    root=a.capture.resolve();root.mkdir(parents=True,exist_ok=True);output=a.output.resolve();output.mkdir(mode=0o700)
    if not (root/'recipe-source').exists():shutil.copytree(ROOT,root/'recipe-source')
    for suffix in ('stdout','stderr'):
        source=Path(str(a.driver_prefix)+'.'+suffix)
        if source.is_file():shutil.copyfile(source,root/('driver.'+suffix))
    files={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():
            with path.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
            files[path.relative_to(root).as_posix()]={'bytes':path.stat().st_size,'sha256':digest}
    (root/'artifact-manifest.json').write_text(json.dumps({'files':files},sort_keys=True,indent=2)+'\n')
    archive=output/'public-reference.tar.gz'
    with tarfile.open(archive,'w:gz',compresslevel=1,dereference=True) as tar:tar.add(root,arcname='public-reference',recursive=True)
    with archive.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    report=dict(files=len(files),logical_bytes=sum(v['bytes'] for v in files.values()),bytes=archive.stat().st_size,sha256=digest,
        git_head=os.environ.get('GITHUB_SHA'),run_id=os.environ.get('GITHUB_RUN_ID'),attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
        public_handler_qualified=False,whole_runtime_replaced=False)
    (output/'archive.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
