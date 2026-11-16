"""Export every owned result/source byte except original compiler intermediates."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import tarfile

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=a.input.absolute();out=a.output.absolute()
    assert root.resolve(strict=True)==root and not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False);files={};paths=[]
    for current,dirs,names in os.walk(root,followlinks=False):
        base=Path(current);rel=base.relative_to(root)
        if rel.as_posix()=='original' and 'cargo-target' in dirs:dirs.remove('cargo-target')
        for name in dirs:
            path=base/name;assert not path.is_symlink() and stat.S_ISDIR(path.lstat().st_mode)
        for name in sorted(names):
            path=base/name;relative=path.relative_to(root).as_posix()
            assert relative!='artifact-manifest.json'
            info=path.lstat();assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and path.resolve()==path
            with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            files[relative]={'bytes':info.st_size,'sha256':digest};paths.append(path)
    manifest={'schema':'hepta.runtime.catalog-eleven-artifact.v1','files':files,
        'only_excluded_directory':'original/cargo-target','complete_native_buffers':True,'complete_original_sources_and_streams':True}
    m=root/'artifact-manifest.json';m.write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n');paths.append(m)
    archive=out/'catalog-eleven.tar.gz'
    with tarfile.open(archive,'w:gz',compresslevel=6) as tar:
        for path in sorted(paths):tar.add(path,arcname=path.relative_to(root).as_posix(),recursive=False)
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    result={'archive':archive.name,'bytes':archive.stat().st_size,'sha256':digest,'files':len(files)+1,'complete_archive':True}
    (out/'archive.json').write_text(json.dumps(result,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
