"""Compile the three private Bellman callable HIA components with verified B3."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
B3='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
MODULES=('bellman_params_callable','bellman_diagnostic_callable','bellman_call')
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bootstrap-cache',type=Path)
    a=p.parse_args();a.hepta=a.hepta.resolve(strict=True);output=a.output.absolute()
    assert not output.exists();output.mkdir(parents=True)
    if a.bootstrap_cache:
        cache=a.bootstrap_cache.resolve(strict=True)
        for name in ('B1.image.bin','B2.image.bin','B3.image.bin'):
            raw=(cache/name).read_bytes();assert len(raw)==673413 and hashlib.sha256(raw).hexdigest()==B3
        shutil.copytree(cache,output/'bootstrap')
    else:assert os.environ.get('GITHUB_ACTIONS')=='true','local compiler bootstrap prohibited'
    sys.path.insert(0,str(ROOT/'source/scripts'))
    from hia_native_build import NativeBuild
    builder=NativeBuild(a.hepta,output);rows={};before=time.monotonic()
    for name in MODULES:
        path=builder.compile(name,ROOT/'source/native'/(name+'.hepta'),standalone=None,buffer_profile='batch-plan.v1')
        raw=path.read_bytes();metadata=json.loads(raw);assert metadata['compiler_sha256']==B3
        rows[name]=dict(manifest=str(path),sha256=hashlib.sha256(raw).hexdigest(),source_sha256=metadata['source_sha256'],image_sha256=metadata['image_sha256'])
    report=dict(status='BUILD_PASS',files=rows,fresh_components=3,reused_components=0,wall_seconds=time.monotonic()-before)
    (output/'build.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
