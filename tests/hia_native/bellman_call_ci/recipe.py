"""Rebuild and observe the entire private caller with one shared real worker."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from process_capture import run,put
PINS='1cd154ed65c8b1478f29f4eb9d9835f8076f65932359c29c29d43649b07937db'
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert os.environ.get('GITHUB_ACTIONS')=='true','complete original execution is restricted to CI'
    output=a.output.resolve();output.mkdir(mode=0o700);hepta=a.hepta.resolve(strict=True)
    source=(ROOT/'package-manifest.json').read_bytes();manifest=json.loads(source)
    for name,pin in manifest['files'].items():
        body=(ROOT/name).read_bytes();assert len(body)==pin['bytes'] and hashlib.sha256(body).hexdigest()==pin['sha256'],name
    shutil.copytree(ROOT,output/'recipe-source')
    env=dict(os.environ);env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',RUSTUP_TOOLCHAIN='1.95.0')
    python=[sys.executable,'-I','-S','-B'];started=time.monotonic()
    result=dict(status='RUNNING',source_manifest={'bytes':len(source),'sha256':hashlib.sha256(source).hexdigest()},
        public_handler_qualified=False,whole_runtime_replaced=False,original_source_unchanged=True)
    try:
        run(output,'worker-build',python+[str(ROOT/'worker-source/tests/hia_native/blocking_worker/worker_build.py'),
            '--source-root',str(ROOT/'worker-source'),'--hepta',str(hepta),'--capture',str(output/'worker-build'),
            '--source-pins-sha256',PINS],env,limit=180)
        run(output,'caller-build',python+[str(ROOT/'build.py'),'--hepta',str(hepta),'--output',str(output/'caller-build'),
            '--bootstrap-cache',str(output/'worker-build/build/bootstrap')],env,limit=60)
        run(output,'original',python+[str(ROOT/'observe_full_original.py'),'--output',str(output/'original')],env,limit=600)
        shared=['--build',str(output/'caller-build'),'--reference',str(output/'original/typed'),'--bridge',str(output/'worker-build/bridge')]
        for group,limit in [('ordinary',300),('unicode',120)]:
            run(output,group,python+[str(ROOT/'observe.py'),*shared,'--output',str(output/group),'--group',group],env,limit=limit)
        run(output,'controls',python+[str(ROOT/'controls.py'),*shared,'--output',str(output/'controls')],env,limit=120)
        args=['--package',str(ROOT),'--build',str(output/'caller-build'),'--ordinary',str(output/'ordinary'),
            '--unicode',str(output/'unicode'),'--original-package',str(ROOT),'--original',str(output/'original'),
            '--controls-package',str(ROOT),'--controls',str(output/'controls'),'--bridge',str(output/'worker-build/bridge')]
        run(output,'readonly',python+[str(ROOT/'readonly.py'),*args],env,limit=180)
        proof=json.loads((output/'processes/readonly.stdout').read_bytes())
        assert proof['status']=='READ_ONLY_CALLER683_AND_FRESH_ORIGINAL_PASS' and proof['physical_source_and_evidence_unchanged'] is True
        assert proof['original']['complete_original_typed_cases']==proof['original']['cases']==683
        result.update(status='FRESH_PRIVATE_CALLER_ORIGINAL683_AND_LIFECYCLE_PASS',read_only=proof,
            runtime_images=8,reference_images=2,packer_images=1,caller_controls=60,lifecycle_groups=7)
    except BaseException as exc:
        result.update(status='FAIL',failure={'type':type(exc).__name__,'message':str(exc)});raise
    finally:
        result['wall_seconds']=time.monotonic()-started;put(output/'run.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='read_only'},sort_keys=True))
if __name__=='__main__':main()
