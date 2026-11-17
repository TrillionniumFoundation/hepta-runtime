"""Fresh authorized-CI original build; no original runtime process is executed here."""
from pathlib import Path
import argparse,json,os,sys,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'reference')]
from common import command,pin,put,require
from source_check import source
from receipt_support import process
import read_reference,reference_controls
def main():
    p=argparse.ArgumentParser()
    for n in ('package','target','rust-bin','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true','original execution only in authorized CI')
    package,target,rust=a.package.resolve(strict=True),a.target.resolve(strict=True),a.rust_bin.resolve(strict=True)
    out=a.output.resolve();require(not out.exists(),'new reference gate already attempted');out.mkdir()
    admitted=source(package,a.manifest_sha256,True);before=pin(target/'Cargo.lock')
    origin={'schema':'hepta.runtime.public-extract-reference-build.v1','status':'RUNNING','source':str(package),'target':str(target),'rust_bin':str(rust),'capture':str(out),'python':sys.executable,'source_manifest_sha256':a.manifest_sha256,'source_admission':admitted,'native_runtime_executions':0,'original_runtime_executions':0,'whole_runtime_replaced':False}
    put(out/'ORIGIN.json',origin)
    try:
        environment={'PYTHONPATH':''}
        process(out/'processes','target-prefetch',[rust/'cargo','fetch','--locked'],cwd=target,env=environment,timeout=180)
        process(out/'processes','original-build',[sys.executable,'-I','-S','-B',package/'reference/build_reference.py','--rust-bin',rust,'--target',target,'--core',package/'reference/core','--output',out/'original'],cwd=out,env=environment,timeout=180)
        require(pin(target/'Cargo.lock')==before,'exact target lock changed during prefetch/build')
        read_reference.original(out/'original',package/'reference')
        reference_controls.create(out/'original',package/'reference',out/'reader-controls')
        put(out/'CORE_READY.json',{**origin,'status':'CORE_COMPLETE'})
        command(out,'guarded-read',[sys.executable,'-I','-S','-B',package/'ci/read_gate.py','--package',package,'--capture',out,'--manifest-sha256',a.manifest_sha256])
        report=json.loads((out/'processes/guarded-read.stdout').read_bytes())
        require(report['evidence']['status']=='FRESH_EXTRACT_REFERENCE_COMPLETE_BUILD_READ_PASS','complete guarded original evidence')
        put(out/'QUALIFICATION.json',report['evidence']);print(json.dumps(report['evidence'],sort_keys=True))
    except BaseException as error:
        put(out/'FAILURE.json',{'status':'FAIL','error':repr(error),'traceback':traceback.format_exc(),'deadline_raised':False,'domain_reduced':False});raise
if __name__=='__main__':main()
