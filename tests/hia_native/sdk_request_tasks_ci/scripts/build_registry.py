"""Compile the registry and exact current G1 child with the pinned HIA compiler."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, sys
sys.dont_write_bytecode=True
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--bootstrap',type=Path);a=p.parse_args()
    source=a.source.resolve(strict=True);output=a.output.absolute();assert not output.exists()
    if os.environ.get('CI')!='true':assert a.bootstrap is not None,'A verified B3 copy is required locally.'
    output.mkdir(parents=True)
    if a.bootstrap:
        b=a.bootstrap.resolve(strict=True)
        assert hashlib.sha256((b/'B3.image.bin').read_bytes()).hexdigest()=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
        shutil.copytree(b,output/'build/bootstrap')
    sys.path.insert(0,str(source/'scripts'));from hia_native_build import NativeBuild
    build=NativeBuild(a.hepta.resolve(strict=True),output/'build');members={}
    for name,filename,profile in [('request-tasks','sdk_request_task_registry.hepta','history.v1'),
            ('request-tasks-message','sdk_message_target.hepta','sdk-message-target.v1')]:
        path=build.compile(name,source/'native'/filename,standalone=None,buffer_profile=profile)
        raw=path.read_bytes();members[name]=dict(manifest=str(path.relative_to(output)),
            manifest_sha256=hashlib.sha256(raw).hexdigest(),metadata=json.loads(raw))
    receipt=dict(schema='hepta.sdk-request-tasks.build.v1',status='PASS',members=members,
        fresh_member_compiles=2,reused_candidate_members=0,bootstrap_reused=a.bootstrap is not None,
        independent_cold_qualified=False,rust_executed=False,public_registry_integrated=False,
        full_async_runtime_qualified=False,full_sdk_qualified=False,production_activated=False,old_path_removed=False)
    (output/'BUILD.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
