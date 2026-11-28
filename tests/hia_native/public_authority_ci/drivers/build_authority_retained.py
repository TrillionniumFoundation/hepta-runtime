"""Build an explicitly selected retained authority profile and its fixtures."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--bootstrap',type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    if os.environ.get('CI')!='true':assert a.bootstrap is not None
    out.mkdir(parents=True);start=time.monotonic()
    if a.bootstrap:
        assert SHA((a.bootstrap/'B3.image.bin').read_bytes())=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
        shutil.copytree(a.bootstrap,out/'build/bootstrap')
    sys.path.insert(0,str(source/'scripts'))
    import hia_native_authority_qualification as q
    from hia_native_authority_build import build_authority
    from hia_native_authority_probe_build import build_loader_probe
    from hia_native_scope_build import build_scope
    before=q.source_pins(source);hepta=a.hepta.resolve(strict=True)
    authority=build_authority(hepta,out/'build',source_root=source)
    probe=build_loader_probe(hepta,out/'build',source_root=source)
    scope=build_scope(hepta,out/'build',source_root=source)
    assert q.source_pins(source)==before
    paths=dict(authority=str(authority),probe=str(probe),scope=str(scope))
    put(out/'MANIFESTS.json',paths)
    put(out/'BUILD.json',dict(schema='hepta.public-authority.retained-build.v1',status='PASS',
        source_root=str(source),source_pins=before,profile_sha256=q.PROFILE_SHA,
        manifests={key:dict(path=Path(value).relative_to(out).as_posix(),sha256=SHA(Path(value).read_bytes())) for key,value in paths.items()},
        bootstrap_reused=a.bootstrap is not None,elapsed_seconds=time.monotonic()-start,
        original_rust_executed=False,existing_binary_inputs=False,production_activated=False,old_path_removed=False))
    print(json.dumps(paths,sort_keys=True))

if __name__=='__main__':main()
