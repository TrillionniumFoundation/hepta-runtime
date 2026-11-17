"""Pack the private observer with the exact members freshly built for public stdio."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys

sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','public','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);public=a.public.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();out.mkdir(parents=True)
    built=json.loads((public/'BUILD.json').read_bytes())
    manifest=public/'build/public-authority-batch/manifest.json';raw=manifest.read_bytes();md=json.loads(raw)
    assert built['status']=='NATIVE_BUILD_PASS' and built['physical_images']==md['physical_images']==102
    assert SHA(raw)==built['manifest_sha256'] and md['private_instance_fixture'] is False
    reuse={row['name']:row['manifest'] for row in md['members']};assert len(reuse)==102
    shutil.copytree(public/'build/bootstrap',out/'build/bootstrap')
    sys.path.insert(0,str(source/'scripts'));from public_nine_build import build_runtime_mcp
    path=build_runtime_mcp(a.hepta.resolve(strict=True),out/'build',name='authority-private',source_root=source,manifests=reuse,private_fixture=True)
    result=json.loads(path.read_bytes());assert all(row['fresh_compile'] is False for row in result['members'])
    assert result['source_binding']==md['source_binding'] and result['physical_images']==102
    report=dict(schema='hepta.public-authority.private-build.v1',status='PASS',
        manifest=path.relative_to(out).as_posix(),manifest_sha256=SHA(path.read_bytes()),
        public_manifest_sha256=SHA(raw),physical_images=102,checked_public_members=102,
        fresh_member_compiles=0,fresh_hia_link_and_pack=True,elf_sha256=result['elf_sha256'],
        public_case_qualification_inherited=False,production_activated=False,old_path_removed=False)
    (out/'BUILD.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
