"""Reproduce native-produced literals and build both fixed catalog images."""
import argparse
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
import author_slot0
from read_static_build import build_check

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for key in ('hepta','projection-build','projection-capture','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--bootstrap',type=Path)
    a=p.parse_args();out=a.output.absolute();c.source_check();out.mkdir(parents=True,exist_ok=False)
    proof=author_slot0.generate(a.hepta.resolve(strict=True),ROOT/'pipeline',a.projection_build.resolve(strict=True),a.projection_capture.resolve(strict=True),out/'reproduced')
    for name in ('runtime_mcp_catalog_eleven.hepta','catalog_eleven.pseudo','catalog-mode-0.bin','catalog-mode-1.bin','catalog-common.lzss'):
        assert (out/'reproduced'/name).read_bytes()==(ROOT/'native'/name).read_bytes()
    expected=__import__('json').loads((ROOT/'native/catalog-eleven-composition.json').read_bytes())
    assert {k:v for k,v in proof.items() if k!='pipeline_result_sha256'}=={k:v for k,v in expected.items() if k!='pipeline_result_sha256'}
    if a.bootstrap:
        (out/'bootstrap').mkdir();r=c.BASE.Reader(a.bootstrap.resolve(strict=True))
        for name in ('bootstrap.json','B1.image.bin','B2.image.bin','B3.image.bin'):c.put(out/'bootstrap'/name,r.raw(name))
    else:assert os.environ.get('GITHUB_ACTIONS')=='true'
    sys.path.insert(0,str(ROOT/'pipeline/policy_base/runtime_support/scripts'))
    from hia_native_build import NativeBuild
    builder=NativeBuild(a.hepta.resolve(strict=True),out)
    for name,(path,expected,profile) in c.source_pins().items():
        assert c.sha((ROOT/path).read_bytes())==expected
        builder.compile(name,ROOT/path,standalone=None,buffer_profile=profile)
    _,modules=build_check(out,ROOT)
    c.put(out/'static-build.json',{'status':'PASS','modules':modules,'copied_qualified_bootstrap':a.bootstrap is not None,
        'source_profile':c.pin((ROOT/'source-profile.json').read_bytes()),'fresh_original_build':False})
    print(c.encoded({'status':'PASS','modules':modules}).decode())
