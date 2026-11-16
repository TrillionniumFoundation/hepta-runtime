"""Reproduce both new HIA sources and compile their exact private components."""
import argparse
import os
from pathlib import Path
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import configured_common as c
import author_configured
import author_frontend


def build(hepta, output, bootstrap=None):
    c.source_check(ROOT)
    output.mkdir(parents=True,exist_ok=False)
    for label,author,names in [
        ("catalog",author_configured,("runtime_mcp_catalog_configured.hepta","catalog_configured.pseudo","catalog_configured_composition.json")),
        ("frontend",author_frontend,("runtime_mcp.hepta","catalog_frontend.pseudo","catalog_frontend_composition.json"))]:
        author.generate(hepta,ROOT,output/"reproduced"/label)
        for name in names:
            assert (output/"reproduced"/label/name).read_bytes()==(ROOT/"native"/name).read_bytes(),name
    if bootstrap is not None:
        r=c.BASE.Reader(bootstrap);(output/"bootstrap").mkdir()
        for name in ("bootstrap.json","B1.image.bin","B2.image.bin","B3.image.bin"):
            c.put(output/"bootstrap"/name,r.raw(name))
    else:
        assert os.environ.get("GITHUB_ACTIONS")=="true","local builds require the admitted compiler cache"
    support=ROOT/"retained/pipeline/policy_base/runtime_support/scripts"
    sys.path.insert(0,str(support))
    from hia_native_build import NativeBuild
    builder=NativeBuild(hepta,output)
    for name,(path,expected,profile) in c.MODULES.items():
        assert c.sha((ROOT/path).read_bytes())==expected
        builder.compile(name,ROOT/path,standalone=None,buffer_profile=profile)
    _,modules=c.build_check(output,ROOT)
    result={"status":"FRESH_CONFIGURED_COMPONENT_BUILD_PASS","modules":modules,
        "source_profile":c.pin((ROOT/"source-profile.json").read_bytes()),
        "copied_qualified_bootstrap":bootstrap is not None,"local_rust_execution":False,
        "public_packed_graph_qualified":False}
    c.put(output/"configured-build.json",result)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser()
    for key in ("hepta","output"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--bootstrap",type=Path)
    a=p.parse_args()
    print(c.encoded(build(a.hepta.resolve(strict=True),a.output.absolute(),a.bootstrap.resolve(strict=True) if a.bootstrap else None)).decode())
