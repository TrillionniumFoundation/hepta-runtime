"""Fresh compiler build and source-only callable packing recipe generation."""
import argparse,importlib.util,json,shutil,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import source,read,pin,require,encoded
from hia_native_build import NativeBuild
def run(hepta,owner,output):
    identity=source()
    builder=NativeBuild(hepta,output)
    expected=json.loads(read(ROOT/"COMPILER_IDENTITY.json"))
    require(builder.identity==expected,"complete compiler identity")
    b3=builder.bootstrap()
    require(pin(read(b3))==dict(bytes=673413,sha256="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"),"fixed B3")
    modules={}
    for name,path in (("audit-anchor-publish",owner/"audit_anchor_publish.hepta"),("audit-json",ROOT/"imports/audit_json.hepta")):
        manifest=builder.compile(name,path,standalone=None)
        modules[name]=dict(source=pin(read(path)),manifest=dict(path=str(manifest.relative_to(output)),**pin(read(manifest))),
            image=pin(read(manifest.parent/"module.image.bin")))
    packroot=output/"pack-input"
    (packroot/"authoring").mkdir(parents=True)
    (packroot/"imports").mkdir()
    size=modules["audit-anchor-publish"]["image"]["bytes"]
    template=read(ROOT/"authoring/audit_anchor_publish_callable.S.in")
    require(template.count(b"@OWNER_BYTES@")==1,"one exact image extent")
    (packroot/"authoring/audit_anchor_publish_callable.S").write_bytes(template.replace(b"@OWNER_BYTES@",str(size).encode()))
    (packroot/"imports/audit_anchor_publish.hepta").write_bytes(read(owner/"audit_anchor_publish.hepta"))
    (packroot/"imports/audit_json.hepta").write_bytes(read(ROOT/"imports/audit_json.hepta"))
    for name,digest in expected["files"].items():
        path=hepta/name;body=read(path);require(pin(body)["sha256"]==digest,"retained complete compiler source")
        destination=output/"compiler-source"/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(body);destination.chmod(stat.S_IMODE(path.stat().st_mode))
    require(source()==identity,"frozen source after build")
    result=dict(schema="hepta.audit-anchor-publish.prepare.v1",source_sha256=identity,compiler=expected,
        modules=modules,owner_source_semantic_executions=0,rust_executions=0,
        matching_source_cold_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    (output/"BUILD.json").write_bytes(encoded(result))
    print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--hepta",type=Path,required=True);p.add_argument("--owner",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.owner.resolve(strict=True),a.output.absolute())
