"""Fresh compiler-only build of the original namespace policy HIA owner."""
import argparse,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,pin,read,require,source,COMPILER
from hia_native_build import NativeBuild
def run(hepta,authored,output):
    identity=source();builder=NativeBuild(hepta,output);fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    require(builder.identity==fixed,"all fixed compiler sources")
    image=builder.bootstrap();require(pin(read(image))==dict(bytes=673413,sha256=COMPILER),"actual complete B1/B2/B3")
    path=authored/"namespace_versions.hepta"
    composition=loads(read(authored/"namespace_versions.composition.json"))
    require(composition["source"]["sha256"]==pin(read(path))["sha256"],"exact authored HIA policy")
    manifest=builder.compile("namespace-versions",path,standalone=None)
    module=dict(source=pin(read(path)),image=pin(read(manifest.parent/"module.image.bin")),
        manifest=dict(path=str(manifest.relative_to(output)),**pin(read(manifest))))
    for name,digest in fixed["files"].items():
        raw=read(hepta/name);require(pin(raw)["sha256"]==digest,"whole exact compiler source")
        dest=output/"compiler-source"/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(raw);dest.chmod(stat.S_IMODE((hepta/name).stat().st_mode))
    require(source()==identity,"all frozen source unchanged")
    result=dict(schema="hepta.namespace-versions.owner-build.v1",status="PASS",source_manifest_sha256=identity,
        compiler=fixed,module=module,composition=pin(read(authored/"namespace_versions.composition.json")),
        native_application_calls=0,original_application_calls=0,namespace_version_qualified=False,public_handler_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("hepta","authored","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.authored.resolve(strict=True),a.output.absolute())
