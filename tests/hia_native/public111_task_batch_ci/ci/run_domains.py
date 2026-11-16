"""Execute split current-owner, retained-profile, public-owner, and connection jobs."""
from pathlib import Path
import argparse,json,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import command,put,require,pin
from domain_support import begin,finish,doc
import read_build

def write_module_map(build):
    """One additive observer index outside every preexisting artifact inventory."""
    origin=doc(build/"BUILD_ORIGIN.json");producer=Path(origin["output"])
    rows={}
    for label in ("production/build/public-task-batch","instances/task-pump"):
        md=doc(build/label/"manifest.json")
        for item in [*md["members"],md["link"],md["pack"]]:
            path=Path(item["manifest"]);relative=path.relative_to(producer)
            require((build/relative).is_file(),"actual module outside same-CI build")
            rows[str(path)]=relative.as_posix()
        name=Path(md["packed_capabilities"]["57"]["build_root"])/"bellman-port-packed.elf"
        relative=name.relative_to(producer);require((build/relative).is_file(),"complete packed capability absent")
        rows[str(name)]=relative.as_posix()
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",choices=("owner","profiles","authority","connection"),required=True)
    for name in ("package","output"):p.add_argument("--"+name,type=Path,required=True)
    for name in ("hepta","build","owner","build-receipt","owner-receipt","sdk-source","rust-bin","get-info-reference"):
        p.add_argument("--"+name,type=Path)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    deps={}
    for name in ("build","owner"):
        if getattr(a,name) is not None:
            receipt=getattr(a,name+"_receipt")
            require(receipt is not None,"complete dependency receipt missing")
            deps[name]=(getattr(a,name),receipt)
    details={n:str(getattr(a,n).resolve(strict=True)) for n in ("hepta","sdk_source","rust_bin","get_info_reference")
        if getattr(a,n) is not None}
    package,out,origin=begin(a.package,a.output,a.manifest_sha256,a.role,deps,details)
    source=package/"joint/authority";drivers=source/"drivers";adapt=package/"ci/authority"
    py=[sys.executable,"-I","-S","-B"]
    def run(label,script,args):return command(out,label,py+[str(script),*map(str,args)])
    try:
        if a.build:
            build=a.build.resolve(strict=True);read_build.prepare(package)
            proof=read_build.verify_build(package,build,a.manifest_sha256)
            require(proof["runtime_hia_images"]==111 and proof["fresh_direct_members"]==103,"actual default graph")
        if a.role=="owner":
            require(a.hepta is not None,"exact Hepta required")
            run("owner-current243",source/"owner-reference/tests/hia_native/caller_owner_export/qualify.py",
                ["--phase","all","--source-root",source/"owner-reference","--hepta",a.hepta,"--output",out/"owner-v4"])
        elif a.role=="profiles":
            require(a.hepta is not None and a.build is not None,"profile dependencies")
            for label,sub,runner in (("current","authority-retained","run_authority_retained.py"),
                                     ("historical","authority-historical","run_authority_historical.py")):
                run(label+"-build",drivers/"build_authority_retained.py",
                    ["--source",source/sub,"--hepta",a.hepta,"--bootstrap",build/"production/build/bootstrap",
                     "--output",out/(label+"-build")])
                args=["--source",source/sub,"--manifests",out/(label+"-build/MANIFESTS.json"),"--output",out/label]
                if label=="current":args+=["--hepta",a.hepta]
                run(label+"-groups",drivers/runner,args)
        else:
            require(a.build is not None,"actual graph dependency")
            # The portable mapping lives under a new sibling view containing only
            # copied, admitted module files. It never edits the dependency archive.
            maproot=out/"graph-view";maproot.mkdir()
            rows=write_module_map(build)
            import shutil
            for relative in sorted(set(rows.values())):
                original=build/relative
                if original.name=="manifest.json":
                    root=original.parent
                    for item in root.iterdir():
                        if item.is_file():
                            dest=maproot/item.relative_to(build);dest.parent.mkdir(parents=True,exist_ok=True)
                            if not dest.exists():shutil.copyfile(item,dest);dest.chmod(item.stat().st_mode&0o777)
                else:
                    dest=maproot/relative;dest.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(original,dest);dest.chmod(original.stat().st_mode&0o777)
            put(maproot/"module-map.json",{"schema":"hepta.public-authority.portable-module-map.v1","modules":rows})
            put(out/"module-map.json",{"schema":"hepta.public-authority.portable-module-map.v1",
                "modules":{k:"graph-view/"+v for k,v in rows.items()}})
            if a.role=="authority":
                require(a.owner is not None,"current owner original dependency")
                private=build/"instances/task-pump/manifest.json"
                run("native-private-binding",adapt/"capture_private_binding.py",
                    ["--source",package/"graph/source","--manifest",private,"--output",out/"private-binding"])
                run("private-readonly",adapt/"verify_private_readonly.py",
                    ["--source",package/"graph/source","--manifest",private,"--capture",out/"private-binding",
                     "--module-map",out/"module-map.json"])
                run("current-public-owner16",adapt/"public_owner_reference.py",
                    ["--source",package/"graph/source","--manifest",private,"--capture",out/"private-binding",
                     "--owner-output",a.owner.resolve(strict=True)/"owner-v4","--output",out/"public-owner-reference",
                     "--module-map",out/"module-map.json"])
            else:
                require(all(getattr(a,n) is not None for n in ("hepta","sdk_source","rust_bin","get_info_reference")),
                    "complete connection reference dependencies")
                run("retained62",source/"transport-reference/drivers/build_retained_eight.py",
                    ["--sdk-source",a.sdk_source,"--hepta",a.hepta,"--output",out/"retained-eight"])
                run("normal-corpus",drivers/"transport_cases.py",["--output",out/"transport-inputs"])
                run("native-framing24",adapt/"capture_transport_native.py",
                    ["--build",build/"production","--cases",out/"transport-inputs","--output",out/"native-framing"])
                run("fresh-original28",source/"transport-reference/drivers/run_transport_reference.py",
                    ["--source",source/"transport-reference","--cases",out/"transport-inputs","--native",out/"native-framing",
                     "--rust-bin",a.rust_bin,"--output",out/"transport-reference"])
                run("fresh-original54",source/"handshake-reference/scripts/run_reference.py",
                    ["--source",source/"handshake-reference","--rust-bin",a.rust_bin,"--output",out/"handshake-reference"])
                run("native-handshake54",drivers/"capture_handshake.py",
                    ["--source",source/"handshake-reference","--build",build/"production","--output",out/"native-handshake"])
                baseline=doc(out/"retained-eight/BUILD.json")
                run("public90",adapt/"qualify_public.py",
                    ["--source",package/"graph/source","--manifest",build/"production/build/public-task-batch/manifest.json",
                     "--baseline-elf",baseline["elf"],"--get-info-reference",a.get_info_reference,"--output",out/"public-loop"])
        extra=[]
        for name in ("build","owner"):
            if getattr(a,name) is not None:extra+=["--"+name,str(getattr(a,name).resolve(strict=True))]
        finish(package,out,a.manifest_sha256,a.role,extra)
    except BaseException as e:
        put(out/"FAILURE.json",{"role":a.role,"status":"FAIL","error":repr(e),"traceback":traceback.format_exc(),
            "domain_reduced":False,"deadline_raised":False});raise
if __name__=="__main__":main()
