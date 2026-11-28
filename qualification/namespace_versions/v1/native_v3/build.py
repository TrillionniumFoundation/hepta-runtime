"""Fresh native compiler and HIA packers only. No namespace application calls."""
import argparse,ctypes as C,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import COMPILER,encoded,loads,pin,read,require,source
from hia_native_build import NativeBuild
from hia_native import NativeModule
from pack_contract import inputs,cases,child_inputs,child_cases
MODULES={"namespace-versions":"native/namespace_versions.hepta","namespace-watcher":"imports/namespace_watcher.hepta",
    "namespace-fingerprint":"imports/namespace_fingerprint.hepta","namespace-watcher-packer":"imports/namespace_watcher_callable.hepta",
    "namespace-fingerprint-packer":"imports/namespace_fingerprint_callable.hepta"}
PINNED_IMAGES={"namespace-versions":dict(bytes=160201,sha256="024f0f5160fcd4e2ee6c7ec7e5d235f734472512c51d73e9974e68fcc6493382"),
    "namespace-watcher":dict(bytes=144716,sha256="bf568cbea25436d2deff6ec210cd707cc73230005d71e6576d2e873f6105321b"),
    "namespace-fingerprint":dict(bytes=104516,sha256="0e4153a7f4e99b09139ec1ff2cfc1a26a6b5f6234159be38219e727215ac31b0")}
def start(hepta,output):
    b=NativeBuild(hepta,output);fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    require(b.identity==fixed,"all exact fresh compiler sources")
    require(pin(read(b.bootstrap()))==dict(bytes=673413,sha256=COMPILER),"actual complete B1/B2/B3")
    return b,fixed
def module_record(path,manifest,output):
    return dict(source=pin(read(path)),image=pin(read(manifest.parent/"module.image.bin")),
        manifest=dict(path=manifest.relative_to(output).as_posix(),**pin(read(manifest))))
def emit(manifest,wire,expected,plan,folder,composition):
    folder.mkdir(parents=True,exist_ok=False);rows=[]
    with NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"])as m:
        for name,request,capacity,wanted in plan:
            pi=C.create_string_buffer(request+b"\xc3"*16,len(request)+16)
            po=C.create_string_buffer(b"\xa5"*(capacity+16),capacity+16)
            pw=C.create_string_buffer(bytes(64)+b"\x5a"*16,80)
            before=(pi.raw,po.raw,pw.raw)
            returned=int(m._entry(C.addressof(pi),len(request),C.addressof(po),capacity,C.addressof(pw),64))
            after=(pi.raw,po.raw,pw.raw);physical={}
            for label,raw in zip(("input-before","output-before","workspace-before","input-after","output-after","workspace-after"),before+after):
                filename=name+"."+label+".bin";(folder/filename).write_bytes(raw);physical[label]=dict(path=filename,**pin(raw))
            rows.append(dict(name=name,input_bytes=len(request),output_capacity=capacity,workspace_capacity=64,returned=returned,files=physical))
            (folder/"EMISSION.json").write_bytes(encoded(dict(schema="hepta.namespace-versions.packer-emission.v1",status="IN_PROGRESS",
                module_manifest=pin(read(manifest)),source_composition=pin(composition),image=pin(expected),calls=rows)))
            require(returned==wanted and after[0]==before[0]and after[2]==before[2],"actual complete immutable packing buffers: "+name)
            require(after[1]==(expected+before[1][len(expected):]if name=="valid"else before[1]),"every emitted byte/tail: "+name)
    (folder/"callable.image.bin").write_bytes(expected)
    result=dict(schema="hepta.namespace-versions.packer-emission.v1",status="PASS",module_manifest=pin(read(manifest)),
        source_composition=pin(composition),image=pin(expected),calls=rows,packer_calls=len(rows),packer_refusals=len(rows)-1)
    (folder/"EMISSION.json").write_bytes(encoded(result));return result
def dependencies(hepta,output):
    identity=source();b,fixed=start(hepta,output);modules={}
    for name,relative in MODULES.items():
        path=ROOT/relative;manifest=b.compile(name,path,standalone=None);modules[name]=module_record(path,manifest,output)
    require(modules["namespace-versions"]["image"]==PINNED_IMAGES["namespace-versions"],"exact previously compiled namespace HIA policy")
    emissions={}
    for name in("namespace-watcher","namespace-fingerprint"):
        proofraw=read(ROOT/("imports/"+name.replace("-","_")+"_callable.composition.json"));proof=loads(proofraw)
        owner=read(output/"modules"/name/"module.image.bin");wire,expected=child_inputs(owner,proof,name)
        require(pin(expected)==PINNED_IMAGES[name],"exact independently source-built child image")
        emissions[name]=emit(output/"modules"/(name+"-packer")/"manifest.json",wire,expected,child_cases(wire,len(expected)),
            output/"dependencies"/name,proofraw)
    require(source()==identity,"whole frozen source unchanged")
    result=dict(schema="hepta.namespace-versions.dependencies-build.v1",status="PASS",source_manifest_sha256=identity,
        compiler=fixed,modules=modules,emissions=emissions,native_application_calls=0,original_application_calls=0)
    (output/"DEPENDENCIES.json").write_bytes(encoded(result));print("DEPENDENCIES_BUILD "+str({n:r["image"]for n,r in modules.items()}))
def packer(hepta,output,authored):
    identity=source();b,fixed=start(hepta,output);prior=loads(read(output/"DEPENDENCIES.json"))
    require(prior["source_manifest_sha256"]==identity and prior["compiler"]==fixed,"same actual source/compiler")
    proofraw=read(authored/"generated/native/namespace_versions_callable.composition.json");proof=loads(proofraw)
    sourcepath=authored/"generated/native/namespace_versions_callable.hepta"
    require(pin(read(sourcepath))==proof["packer_source"],"whole authored HIA packer")
    manifest=b.compile("namespace-versions-packer",sourcepath,standalone=None)
    modules=dict(prior["modules"]);modules["namespace-versions-packer"]=module_record(sourcepath,manifest,output)
    images={"namespace-versions":read(output/"modules/namespace-versions/module.image.bin"),
        "namespace-watcher":read(output/"dependencies/namespace-watcher/callable.image.bin"),
        "namespace-fingerprint":read(output/"dependencies/namespace-fingerprint/callable.image.bin")}
    wire,expected=inputs(images,proof);emission=emit(manifest,wire,expected,cases(wire,len(expected)),output/"emission",proofraw)
    installed=output/"callable";installed.mkdir()
    asm=read(authored/"generated/authoring/namespace_versions_callable.S")
    (installed/"namespace_versions_callable.S").write_bytes(asm);(installed/"callable.image.bin").write_bytes(expected)
    admission=dict(schema="hepta.runtime.native-module.v1",abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1",target="linux-x86_64",
        compiler_commit=fixed["commit"],compiler_sha256=COMPILER,source="namespace_versions_callable.S",source_sha256=pin(asm)["sha256"],
        image="callable.image.bin",image_sha256=pin(expected)["sha256"],qualification="private_hia_packer_composition",standalone=None,
        buffer_profile="standard",input_capacity=4224,output_capacity=192,workspace_capacity=4096,composition_source=pin(proofraw))
    (installed/"manifest.json").write_bytes(encoded(admission));(installed/"BINDING.json").write_bytes(encoded(dict(proof,callable_image=pin(expected))))
    for name,digest in fixed["files"].items():
        raw=read(hepta/name);require(pin(raw)["sha256"]==digest,"every fixed compiler source")
        dest=output/"compiler-source"/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
        dest.chmod(stat.S_IMODE((hepta/name).stat().st_mode))
    require(source()==identity,"all source unchanged after actual compile/pack")
    result=dict(schema="hepta.namespace-versions.callable-build.v1",status="PASS",source_manifest_sha256=identity,compiler=fixed,
        modules=modules,dependencies=prior["emissions"],emission=emission,composition=pin(proofraw),authoring=pin(read(authored/"AUTHORING.json")),
        callable=dict(image=pin(expected),manifest=pin(read(installed/"manifest.json")),binding=pin(read(installed/"BINDING.json"))),
        fresh_semantic_hia_images=3,fresh_packer_hia_images=3,native_application_calls=0,original_application_calls=0,
        namespace_version_qualified=False,public_handler_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(result));print("CALLABLE_BUILD "+str(result["callable"]))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--phase",choices=("dependencies","packer"),required=True)
    for name in("hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--authored",type=Path);a=p.parse_args()
    if a.phase=="dependencies":dependencies(a.hepta.resolve(strict=True),a.output.absolute())
    else:packer(a.hepta.resolve(strict=True),a.output.resolve(strict=True),a.authored.resolve(strict=True))
