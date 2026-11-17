"""Fresh fixed-eight successor owner and unchanged native adapter/packer build.

The new image has no inherited old qualification. Its exact output is checked
against the complete actual same-CI compiler receipt by read_build_fixed8.py.
"""
import argparse,ctypes as C,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import COMPILER,encoded,loads,pin,read,require,source
from hia_native_build import NativeBuild
from hia_native import NativeModule
from pack_contract import inputs,cases

def compiler(hepta,output):
    builder=NativeBuild(hepta,output)
    fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    require(builder.identity==fixed,"complete fixed compiler source")
    require(pin(read(builder.bootstrap()))==dict(bytes=673413,sha256=COMPILER),"actual complete B1/B2/B3")
    return builder,fixed

def record_module(name,source_path,manifest,output):
    image=read(manifest.parent/"module.image.bin")
    return dict(source=pin(read(source_path)),image=pin(image),
        manifest=dict(path=str(manifest.relative_to(output)),**pin(read(manifest))))

def owner(hepta,output):
    identity=source();builder,fixed=compiler(hepta,output)
    expected=loads(read(ROOT/"FIXED8.json"))
    require(pin(read(ROOT/"native/namespace_watcher.hepta"))=={k:expected["owner"][k] for k in ("bytes","sha256")},"exact fixed-eight successor source")
    manifest=builder.compile("namespace-watcher",ROOT/"native/namespace_watcher.hepta",standalone=None)
    row=record_module("namespace-watcher",ROOT/"native/namespace_watcher.hepta",manifest,output)
    require(row["source"]=={k:expected["owner"][k] for k in ("bytes","sha256")},"fresh successor compiles the frozen owner")
    # This new image is derived by the actual pinned compiler; it is not the old image.
    # The pure reader reopens the complete compiler input/output, receipt and image.
    result=dict(schema="hepta.namespace-watcher.callable-owner-build.v1",status="PASS",
        source_manifest_sha256=identity,compiler=fixed,module=row,
        watcher_semantic_executions=0,rust_executions=0)
    (output/"OWNER_BUILD.json").write_bytes(encoded(result))
    require(source()==identity,"whole source unchanged")
    print(encoded(result).decode(),end="")

def emit(manifest,owner_image,proof,output,proof_bytes):
    output.mkdir()
    wire,expected=inputs(owner_image,proof);rows=[]
    with NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"]) as module:
        for name,request,capacity,wanted in cases(wire,len(expected)):
            pi=C.create_string_buffer(request+b"\xc3"*16,len(request)+16)
            po=C.create_string_buffer(b"\xa5"*(capacity+16),capacity+16)
            pw=C.create_string_buffer(bytes(64)+b"\x5a"*16,80)
            before=(pi.raw,po.raw,pw.raw)
            returned=int(module._entry(C.addressof(pi),len(request),C.addressof(po),capacity,C.addressof(pw),64))
            after=(pi.raw,po.raw,pw.raw)
            require(returned==wanted and after[0]==before[0] and after[2]==before[2],
                "actual HIA packer and complete immutable buffers: "+name)
            wanted_output=expected+before[1][len(expected):] if name=="valid" else before[1]
            require(after[1]==wanted_output,"complete actual packed byte/tail: "+name)
            physical={}
            for label,raw in zip(("input-before","output-before","workspace-before","input-after","output-after","workspace-after"),before+after):
                filename=name+"."+label+".bin";(output/filename).write_bytes(raw)
                physical[label]=dict(path=filename,**pin(raw))
            rows.append(dict(name=name,input_bytes=len(request),output_capacity=capacity,
                workspace_capacity=64,returned=returned,files=physical))
    (output/"callable.image.bin").write_bytes(expected)
    result=dict(schema="hepta.namespace-watcher.callable-emission.v1",status="PASS",
        module_manifest=pin(read(manifest)),image=pin(expected),source_composition=pin(proof_bytes),
        calls=rows,native_packer_calls=len(rows),refusals=len(rows)-1)
    (output/"EMISSION.json").write_bytes(encoded(result))
    return expected,result

def packer(hepta,output,authored):
    identity=source();builder,fixed=compiler(hepta,output)
    owner_report=loads(read(output/"OWNER_BUILD.json"))
    require(owner_report["source_manifest_sha256"]==identity,"same-CI owner source")
    proof_bytes=read(authored/"generated/native/namespace_watcher_callable.composition.json")
    proof=loads(proof_bytes)
    require(proof["semantic_source"]==pin(read(ROOT/"native/namespace_watcher.hepta")) and
        proof["adapter_template"]==pin(read(ROOT/"authoring/namespace_watcher_callable.S.in")) and
        proof["author"]==pin(read(ROOT/"authoring/author_callable.py")),"whole native author closure")
    owner_image=read(output/"modules/namespace-watcher/module.image.bin")
    require(pin(owner_image)==proof["owner"]==owner_report["module"]["image"],"same-CI exact owner")
    path=authored/"generated/native/namespace_watcher_callable.hepta"
    require(pin(read(path))==proof["packer_source"],"complete generated packer source")
    manifest=builder.compile("namespace-watcher-callable-packer",path,standalone=None)
    row=record_module("namespace-watcher-callable-packer",path,manifest,output)
    packed,emission=emit(manifest,owner_image,proof,output/"emission",proof_bytes)
    installed=output/"callable";installed.mkdir()
    asm=read(authored/"generated/authoring/namespace_watcher_callable.S")
    (installed/"namespace_watcher_callable.S").write_bytes(asm)
    (installed/"callable.image.bin").write_bytes(packed)
    admission=dict(schema="hepta.runtime.native-module.v1",
        abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1",target="linux-x86_64",
        compiler_commit=fixed["commit"],compiler_sha256=COMPILER,
        source="namespace_watcher_callable.S",source_sha256=pin(asm)["sha256"],
        image="callable.image.bin",image_sha256=pin(packed)["sha256"],
        qualification="private_hia_packer_composition",standalone=None,buffer_profile="standard",
        input_capacity=96,output_capacity=128,workspace_capacity=131072,
        composition_source=pin(proof_bytes))
    (installed/"manifest.json").write_bytes(encoded(admission))
    (installed/"BINDING.json").write_bytes(encoded(dict(proof,callable_image=pin(packed))))
    for name,expected in fixed["files"].items():
        raw=read(hepta/name);require(pin(raw)["sha256"]==expected,"all exact compiler sources")
        dest=output/"compiler-source"/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(raw);dest.chmod(stat.S_IMODE((hepta/name).stat().st_mode))
    require(source()==identity,"whole source unchanged across actual compile/pack")
    result=dict(schema="hepta.namespace-watcher.callable-build.v1",status="PASS",
        source_manifest_sha256=identity,compiler=fixed,
        modules={"namespace-watcher":owner_report["module"],"namespace-watcher-callable-packer":row},
        compiler_image=dict(bytes=673413,sha256=COMPILER),emission=emission,
        authoring=pin(read(authored/"AUTHORING.json")),composition=pin(proof_bytes),
        callable=dict(manifest=pin(read(installed/"manifest.json")),
            binding=pin(read(installed/"BINDING.json")),image=pin(packed)),
        fresh_hia_compile=True,production_hia_owners=1,packer_hia_owners=1,
        watcher_semantic_executions=0,rust_executions=0,namespace_version_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
    (output/"BUILD.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--phase",choices=("owner","packer"),required=True)
    p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--authored",type=Path)
    a=p.parse_args()
    if a.phase=="owner":owner(a.hepta.resolve(strict=True),a.output.absolute())
    else:packer(a.hepta.resolve(strict=True),a.output.resolve(strict=True),a.authored.resolve(strict=True))
