"""Inert complete compiler, GAS, packer and flat-image evidence reader."""
import argparse,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import COMPILER,encoded,loads,pin,read,require,sha,files,source
from original_build_invocation import invocation
from pack_contract import inputs,cases

EXPORTS={name:"namespace_watcher_"+name for name in ("entry","initialize","bind","dispose","owner","end")}
EXPORTS.update({name:"namespace_file_"+name for name in ("pin_adopt","pin_clone","pin_release")})

def verify(build,authored,symbolic):
    identity=source();fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    report=loads(read(build/"BUILD.json"));owner_report=loads(read(build/"OWNER_BUILD.json"))
    proof_raw=read(authored/"generated/native/namespace_watcher_callable.composition.json")
    proof=loads(proof_raw);author=loads(read(authored/"AUTHORING.json"))
    bootstrap=loads(read(build/"bootstrap/bootstrap.json"))
    require(report["schema"]=="hepta.namespace-watcher.callable-build.v1" and report["status"]=="PASS"
        and report["source_manifest_sha256"]==owner_report["source_manifest_sha256"]==identity
        and report["compiler"]==owner_report["compiler"]==bootstrap["dependency"]==fixed,"complete source/compiler closure")
    expected_source=loads(read(ROOT/"FIXED8.json"))
    require(pin(read(ROOT/"native/namespace_watcher.hepta"))=={k:expected_source["owner"][k] for k in ("bytes","sha256")},"frozen exact fixed-eight source")
    require(proof["semantic_source"]==pin(read(ROOT/"native/namespace_watcher.hepta"))
        and proof["owner"]==owner_report["module"]["image"]
        and proof["adapter_template"]==pin(read(ROOT/"authoring/namespace_watcher_callable.fixed9.S.in"))
        and proof["author"]==pin(read(ROOT/"authoring/author_callable.py")),"complete native author source")
    require(author["schema"]=="hepta.namespace-watcher-callable.authoring.v1" and author["status"]=="SOURCE_ONLY_PASS"
        and author["source"]==proof and report["authoring"]==pin(read(authored/"AUTHORING.json"))
        and report["composition"]==pin(proof_raw),"exact generated proof/report")
    retained=files(build/"compiler-source")
    require(len(retained)==1080 and set(retained)==set(fixed["files"]),"all fixed compiler source files")
    for name,row in retained.items():require(row["sha256"]==fixed["files"][name],"complete compiler source: "+name)
    require(read(build.parent/"fixed8-author/PROOF.json")==encoded(symbolic),"full independent symbolic fixed-eight proof")
    require(read(build.parent/"fixed8-author/baseline-reproduced/namespace_watcher.hepta")==read(ROOT/"baseline/namespace_watcher.hepta")
        and read(build.parent/"fixed8-author/baseline-reproduced/namespace_watcher.composition.json")==read(ROOT/"baseline/namespace_watcher.composition.json"),"whole original source reproduction")
    require(bootstrap["schema"]=="hepta.runtime.native-bootstrap.v1"
        and bootstrap["qualification"]=="development_fixed_point"
        and bootstrap["matching_source_cold_qualified"] is False
        and bootstrap["generation_sha256"]==COMPILER,"precise bootstrap qualification")
    folder=build/"bootstrap";compiler_source=read(build/"compiler-source/examples/hia_bootstrap/selfhost.hepta")
    require(bootstrap["compiler_source_sha256"]==sha(compiler_source),"complete compiler input")
    images=[read(folder/(label+".image.bin")) for label in ("B1","B2","B3")]
    require(all(pin(raw)==dict(bytes=673413,sha256=COMPILER) for raw in images),"all actual B1/B2/B3 bytes")
    previous=read(folder/Path(loads(read(folder/"B1.request.json"))["image"]).name)
    for i,label in enumerate(("B1","B2","B3")):
        receipt=invocation(folder,label,compiler_source,previous,images[i],"seed-shared" if i==0 else "flat-x86-64")
        require(receipt==bootstrap["generation_receipts"][i],"complete actual bootstrap receipt")
        previous=images[i]
    modules={"namespace-watcher":ROOT/"native/namespace_watcher.hepta",
        "namespace-watcher-callable-packer":authored/"generated/native/namespace_watcher_callable.hepta"}
    require(set(report["modules"])==set(modules),"one runtime HIA owner and one packer")
    compiled={}
    for name,path in modules.items():
        module=build/"modules"/name;raw=read(path);image=read(module/"module.image.bin")
        manifest=loads(read(module/"manifest.json"));row=report["modules"][name]
        require(read(module/(name+".hepta"))==raw and manifest["source"]==name+".hepta"
            and manifest["source_sha256"]==sha(raw) and manifest["image"]=="module.image.bin"
            and manifest["image_sha256"]==sha(image) and manifest["compiler_sha256"]==COMPILER
            and manifest["compiler_commit"]==fixed["commit"] and manifest["standalone"] is None
            and manifest["schema"]=="hepta.runtime.native-module.v1"
            and manifest["abi"]=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
            and manifest["target"]=="linux-x86_64" and manifest["qualification"]=="development_fixed_point"
            and manifest.get("buffer_profile","standard")=="standard"
            and [manifest[k] for k in ("input_capacity","output_capacity","workspace_capacity")]==[8<<20,8<<20,32<<20],
            "entire actual native module manifest")
        receipt=invocation(module,"module",raw,images[-1],image,"flat-x86-64")
        record=loads(read(module/"build.json"))
        require(record["compiler_dependency"]==fixed and record["compile_receipt"]==receipt
            and record["whole_runtime_replaced"] is False,"full actual compiler receipt")
        require(row==dict(source=pin(raw),image=pin(image),
            manifest=dict(path="modules/"+name+"/manifest.json",**pin(read(module/"manifest.json")))),
            "whole actual module record")
        compiled[name]=image
    require(owner_report["module"]==report["modules"]["namespace-watcher"]
        and pin(compiled["namespace-watcher"])==proof["owner"],"same-CI actual owner not replaced")
    template=read(ROOT/"authoring/namespace_watcher_callable.fixed9.S.in")
    asm=template.replace(b"@OWNER_BYTES@",str(len(compiled["namespace-watcher"])).encode())
    require(template.count(b"@OWNER_BYTES@")==1 and read(authored/"namespace_watcher_callable.S")==asm
        and read(authored/"generated/authoring/namespace_watcher_callable.S")==asm
        and proof["adapter_source"]==pin(asm),"exact generated assembly from fixed source")
    records=loads(read(authored/"ASSEMBLY-PROCESSES.json"))
    require(records==author["commands"] and len(records)==4,"all actual assembler commands")
    origin=str(Path(records[0]["argv"][4]).parent)
    required=[
        ["/usr/bin/as","--64","--fatal-warnings","-o",origin+"/adapter.o",origin+"/namespace_watcher_callable.S"],
        ["/usr/bin/objcopy","-O","binary","--only-section=.text",origin+"/adapter.o",origin+"/template.bin"],
        ["/usr/bin/readelf","--wide","--relocs","--symbols",origin+"/adapter.o"],
        ["/usr/bin/objdump","-d","--no-show-raw-insn",origin+"/adapter.o"]]
    require([r["argv"] for r in records]==required,"exact complete assembler invocations")
    for i,row in enumerate(records):
        require(row["timeout_seconds"]==60 and row["exit_code"]==0
            and row["stdout"]==pin(read(authored/(str(i)+".stdout")))
            and row["stderr"]==pin(read(authored/(str(i)+".stderr")))
            and not read(authored/(str(i)+".stderr")),"complete actual assembly streams")
    symbols=read(authored/"2.stdout").decode()
    require("There are no relocations in this file." in symbols
        and len([x for x in symbols.splitlines() if " UND " in x])==1,"no unresolved native symbols")
    require(set(proof["offsets"])==set(EXPORTS),"all exact exports")
    for key,symbol in EXPORTS.items():
        matches=re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+"+symbol+r"\s*$",symbols,re.M)
        require(len(matches)==1 and int(matches[0],16)==proof["offsets"][key],"actual export offset: "+key)
    adapter=bytes.fromhex(proof["adapter_hex"])
    require(pin(adapter)==proof["adapter"] and read(authored/"adapter.bin")==adapter
        and read(authored/"template.bin")==adapter+bytes(len(compiled["namespace-watcher"])),
        "every assembled adapter byte and zero HIA placeholder")
    generated=author["generated"]
    require(set(generated)=={"authoring/namespace_watcher_callable.S","native/namespace_watcher_callable.hepta",
        "native/namespace_watcher_callable.composition.json","authoring/namespace_watcher_callable.pseudo"},
        "complete actual generated file set")
    for name,row in generated.items():require(pin(read(authored/"generated"/name))==row,"whole generated file: "+name)
    require(pin(read(modules["namespace-watcher-callable-packer"]))==proof["packer_source"]
        and pin(read(authored/"generated/authoring/namespace_watcher_callable.pseudo"))==proof["pseudo"],
        "exact generated HIA/pseudo")
    wire,expected=inputs(compiled["namespace-watcher"],proof)
    emission=loads(read(build/"emission/EMISSION.json"))
    require(emission==report["emission"] and emission["schema"]=="hepta.namespace-watcher.callable-emission.v1"
        and emission["status"]=="PASS" and emission["image"]==pin(expected)
        and emission["source_composition"]==pin(proof_raw)
        and emission["module_manifest"]==pin(read(build/"modules/namespace-watcher-callable-packer/manifest.json")),
        "whole actual packing identity")
    wants=cases(wire,len(expected));require(emission["native_packer_calls"]==len(emission["calls"])==len(wants)==8
        and emission["refusals"]==7,"all original packer controls")
    count=0
    for row,(name,request,capacity,returned) in zip(emission["calls"],wants):
        require(row["name"]==name and row["input_bytes"]==len(request) and row["output_capacity"]==capacity
            and row["workspace_capacity"]==64 and row["returned"]==returned,"exact actual packing call")
        buffers={"input-before":request+b"\xc3"*16,"output-before":b"\xa5"*(capacity+16),
            "workspace-before":bytes(64)+b"\x5a"*16}
        buffers.update({"input-after":buffers["input-before"],"workspace-after":buffers["workspace-before"],
            "output-after":expected+buffers["output-before"][len(expected):] if name=="valid" else buffers["output-before"]})
        require(set(row["files"])==set(buffers),"complete input/output/workspace before/after")
        for key,raw in buffers.items():
            filename=name+"."+key+".bin"
            require(row["files"][key]==dict(path=filename,**pin(raw))
                and read(build/"emission"/filename)==raw,"full physical packer buffer: "+name+"/"+key)
            count+=len(raw)
    require(read(build/"emission/callable.image.bin")==read(build/"callable/callable.image.bin")==expected,
        "complete emitted and installed flat image")
    require(loads(read(build/"callable/BINDING.json"))==dict(proof,callable_image=pin(expected)),"complete callable binding")
    wanted_manifest=dict(schema="hepta.runtime.native-module.v1",
        abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1",target="linux-x86_64",
        compiler_commit=fixed["commit"],compiler_sha256=COMPILER,
        source="namespace_watcher_callable.S",source_sha256=sha(asm),
        image="callable.image.bin",image_sha256=sha(expected),qualification="private_hia_packer_composition",
        standalone=None,buffer_profile="standard",input_capacity=96,output_capacity=128,workspace_capacity=131072,
        composition_source=pin(proof_raw))
    require(loads(read(build/"callable/manifest.json"))==wanted_manifest
        and read(build/"callable/namespace_watcher_callable.S")==asm
        and report["callable"]==dict(manifest=pin(read(build/"callable/manifest.json")),
            binding=pin(read(build/"callable/BINDING.json")),image=pin(expected)),"whole actual loader admission")
    require(report["production_hia_owners"]==1 and report["packer_hia_owners"]==1
        and report["fresh_hia_compile"] is True and report["watcher_semantic_executions"]==0
        and report["rust_executions"]==0 and report["namespace_version_qualified"] is False
        and report["public_handler_qualified"] is False and report["whole_runtime_replaced"] is False,
        "exact source/build-only scope")
    from source_check_fixed9 import check as fixed_nine
    require(fixed_nine()["source_manifest_sha256"]==identity,"whole exact corrected native boundary")
    return dict(status="COMPLETE_WATCHER_FIXED_NINE_BUILD_READBACK_PASS",fcntl_duplicate_minimum=3,source_manifest_sha256=identity,
        fixed_eight_proved_functions=3,unchanged_full_function_asts=26,
        fixed_eight_proof=pin(encoded(symbolic)),compiler_files=1080,production_hia_images=1,packer_hia_images=1,packer_calls=8,packer_refusals=7,
        complete_packer_buffer_bytes=count,image=pin(expected),offsets=proof["offsets"],
        watcher_semantic_executions=0,rust_executions=0,reader_native_executions=0,
        namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",type=Path,required=True)
    p.add_argument("--authored",type=Path,required=True);a=p.parse_args()
    from authoring.author_fixed8 import proof as symbolic_proof
    from source_check_fixed9 import check as fixed_nine
    from read_only_guard import guarded
    import time
    build=a.build.resolve(strict=True);authored=a.authored.resolve(strict=True)
    symbolic=symbolic_proof(ROOT,build/"compiler-source");fixed_nine()
    started=time.monotonic();result=guarded(lambda:verify(build,authored,symbolic),roots=[ROOT,build.parent],foreign_path="/tmp/watcher-fixed9-reader-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"whole independent fixed9 build reader deadline")
    (build.parent/"FIXED9-GUARDED.json").write_bytes(encoded(result))
    print(encoded(dict(result["evidence"],guard_probes=len(result["probes"]),whole_filesystem_entries=len(result["before"]),
        elapsed_seconds=time.monotonic()-started)).decode(),end="")
