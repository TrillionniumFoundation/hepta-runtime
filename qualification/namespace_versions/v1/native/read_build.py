"""Independent inert full compiler/assembler/packer reader; never executes an app."""
import argparse,re,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import COMPILER,encoded,loads,pin,read,require,sha,files,source
from original_build_invocation import invocation
from read_only_guard import guarded
from pack_contract import inputs,cases,child_inputs,child_cases
from authoring.author_callable import generate,EXPORTS
MODULES={"namespace-versions":"native/namespace_versions.hepta","namespace-watcher":"imports/namespace_watcher.hepta",
    "namespace-fingerprint":"imports/namespace_fingerprint.hepta","namespace-watcher-packer":"imports/namespace_watcher_callable.hepta",
    "namespace-fingerprint-packer":"imports/namespace_fingerprint_callable.hepta"}
QUALIFIED={"namespace-versions":dict(bytes=160201,sha256="024f0f5160fcd4e2ee6c7ec7e5d235f734472512c51d73e9974e68fcc6493382"),
    "namespace-watcher":dict(bytes=144700,sha256="47c86139bcbc735c4b465a7c698fe73b656ed018e944a02c02dcf049f7e0fae9"),
    "namespace-fingerprint":dict(bytes=104516,sha256="0e4153a7f4e99b09139ec1ff2cfc1a26a6b5f6234159be38219e727215ac31b0")}
def members(build):
    return {"namespace-versions":read(build/"modules/namespace-versions/module.image.bin"),
        "namespace-watcher":read(build/"dependencies/namespace-watcher/callable.image.bin"),
        "namespace-fingerprint":read(build/"dependencies/namespace-fingerprint/callable.image.bin")}
def prepare(build,authored):
    source();proof=loads(read(authored/"generated/native/namespace_versions_callable.composition.json"))
    return generate(ROOT,build/"compiler-source",read(authored/"adapter.bin"),proof["offsets"],members(build))
def emission(folder,manifest,wire,expected,plan,composition):
    record=loads(read(folder/"EMISSION.json"));wanted=dict(schema="hepta.namespace-versions.packer-emission.v1",status="PASS",
        module_manifest=pin(read(manifest)),source_composition=pin(composition),image=pin(expected),
        calls=record["calls"],packer_calls=len(plan),packer_refusals=len(plan)-1)
    require(record==wanted and len(record["calls"])==len(plan),"entire packer emission record")
    count=0
    for row,(name,request,capacity,returned)in zip(record["calls"],plan):
        require(row["name"]==name and row["input_bytes"]==len(request)and row["output_capacity"]==capacity
            and row["workspace_capacity"]==64 and row["returned"]==returned,"whole actual HIA packer call")
        buffers={"input-before":request+b"\xc3"*16,"output-before":b"\xa5"*(capacity+16),"workspace-before":bytes(64)+b"\x5a"*16}
        buffers.update({"input-after":buffers["input-before"],"workspace-after":buffers["workspace-before"],
            "output-after":expected+buffers["output-before"][len(expected):]if name=="valid"else buffers["output-before"]})
        require(set(row["files"])==set(buffers),"all six actual physical buffers")
        for key,raw in buffers.items():
            filename=name+"."+key+".bin"
            require(row["files"][key]==dict(path=filename,**pin(raw))and read(folder/filename)==raw,"every full actual packer buffer/tail")
            count+=len(raw)
    require(read(folder/"callable.image.bin")==expected,"all emitted callable bytes")
    return record,count
def verify(build,authored,prepared):
    identity=source();fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    report=loads(read(build/"BUILD.json"));deps=loads(read(build/"DEPENDENCIES.json"));bootstrap=loads(read(build/"bootstrap/bootstrap.json"))
    require(report["schema"]=="hepta.namespace-versions.callable-build.v1"and report["status"]=="PASS"
        and deps["schema"]=="hepta.namespace-versions.dependencies-build.v1"and deps["status"]=="PASS"
        and report["source_manifest_sha256"]==deps["source_manifest_sha256"]==identity
        and report["compiler"]==deps["compiler"]==bootstrap["dependency"]==fixed,"whole source and compiler identity")
    retained=files(build/"compiler-source")
    require(len(retained)==1080 and set(retained)==set(fixed["files"]),"entire fixed compiler source tree")
    for name,row in retained.items():require(row["sha256"]==fixed["files"][name],"every compiler byte")
    require(bootstrap["schema"]=="hepta.runtime.native-bootstrap.v1"and bootstrap["qualification"]=="development_fixed_point"
        and bootstrap["matching_source_cold_qualified"]is False and bootstrap["generation_sha256"]==COMPILER,"precise compiler qualification")
    folder=build/"bootstrap";compiler_source=read(build/"compiler-source/examples/hia_bootstrap/selfhost.hepta")
    require(bootstrap["compiler_source_sha256"]==sha(compiler_source),"entire bootstrap compiler source")
    generations=[read(folder/(n+".image.bin"))for n in("B1","B2","B3")]
    require(all(pin(raw)==dict(bytes=673413,sha256=COMPILER)for raw in generations),"all actual complete generations")
    previous=read(folder/Path(loads(read(folder/"B1.request.json"))["image"]).name)
    for i,label in enumerate(("B1","B2","B3")):
        receipt=invocation(folder,label,compiler_source,previous,generations[i],"seed-shared"if i==0 else"flat-x86-64")
        require(receipt==bootstrap["generation_receipts"][i],"complete actual bootstrap receipt")
        previous=generations[i]
    module_paths={n:ROOT/p for n,p in MODULES.items()}
    module_paths["namespace-versions-packer"]=authored/"generated/native/namespace_versions_callable.hepta"
    require(set(report["modules"])==set(module_paths)and set(deps["modules"])==set(MODULES),"three semantic owners and three packers")
    compiled={}
    for name,path in module_paths.items():
        module=build/"modules"/name;raw=read(path);image=read(module/"module.image.bin")
        manifest=loads(read(module/"manifest.json"));record=loads(read(module/"build.json"))
        require(read(module/(name+".hepta"))==raw and manifest["source"]==name+".hepta"
            and manifest["source_sha256"]==sha(raw)and manifest["image"]=="module.image.bin"
            and manifest["image_sha256"]==sha(image)and manifest["compiler_sha256"]==COMPILER
            and manifest["compiler_commit"]==fixed["commit"]and manifest["standalone"]is None
            and manifest["schema"]=="hepta.runtime.native-module.v1"
            and manifest["abi"]=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
            and manifest["target"]=="linux-x86_64"and manifest["qualification"]=="development_fixed_point"
            and manifest.get("buffer_profile","standard")=="standard"
            and [manifest[k]for k in("input_capacity","output_capacity","workspace_capacity")]==[8<<20,8<<20,32<<20],
            "complete actual compiled module manifest")
        actual=invocation(module,"module",raw,generations[-1],image,"flat-x86-64")
        require(record["compiler_dependency"]==fixed and record["compile_receipt"]==actual
            and record["whole_runtime_replaced"]is False,"entire actual compile output/receipt")
        wanted=dict(source=pin(raw),image=pin(image),manifest=dict(path="modules/"+name+"/manifest.json",**pin(read(module/"manifest.json"))))
        require(report["modules"][name]==wanted,"exact whole module identity")
        if name in MODULES:require(deps["modules"][name]==wanted,"dependency compilation is the same actual invocation")
        compiled[name]=image
    proofraw=read(authored/"generated/native/namespace_versions_callable.composition.json");proof=loads(proofraw)
    require(report["composition"]==pin(proofraw),"exact raw composition including integer constants")
    generated_names=("authoring/namespace_versions_callable.S","native/namespace_versions_callable.hepta",
        "native/namespace_versions_callable.composition.json","authoring/namespace_versions_callable.pseudo")
    for name,wanted in zip(generated_names,prepared):
        require(read(authored/"generated"/name)==wanted,"entire independently regenerated source: "+name)
    author=loads(read(authored/"AUTHORING.json"));records=loads(read(authored/"ASSEMBLY-PROCESSES.json"))
    require(report["authoring"]==pin(read(authored/"AUTHORING.json"))and author["source"]==proof
        and author["schema"]=="hepta.namespace-versions.callable-author.v1"and author["status"]=="SOURCE_ONLY_PASS"
        and author["native_application_calls"]==author["original_application_calls"]==0
        and author["generated"]=={n:pin(b)for n,b in zip(generated_names,prepared)}and author["commands"]==records
        and len(records)==4,"whole author record")
    origin=str(Path(records[0]["argv"][4]).parent)
    wanted_commands=[
        ["/usr/bin/as","--64","--fatal-warnings","-o",origin+"/adapter.o",origin+"/namespace_versions_callable.S"],
        ["/usr/bin/objcopy","-O","binary","--only-section=.text",origin+"/adapter.o",origin+"/template.bin"],
        ["/usr/bin/readelf","--wide","--relocs","--symbols",origin+"/adapter.o"],
        ["/usr/bin/objdump","-d","--no-show-raw-insn",origin+"/adapter.o"]]
    require([r["argv"]for r in records]==wanted_commands,"exact actual native assembler commands")
    for i,r in enumerate(records):
        require(r["timeout_seconds"]==60 and r["exit_code"]==0 and r["stdout"]==pin(read(authored/(str(i)+".stdout")))
            and r["stderr"]==pin(read(authored/(str(i)+".stderr")))and not read(authored/(str(i)+".stderr")),"whole actual assembler streams")
    symbols=read(authored/"2.stdout").decode()
    require("There are no relocations in this file."in symbols and len([x for x in symbols.splitlines()if" UND "in x])==1
        and set(proof["offsets"])==set(EXPORTS),"all native exports and no relocation/unresolved symbol")
    for key,symbol in EXPORTS.items():
        found=re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+"+symbol+r"\s*$",symbols,re.M)
        require(len(found)==1 and int(found[0],16)==proof["offsets"][key],"actual assembler symbol")
    adapter=bytes.fromhex(proof["adapter_hex"]);images=members(build)
    require({n:pin(raw)for n,raw in images.items()}==QUALIFIED,"complete previously compiled and independently qualified images")
    require(read(authored/"adapter.bin")==adapter and read(authored/"template.bin")==adapter+bytes(sum(map(len,images.values())))
        and read(authored/"namespace_versions_callable.S")==prepared[0],"whole adapter and empty placeholders")
    total=0
    for name in("namespace-watcher","namespace-fingerprint"):
        childraw=read(ROOT/("imports/"+name.replace("-","_")+"_callable.composition.json"));child=loads(childraw)
        wire,expected=child_inputs(compiled[name],child,name)
        require(expected==images[name],"entire actual child image composition")
        record,count=emission(build/"dependencies"/name,build/"modules"/(name+"-packer")/"manifest.json",wire,expected,
            child_cases(wire,len(expected)),childraw)
        require(record==report["dependencies"][name]==deps["emissions"][name],"same complete actual dependency emission")
        total+=count
    wire,expected=inputs(images,proof);record,count=emission(build/"emission",build/"modules/namespace-versions-packer/manifest.json",
        wire,expected,cases(wire,len(expected)),proofraw);total+=count
    require(record==report["emission"],"whole actual final HIA packer emission")
    installed=build/"callable";asm=prepared[0]
    wanted=dict(schema="hepta.runtime.native-module.v1",abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1",target="linux-x86_64",
        compiler_commit=fixed["commit"],compiler_sha256=COMPILER,source="namespace_versions_callable.S",source_sha256=sha(asm),
        image="callable.image.bin",image_sha256=sha(expected),qualification="private_hia_packer_composition",standalone=None,
        buffer_profile="standard",input_capacity=4224,output_capacity=192,workspace_capacity=4096,composition_source=pin(proofraw))
    require(read(installed/"namespace_versions_callable.S")==asm and read(installed/"callable.image.bin")==expected
        and loads(read(installed/"manifest.json"))==wanted and loads(read(installed/"BINDING.json"))==dict(proof,callable_image=pin(expected)),
        "entire installed image/source/manifest/binding")
    require(report["callable"]==dict(image=pin(expected),manifest=pin(read(installed/"manifest.json")),binding=pin(read(installed/"BINDING.json"))),
        "whole installed file identity")
    require(report["native_application_calls"]==report["original_application_calls"]==deps["native_application_calls"]==deps["original_application_calls"]==0
        and report["fresh_semantic_hia_images"]==report["fresh_packer_hia_images"]==3
        and report["namespace_version_qualified"]is False and report["public_handler_qualified"]is False,"build-only claims")
    return dict(status="COMPLETE_NAMESPACE_VERSIONS_CALLABLE_BUILD_READ_PASS",source_manifest_sha256=identity,
        image=pin(expected),adapter=proof["adapter"],offsets=proof["offsets"],members=QUALIFIED,shape=proof["shape"],
        compiler_files=1080,complete_compiler_output_bytes=9*(1<<20),complete_packer_buffer_bytes=total,
        fresh_semantic_hia_images=3,fresh_packer_hia_images=3,packer_calls=26,packer_refusals=23,
        reader_native_executions=0,reader_rust_executions=0,native_application_calls=0,original_application_calls=0,
        namespace_version_qualified=False,public_handler_qualified=False)
def run(build,authored,output):
    expected=prepare(build,authored);started=time.monotonic()
    result=guarded(lambda:verify(build,authored,expected),roots=[ROOT,build,authored],
        foreign_path="/tmp/namespace-versions-native-forbidden-producer/CAPTURE.json")
    require(time.monotonic()-started<=180,"whole pure build read deadline")
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(encoded(result))
    print(encoded(dict(result["evidence"],guard_probes=len(result["probes"]),files=len(result["before"]),
        elapsed_seconds=time.monotonic()-started)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("build","authored","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.authored.resolve(strict=True),a.output.absolute())
