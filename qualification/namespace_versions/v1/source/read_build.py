"""Independently read all fresh compiler bytes; never execute the application."""
import argparse,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import COMPILER,encoded,loads,pin,read,require,sha,files,source
from original_build_invocation import invocation
from read_only_guard import guarded
from authoring.author_versions import generate
def prepare(build):
    source();return generate(ROOT,build/"compiler-source")
def verify(build,authored,prepared):
    identity=source();fixed=loads(read(ROOT/"COMPILER_IDENTITY.json"))
    report=loads(read(build/"BUILD.json"));bootstrap=loads(read(build/"bootstrap/bootstrap.json"))
    require(report["schema"]=="hepta.namespace-versions.owner-build.v1"and report["status"]=="PASS"
        and report["source_manifest_sha256"]==identity and report["compiler"]==bootstrap["dependency"]==fixed,
        "complete actual source/compiler closure")
    raw=read(authored/"namespace_versions.hepta");proof=read(authored/"namespace_versions.composition.json")
    require((raw,proof)==prepared,"entire HIA source and composition independently reconstructed")
    require(report["composition"]==pin(proof),"exact complete authored composition")
    retained=files(build/"compiler-source")
    require(len(retained)==1080 and set(retained)==set(fixed["files"]),"all fixed compiler files")
    for name,row in retained.items():require(row["sha256"]==fixed["files"][name],"every compiler source byte")
    require(bootstrap["schema"]=="hepta.runtime.native-bootstrap.v1"and
        bootstrap["qualification"]=="development_fixed_point"and bootstrap["matching_source_cold_qualified"]is False
        and bootstrap["generation_sha256"]==COMPILER,"precise actual compiler bootstrap claim")
    folder=build/"bootstrap";compiler_source=read(build/"compiler-source/examples/hia_bootstrap/selfhost.hepta")
    require(bootstrap["compiler_source_sha256"]==sha(compiler_source),"complete compiler input")
    images=[read(folder/(n+".image.bin"))for n in("B1","B2","B3")]
    require(all(pin(b)==dict(bytes=673413,sha256=COMPILER)for b in images),"all actual B1/B2/B3 bytes")
    previous=read(folder/Path(loads(read(folder/"B1.request.json"))["image"]).name)
    for i,label in enumerate(("B1","B2","B3")):
        receipt=invocation(folder,label,compiler_source,previous,images[i],"seed-shared"if i==0 else"flat-x86-64")
        require(receipt==bootstrap["generation_receipts"][i],"whole actual bootstrap invocation")
        previous=images[i]
    module=build/"modules/namespace-versions";image=read(module/"module.image.bin")
    manifest=loads(read(module/"manifest.json"));record=loads(read(module/"build.json"))
    require(read(module/"namespace-versions.hepta")==raw and manifest["source"]=="namespace-versions.hepta"
        and manifest["source_sha256"]==sha(raw)and manifest["image"]=="module.image.bin"
        and manifest["image_sha256"]==sha(image)and manifest["compiler_sha256"]==COMPILER
        and manifest["compiler_commit"]==fixed["commit"]and manifest["standalone"]is None
        and manifest["schema"]=="hepta.runtime.native-module.v1"
        and manifest["abi"]=="hepta.runtime.borrowed-bytes.linux-x86_64.v1"
        and manifest["target"]=="linux-x86_64"and manifest["qualification"]=="development_fixed_point"
        and manifest.get("buffer_profile","standard")=="standard"
        and [manifest[k]for k in("input_capacity","output_capacity","workspace_capacity")]==[8<<20,8<<20,32<<20],
        "entire actual compiled module manifest")
    receipt=invocation(module,"module",raw,images[-1],image,"flat-x86-64")
    require(record["compiler_dependency"]==fixed and record["compile_receipt"]==receipt
        and record["whole_runtime_replaced"]is False,"entire actual module compiler receipt")
    require(report["module"]==dict(source=pin(raw),image=pin(image),
        manifest=dict(path="modules/namespace-versions/manifest.json",**pin(read(module/"manifest.json")))),
        "actual module byte identity")
    require(report["native_application_calls"]==report["original_application_calls"]==0
        and report["namespace_version_qualified"]is False and report["public_handler_qualified"]is False,
        "author/build only, no application claim")
    return dict(status="COMPLETE_NAMESPACE_VERSIONS_SOURCE_BUILD_READ_PASS",source_manifest_sha256=identity,
        owner=pin(raw),composition=pin(proof),shape=loads(proof)["shape"],image=pin(image),compiler_files=1080,
        complete_compiler_output_bytes=4*(1<<20),reader_native_executions=0,reader_rust_executions=0,
        namespace_version_qualified=False,public_handler_qualified=False)
def run(build,authored,output):
    expected=prepare(build);started=time.monotonic()
    result=guarded(lambda:verify(build,authored,expected),roots=[ROOT,build,authored],
        foreign_path="/tmp/namespace-versions-forbidden-producer/CAPTURE.json")
    require(time.monotonic()-started<=180,"whole pure build reader deadline")
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(encoded(result))
    print(encoded(dict(result["evidence"],guard_probes=len(result["probes"]),files=len(result["before"]),
        elapsed_seconds=time.monotonic()-started)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("build","authored","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.authored.resolve(strict=True),a.output.absolute())
