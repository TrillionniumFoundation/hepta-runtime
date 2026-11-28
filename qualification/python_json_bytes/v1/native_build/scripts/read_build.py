#!/usr/bin/env python3
"""Complete copied compiler and decoder build read; no semantic invocation."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,pin,require,sha,source_evidence,B3,HEPTA
import bootstrap_input
def build_evidence(source, output):
    source, output = Path(source), Path(output)
    bundle = decode(owned(output, "build/module.json").read_bytes())
    require(bundle["schema"] == "hepta.runtime.python-json-bytes.native-build.v1", "build schema changed")
    require(bundle["application_calls"] == 0 and bundle["compiler_cold_gate_repeated"] is False, "build scope changed")
    require(bundle["compiler_commit"] == HEPTA and bundle["compiler_sha256"] == B3, "build compiler changed")
    bootstrap = decode(owned(output, "build/bootstrap/bootstrap.json").read_bytes())
    require(bootstrap["generation_sha256"] == B3 and bootstrap["qualification"] == "development_fixed_point", "bootstrap identity changed")
    dependency = bootstrap["dependency"]
    require(dependency["commit"] == HEPTA and dependency["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49", "compiler source commit/tree changed")
    for path, digest in dependency["files"].items():
        require(pin(owned(output, "compiler-source/" + path))["sha256"] == digest, "compiler dependency file changed: " + path)
    require({p.relative_to(output/"compiler-source").as_posix()for p in(output/"compiler-source").rglob("*")if p.is_file()} == set(dependency["files"]), "complete compiler source set")
    require(bundle["compiler_modes"] == {name:(output/"compiler-source"/name).stat().st_mode&0o777 for name in dependency["files"]}, "complete compiler modes")
    for generation in ("B1", "B2", "B3"):
        require(pin(owned(output, "build/bootstrap/" + generation + ".image.bin"))["sha256"] == B3, "bootstrap generation changed")
    artifacts = {"build/module.json": pin(output / "build/module.json")}
    for name, row in {"python_json_bytes": bundle["member"]}.items():
        path = owned(output, row["manifest"])
        require(pin(path)["sha256"] == row["manifest_sha256"], "member manifest changed")
        metadata = decode(path.read_bytes())
        require(metadata["source_sha256"] == row["source_sha256"] == pin(owned(source, "native/" + name + ".hepta"))["sha256"], "member source changed")
        require(metadata["image_sha256"] == row["image_sha256"], "member image declaration changed")
        require(metadata["compiler_commit"] == HEPTA and metadata["compiler_sha256"] == B3 and metadata["buffer_profile"] == "serde-json.v1" and metadata["standalone"] is None, "member ABI changed")
        require([metadata[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [16 << 20, 64 << 20, 256 << 20], "member capacities changed")
        module_source = owned(path.parent, metadata["source"]).read_bytes()
        image = owned(path.parent, metadata["image"]).read_bytes()
        require(sha(module_source) == metadata["source_sha256"] and sha(image) == metadata["image_sha256"], "actual member bytes changed")
        request = decode(owned(path.parent, "module.request.json").read_bytes())
        receipt = decode(owned(path.parent, "module.receipt.json").read_bytes())
        raw_output = owned(path.parent, "module.output.bin").read_bytes()
        require(owned(path.parent, "module.input.bin").read_bytes() == module_source, "compiled input differs from published source")
        require(receipt["status"] == "returned" and type(receipt["abi_status"]) is int and receipt["abi_status"] == 0 and type(receipt["core_u32"]) is int, "compile did not return cleanly")
        require(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image) and image == raw_output[:len(image)], "compiled complete output/image differs")
        require(receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == [] and receipt["artifact_sha256"] == B3, "compile custody changed")
        require(receipt["input_bytes"] == len(module_source) and receipt["input_sha256"] == sha(module_source) and receipt["output_sha256"] == sha(raw_output) and receipt["produced_sha256"] == sha(image), "compile complete input/output hash differs")
        require(request["source_sha256"] == sha(module_source) and request["image_sha256"] == B3 and request["format"] == "flat-x86-64", "compile request changed")
        build = decode(owned(path.parent, "build.json").read_bytes())
        require(build["compile_receipt"] == receipt and build["compiler_dependency"] == dependency, "member build source closure changed")
        for artifact in (path, path.parent / metadata["source"], path.parent / metadata["image"]):
            artifacts[artifact.relative_to(output).as_posix()] = pin(artifact)
    return artifacts


def verify(source,output):
    identity=source_evidence(source);artifacts=build_evidence(source,output)
    bundle=decode(owned(output,"build/module.json").read_bytes())
    require(bundle["source"]==identity and bundle["new_seed_executions"]==bundle["new_bootstrap_generations"]==0
        and bundle["hia_compiles"]==1,"one compile from retained B3 and no applications")
    dependency=decode(owned(output,"build/bootstrap/bootstrap.json").read_bytes())["dependency"]
    copied=bootstrap_input.verify(source,output,dependency)
    require(bundle["copied_bootstrap"]==decode(owned(output,"BOOTSTRAP_REUSE.json").read_bytes()),
        "complete copied B3 receipt")
    member=owned(output,bundle["member"]["manifest"]);meta=decode(member.read_bytes())
    require(bundle["image"]==pin(owned(member.parent,meta["image"])),"complete fresh decoder image")
    return dict(status="COMPLETE_PYTHON_JSON_BYTES_BUILD_PASS",source=identity,artifacts=artifacts,
        image=bundle["image"],member=bundle["member"],copied_b3=copied,
        hia_compiles=1,new_seed_executions=0,new_bootstrap_generations=0,decoder_applications=0,
        original_applications=0,whole_runtime_replaced=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--build",type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);output=a.build.resolve(strict=True)
    from readonly import guarded
    result=guarded(lambda:verify(source,output),roots=[source,output])
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
