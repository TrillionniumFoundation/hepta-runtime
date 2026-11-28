#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Strict fresh compiler/module custody without loading executable pages."""
from pathlib import Path
from common import B3, HEPTA, decode, owned, pin, require, sha

def build_evidence(source, output):
    source, output = Path(source), Path(output)
    bundle = decode(owned(output, "BUILD.json").read_bytes())
    require(bundle["status"] == "TWO_FRESH_HIA_OWNERS_COMPILED", "build schema changed")
    require(set(bundle["members"]) == {"text-file-publication", "binary-codec"}, "build member set changed")
    require(bundle["compiler"]["commit"] == HEPTA, "build compiler changed")
    bootstrap = decode(owned(output, "build/bootstrap/bootstrap.json").read_bytes())
    require(bootstrap["generation_sha256"] == B3 and bootstrap["qualification"] == "development_fixed_point", "bootstrap identity changed")
    dependency = bootstrap["dependency"]
    require(dependency["commit"] == HEPTA and dependency["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49", "compiler source commit/tree changed")
    for path, digest in dependency["files"].items():
        require(pin(owned(output, "compiler-source/" + path))["sha256"] == digest, "compiler dependency file changed: " + path)
    for generation in ("B1", "B2", "B3"):
        require(pin(owned(output, "build/bootstrap/" + generation + ".image.bin"))["sha256"] == B3, "bootstrap generation changed")
    artifacts = {"build/typed-params.json": pin(output / "build/typed-params.json")}
    for name, row in bundle["members"].items():
        path = owned(output, row["manifest"])
        require(pin(path)["sha256"] == row["identity"]["sha256"], "member manifest changed")
        metadata = decode(path.read_bytes())
        require(metadata["source_sha256"] == row["source"]["sha256"] == pin(owned(output, "generated/text_file_publication.hepta") if name == "text-file-publication" else owned(source, "native/binary_codec.hepta"))["sha256"], "member source changed")
        require(metadata["image_sha256"] == row["image"], "member image declaration changed")
        require(metadata["compiler_commit"] == HEPTA and metadata["compiler_sha256"] == B3 and metadata["buffer_profile"] == "history.v1" and metadata["standalone"] is None, "member ABI changed")
        require([metadata[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [128 << 20, 128 << 20, 256 << 20], "member capacities changed")
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

    proof=decode(owned(output,"generated/text_file_publication_composition.json").read_bytes())
    for key,path in (("original_file",source/"target/text_file_write.rs"),("pseudo",source/"authoring/publication.pseudo"),
                     ("author",source/"authoring/author_publication.py"),("expanded_pseudo",output/"generated/expanded.pseudo"),
                     ("source",output/"generated/text_file_publication.hepta")):
        require({k:proof[key][k] for k in ("bytes","sha256")}==pin(path),"generated owner source provenance changed")
    require(proof["target_commit"]=="d3d75c30719db966b004756f610007a7c723729e"
        and proof["private_policy_only"] is True and proof["syscalls_emitted_by_hia"] is True
        and proof["sha256_via_actual_binary_codec"] is True and proof["python_policy_implementation"] is False,
        "generated policy scope changed")
    return artifacts

