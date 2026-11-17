"""Complete inert compiler/assembler/packer readback for the native audit callable."""
from pathlib import Path
import re
from common import ROOT, COMPILER, encoded, loads, pin, read, require, sha, files, source
from original_build_invocation import invocation
from pack_contract import inputs, cases

MODULES = {
    "audit-pinned-anchor": "imports/audit_pinned_anchor.hepta",
    "audit-json": "imports/audit_json.hepta",
    "audit-pinned-anchor-callable-packer": "native/audit_pinned_anchor_callable.hepta",
}


def verify(build):
    fixed = loads(read(ROOT / "COMPILER_IDENTITY.json"))
    proof = loads(read(ROOT / "native/audit_pinned_anchor_callable.composition.json"))
    report = loads(read(build / "BUILD.json"))
    bootstrap = loads(read(build / "bootstrap/bootstrap.json"))
    require(report["schema"] == "hepta.audit-pinned-anchor-callable.build.v1" and report["status"] == "PASS" and
            report["source_manifest_sha256"] == source() and report["compiler"] == fixed ==
            bootstrap["dependency"], "complete fixed source and compiler closure")
    retained = files(build / "compiler-source")
    require(set(retained) == set(fixed["files"]) and len(retained) == 1080,
            "complete compiler source file domain")
    for name, row in retained.items():
        require(row["sha256"] == fixed["files"][name], "entire compiler source: " + name)
    require(bootstrap["schema"] == "hepta.runtime.native-bootstrap.v1" and
            bootstrap["qualification"] == "development_fixed_point" and
            bootstrap["matching_source_cold_qualified"] is False and bootstrap["generation_sha256"] == COMPILER,
            "unchanged fixed-point bootstrap scope")
    compiler_source = read(build / "compiler-source/examples/hia_bootstrap/selfhost.hepta")
    require(bootstrap["compiler_source_sha256"] == sha(compiler_source), "complete fresh compiler input")
    folder = build / "bootstrap"
    images = [read(folder / (label + ".image.bin")) for label in ("B1", "B2", "B3")]
    require(all(pin(raw) == dict(bytes=673413, sha256=COMPILER) for raw in images),
            "all three actual complete compiler images")
    seed_name = Path(loads(read(folder / "B1.request.json"))["image"]).name
    previous = read(folder / seed_name)
    for index, label in enumerate(("B1", "B2", "B3")):
        result = invocation(folder, label, compiler_source, previous, images[index],
                            "seed-shared" if index == 0 else "flat-x86-64")
        require(result == bootstrap["generation_receipts"][index], "entire bootstrap receipt")
        previous = images[index]
    require(set(report["modules"]) == set(MODULES), "exact two semantic owners and one HIA packer")
    compiled = {}
    for name, path in MODULES.items():
        module = build / "modules" / name
        raw = read(ROOT / path)
        image = read(module / "module.image.bin")
        manifest = loads(read(module / "manifest.json"))
        expected = report["modules"][name]
        require(read(module / (name + ".hepta")) == raw and manifest["source"] == name + ".hepta" and
                manifest["source_sha256"] == sha(raw) and manifest["image"] == "module.image.bin" and
                manifest["image_sha256"] == sha(image) and manifest["compiler_sha256"] == COMPILER and
                manifest["compiler_commit"] == fixed["commit"] and manifest["standalone"] is None and
                manifest["schema"] == "hepta.runtime.native-module.v1" and
                manifest["abi"] == "hepta.runtime.borrowed-bytes.linux-x86_64.v1" and
                manifest["target"] == "linux-x86_64" and manifest["qualification"] == "development_fixed_point" and
                manifest.get("buffer_profile", "standard") == "standard" and
                [manifest[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] ==
                [8 << 20, 8 << 20, 32 << 20], "full compiled borrowed-module manifest")
        receipt = invocation(module, "module", raw, images[-1], image, "flat-x86-64")
        record = loads(read(module / "build.json"))
        require(record["compiler_dependency"] == fixed and record["compile_receipt"] == receipt and
                record["whole_runtime_replaced"] is False, "actual complete module build record")
        require(expected == dict(source_path=path, source=pin(raw), image=pin(image),
                manifest=dict(path="modules/" + name + "/manifest.json", **pin(read(module / "manifest.json")))),
                "entire module source/image/manifest binding")
        compiled[name] = image
    require(pin(compiled["audit-pinned-anchor"]) == proof["owner"] and
            pin(compiled["audit-json"]) == proof["json"], "both frozen semantic images unchanged")
    assembler = build / "assembler"
    records = loads(read(assembler / "PROCESSES.json"))
    require(len(records) == 4 and records == report["assembler"], "every actual assembler process")
    expected_programs = ("/usr/bin/as", "/usr/bin/objcopy", "/usr/bin/readelf", "/usr/bin/objdump")
    for index, (row, command) in enumerate(zip(records, expected_programs)):
        require(row["argv"][0] == command and row["timeout_seconds"] == 60 and row["exit_code"] == 0 and
                pin(read(assembler / (str(index) + ".stdout"))) == row["stdout"] and
                pin(read(assembler / (str(index) + ".stderr"))) == row["stderr"] and
                read(assembler / (str(index) + ".stderr")) == b"", "complete assembler stdout/stderr")
    original_assembler = str(Path(records[0]["argv"][4]).parent)
    original_source = records[0]["argv"][5]
    require(Path(original_source).name == "audit_pinned_anchor_callable.S" and
            Path(original_source).parent.name == "authoring", "actual fixed assembly input basename")
    required_argv = [
        ["/usr/bin/as", "--64", "--fatal-warnings", "-o", original_assembler + "/adapter.o", original_source],
        ["/usr/bin/objcopy", "-O", "binary", "--only-section=.text",
         original_assembler + "/adapter.o", original_assembler + "/template.bin"],
        ["/usr/bin/readelf", "--wide", "--relocs", "--symbols", original_assembler + "/adapter.o"],
        ["/usr/bin/objdump", "-d", "--no-show-raw-insn", original_assembler + "/adapter.o"],
    ]
    require([r["argv"] for r in records] == required_argv, "complete exact assembler invocations")
    adapter = bytes.fromhex(proof["adapter_hex"])
    require(pin(adapter) == proof["adapter"] and
            pin(read(ROOT / "authoring/audit_pinned_anchor_callable.S")) == proof["adapter_source"] and
            read(assembler / "template.bin") == adapter + bytes(proof["owner"]["bytes"] + proof["json"]["bytes"]),
            "entire actual reassembled template and zero placeholders")
    symbols = read(assembler / "2.stdout").decode()
    require("There are no relocations in this file." in symbols and
            len([line for line in symbols.splitlines() if " UND " in line]) == 1,
            "complete zero-relocation native source")
    for name, offset in proof["offsets"].items():
        found = re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_pinned_anchor_callable_" +
                           name + r"\s*$", symbols, re.M)
        require(len(found) == 1 and int(found[0], 16) == offset, "all native export offsets")
    wire, expected_image = inputs(compiled["audit-pinned-anchor"], compiled["audit-json"], proof)
    emission = loads(read(build / "emission/EMISSION.json"))
    require(emission == report["emission"] and emission["schema"] == "hepta.audit-pinned-anchor-callable.emission.v1" and
            emission["status"] == "PASS" and emission["image"] == pin(expected_image) and
            emission["source_composition"] == pin(read(ROOT / "native/audit_pinned_anchor_callable.composition.json")) and
            emission["module_manifest"] == pin(read(build / "modules/audit-pinned-anchor-callable-packer/manifest.json")),
            "actual HIA packer source and complete output identity")
    expected_cases = cases(wire, len(expected_image))
    require(emission["native_packer_calls"] == len(emission["calls"]) == len(expected_cases) == 9 and
            emission["refusals"] == 8, "all original packer cases and refusals")
    buffer_bytes = 0
    for row, (name, request, capacity, returned) in zip(emission["calls"], expected_cases):
        require(row["name"] == name and row["input_bytes"] == len(request) and
                row["output_capacity"] == capacity and row["workspace_capacity"] == 64 and
                row["returned"] == returned, "exact actual packer case")
        wanted = {
            "input-before": request + b"\xc3" * 16,
            "output-before": b"\xa5" * (capacity + 16),
            "workspace-before": bytes(64) + b"\x5a" * 16,
        }
        wanted.update({"input-after": wanted["input-before"], "workspace-after": wanted["workspace-before"],
                       "output-after": expected_image + wanted["output-before"][len(expected_image):]
                       if name == "valid" else wanted["output-before"]})
        require(set(row["files"]) == set(wanted), "complete packer physical buffer set")
        for label, data in wanted.items():
            identity = row["files"][label]
            filename = name + "." + label + ".bin"
            require(identity == dict(path=filename, **pin(data)) and
                    read(build / "emission" / filename) == data,
                    "every complete actual packer buffer including guards and tails")
            buffer_bytes += len(data)
    require(read(build / "emission/callable.image.bin") == expected_image and
            read(build / "callable/callable.image.bin") == expected_image, "complete installed packed image")
    binding = loads(read(build / "callable/BINDING.json"))
    require(binding == dict(proof, callable_image=pin(expected_image)), "exact fixed callable binding")
    adapter_source = read(ROOT / "authoring/audit_pinned_anchor_callable.S")
    wanted_manifest = dict(schema="hepta.runtime.native-module.v1",
        abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1", target="linux-x86_64",
        compiler_commit=fixed["commit"], compiler_sha256=COMPILER,
        source="audit_pinned_anchor_callable.S", source_sha256=sha(adapter_source),
        image="callable.image.bin", image_sha256=sha(expected_image),
        qualification="private_hia_packer_composition", standalone=None, buffer_profile="standard",
        input_capacity=4352, output_capacity=8192, workspace_capacity=98304,
        composition_source=pin(read(ROOT / "native/audit_pinned_anchor_callable.composition.json")))
    require(loads(read(build / "callable/manifest.json")) == wanted_manifest and
            read(build / "callable/audit_pinned_anchor_callable.S") == adapter_source and
            report["callable"] == dict(manifest=pin(read(build / "callable/manifest.json")),
                binding=pin(read(build / "callable/BINDING.json")), image=pin(expected_image)),
            "exact loader admission, source and full image")
    require(report["production_hia_owners"] == 2 and report["packer_hia_owners"] == 1 and
            report["fresh_hia_compile"] is True and report["audit_record_semantic_execution"] is False and
            report["public_handler_qualified"] is False and report["whole_runtime_replaced"] is False,
            "precise build-only qualification scope")
    return dict(status="COMPLETE_NATIVE_CALLABLE_BUILD_READBACK_PASS", compiler_files=1080,
        fresh_semantic_images=2, fresh_packer_images=1, packer_calls=9, packer_refusals=8,
        complete_packer_buffer_bytes=buffer_bytes, image=pin(expected_image),
        native_or_rust_executions=0)
