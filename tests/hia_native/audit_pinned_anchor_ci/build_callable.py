"""Fresh three-image HIA build and actual HIA packing of the fixed native adapter."""
from pathlib import Path
import argparse
import ctypes as C
import re
import stat
import subprocess
import sys
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from common import COMPILER, encoded, loads, pin, read, require, source
from hia_native_build import NativeBuild
from hia_native import NativeModule
from pack_contract import inputs, cases

MODULES = (
    ("audit-pinned-anchor", "imports/audit_pinned_anchor.hepta"),
    ("audit-json", "imports/audit_json.hepta"),
    ("audit-pinned-anchor-callable-packer", "native/audit_pinned_anchor_callable.hepta"),
)


def assemble(output, composition):
    output.mkdir()
    src = ROOT / "authoring/audit_pinned_anchor_callable.S"
    commands = [
        ["/usr/bin/as", "--64", "--fatal-warnings", "-o", str(output / "adapter.o"), str(src)],
        ["/usr/bin/objcopy", "-O", "binary", "--only-section=.text",
         str(output / "adapter.o"), str(output / "template.bin")],
        ["/usr/bin/readelf", "--wide", "--relocs", "--symbols", str(output / "adapter.o")],
        ["/usr/bin/objdump", "-d", "--no-show-raw-insn", str(output / "adapter.o")],
    ]
    receipts = []
    for index, command in enumerate(commands):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=60,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
        (output / (str(index) + ".stdout")).write_bytes(result.stdout)
        (output / (str(index) + ".stderr")).write_bytes(result.stderr)
        receipts.append(dict(argv=command, timeout_seconds=60, exit_code=result.returncode,
                             stdout=pin(result.stdout), stderr=pin(result.stderr)))
        (output / "PROCESSES.json").write_bytes(encoded(receipts))
        require(result.returncode == 0 and not result.stderr, "complete actual assembler: " + str(index))
    raw = read(output / "template.bin")
    adapter = bytes.fromhex(composition["adapter_hex"])
    require(raw == adapter + bytes(composition["owner"]["bytes"] + composition["json"]["bytes"]),
            "exact complete reassembled template")
    symbols = read(output / "2.stdout").decode()
    require("There are no relocations in this file." in symbols and
            len([line for line in symbols.splitlines() if " UND " in line]) == 1,
            "no unresolved relocation or external direct symbol")
    for name, offset in composition["offsets"].items():
        found = re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_pinned_anchor_callable_" +
                           name + r"\s*$", symbols, re.M)
        require(len(found) == 1 and int(found[0], 16) == offset, "exact export offset: " + name)
    return receipts


def emit(module_manifest, owner, codec, output, composition):
    output.mkdir()
    wire, expected = inputs(owner, codec, composition)
    rows = []
    with NativeModule(module_manifest, manifest_sha256=pin(read(module_manifest))["sha256"]) as module:
        for name, request, capacity, wanted in cases(wire, len(expected)):
            physical_input = C.create_string_buffer(request + b"\xc3" * 16, len(request) + 16)
            physical_output = C.create_string_buffer(b"\xa5" * (capacity + 16), capacity + 16)
            physical_work = C.create_string_buffer(bytes(64) + b"\x5a" * 16, 80)
            before = (physical_input.raw, physical_output.raw, physical_work.raw)
            returned = int(module._entry(C.addressof(physical_input), len(request),
                C.addressof(physical_output), capacity, C.addressof(physical_work), 64))
            after = (physical_input.raw, physical_output.raw, physical_work.raw)
            require(returned == wanted and after[0] == before[0] and after[2] == before[2],
                    "actual HIA packer and complete borrowed input/workspace: " + name)
            wanted_output = expected + before[1][len(expected):] if name == "valid" else before[1]
            require(after[1] == wanted_output, "complete packed image and untouched tail: " + name)
            files = {}
            for label, raw in zip(("input-before", "output-before", "workspace-before",
                                   "input-after", "output-after", "workspace-after"), before + after):
                path = name + "." + label + ".bin"
                (output / path).write_bytes(raw)
                files[label] = dict(path=path, **pin(raw))
            rows.append(dict(name=name, input_bytes=len(request), output_capacity=capacity,
                             workspace_capacity=64, returned=returned, files=files))
    (output / "callable.image.bin").write_bytes(expected)
    result = dict(schema="hepta.audit-pinned-anchor-callable.emission.v1",
        status="PASS", module_manifest=pin(read(module_manifest)), image=pin(expected),
        source_composition=pin(read(ROOT / "native/audit_pinned_anchor_callable.composition.json")),
        calls=rows, native_packer_calls=len(rows), refusals=len(rows) - 1)
    (output / "EMISSION.json").write_bytes(encoded(result))
    return expected, result


def run(hepta, output):
    identity = source()
    builder = NativeBuild(hepta, output)
    fixed = loads(read(ROOT / "COMPILER_IDENTITY.json"))
    require(builder.identity == fixed, "complete original fixed compiler sources")
    require(pin(read(builder.bootstrap())) == dict(bytes=673413, sha256=COMPILER), "fresh exact B1/B2/B3")
    composition = loads(read(ROOT / "native/audit_pinned_anchor_callable.composition.json"))
    require(pin(read(ROOT / "authoring/audit_pinned_anchor_callable.S")) == composition["adapter_source"] and
            pin(read(ROOT / "native/audit_pinned_anchor_callable.hepta")) == composition["packer_source"],
            "frozen native and HIA packer source")
    modules = {}
    paths = {}
    for name, path in MODULES:
        manifest = builder.compile(name, ROOT / path, standalone=None)
        image = read(manifest.parent / "module.image.bin")
        paths[name] = manifest
        modules[name] = dict(source_path=path, source=pin(read(ROOT / path)),
            manifest=dict(path=str(manifest.relative_to(output)), **pin(read(manifest))), image=pin(image))
    require(modules["audit-pinned-anchor"]["image"] == composition["owner"] and
            modules["audit-json"]["image"] == composition["json"], "unchanged exact semantic images")
    assembler = assemble(output / "assembler", composition)
    packed, emission = emit(paths["audit-pinned-anchor-callable-packer"],
        read(paths["audit-pinned-anchor"].parent / "module.image.bin"),
        read(paths["audit-json"].parent / "module.image.bin"), output / "emission", composition)
    installed = output / "callable"
    installed.mkdir()
    source_bytes = read(ROOT / "authoring/audit_pinned_anchor_callable.S")
    (installed / "audit_pinned_anchor_callable.S").write_bytes(source_bytes)
    (installed / "callable.image.bin").write_bytes(packed)
    manifest = dict(schema="hepta.runtime.native-module.v1",
        abi="hepta.runtime.borrowed-bytes.linux-x86_64.v1", target="linux-x86_64",
        compiler_commit=fixed["commit"], compiler_sha256=COMPILER,
        source="audit_pinned_anchor_callable.S", source_sha256=pin(source_bytes)["sha256"],
        image="callable.image.bin", image_sha256=pin(packed)["sha256"],
        qualification="private_hia_packer_composition", standalone=None, buffer_profile="standard",
        input_capacity=4352, output_capacity=8192, workspace_capacity=98304,
        composition_source=pin(read(ROOT / "native/audit_pinned_anchor_callable.composition.json")))
    (installed / "manifest.json").write_bytes(encoded(manifest))
    binding = dict(composition, callable_image=pin(packed))
    (installed / "BINDING.json").write_bytes(encoded(binding))
    for name, expected in fixed["files"].items():
        raw = read(hepta / name)
        require(pin(raw)["sha256"] == expected, "every frozen compiler source byte")
        target = output / "compiler-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(stat.S_IMODE((hepta / name).stat().st_mode))
    require(source() == identity, "source unchanged across real compilation and packing")
    result = dict(schema="hepta.audit-pinned-anchor-callable.build.v1", status="PASS",
        source_manifest_sha256=identity, compiler=fixed, compiler_image=dict(bytes=673413, sha256=COMPILER),
        modules=modules, assembler=assembler, emission=emission,
        callable=dict(manifest=pin(read(installed / "manifest.json")), binding=pin(read(installed / "BINDING.json")),
                      image=pin(packed)),
        fresh_hia_compile=True, production_hia_owners=2, packer_hia_owners=1,
        audit_record_semantic_execution=False, public_handler_qualified=False, whole_runtime_replaced=False)
    (output / "BUILD.json").write_bytes(encoded(result))
    print(encoded(result).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(a.hepta.resolve(strict=True), a.output.absolute())
