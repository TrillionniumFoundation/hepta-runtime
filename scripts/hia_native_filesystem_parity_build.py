"""Build and inspect the HIA filesystem owner and static Linux boundary.

Python invokes the build and checks retained evidence; it is not in the ELF.
Development fixed-point evidence does not replace the separate cold gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new

COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
COMPILER = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
DEPENDENCY = "c3a2f7776feead1232bb31ef6dd319d69cf91663492634ece3c8a2c46dd5c2bd"
OWNER_SOURCE = "1afb3046366a16a346a21345f3710efefdd312a1f9b35878bd7aec5118ddd454"
OWNER_IMAGE = "8ec17b8b488607cda81ba7c21576e411387f9df8e2159115cba5ec4be313806f"
PACKER_SOURCE = "59bef09a939dd55fc778c514a376d2ebcc63bf30752dedc0eaf717e6bc0a0c9e"
PACKER_IMAGE = "a33511df2919097d0a83a5d6bb07553fa1a538b933640bd4f4ea6ce7b2031543"
LAYOUT_SOURCE = "bc33e25fda7a166e540b0a5998b247e339f338d6a6f91755a43ff832d8bf0bf4"
COMPOSITION_SOURCE = "52c5915dcf50742905ddefe6f3ff132612bea4e4eb85a2923a07835319fad9e7"
PREFIX_BYTES = 3984
PREFIX_SHA = "fa182b259b45e3efb062753d851260d95cc941e11d39cbe155387028200f7d9c"
ELF_BYTES = 359046
ELF_SHA = "940d65ad9f223082b82bd6461df3bbc760a45c8829e76c11533d6482a4be3251"
COMPILE_FILES = ("manifest.json", "build.json", "module.input.bin", "module.output.bin",
                 "module.image.bin", "module.receipt.json", "module.request.json",
                 "module.stdout.log", "module.stderr.log")
PACK_FILES = ("pack.input.bin", "pack.output.bin", "pack.receipt.json", "pack.request.json",
              "pack.stdout.log", "pack.stderr.log")
BOOTSTRAP_FILES = ("bootstrap.json", "B1.image.bin", "B2.image.bin", "B3.image.bin")
SOURCE_FILES = ("native/filesystem_parity.hepta", "native/filesystem_parity_packer.hepta",
                "native/filesystem_parity_layout.json", "native/filesystem_parity_composition.json",
                "native/text_budget.hepta", "native/view_error.hepta",
                "scripts/hia_native_filesystem_parity_build.py", "scripts/hia_native_build.py",
                "scripts/hia_native_loader.py")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(actual, expected, message):
    def same(left, right):
        if type(left) is not type(right):
            return False
        if type(right) is dict:
            return left.keys() == right.keys() and all(same(left[key], value) for key, value in right.items())
        if type(right) in (list, tuple):
            return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
        return left == right
    require(same(actual, expected), message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def read(path):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "filesystem artifact crosses a symlink")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
            "filesystem artifact must be an owned regular file")
    return path.read_bytes()


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate filesystem evidence field")
        result[key] = value
    return result


def obj(path):
    def nonfinite(value):
        raise ValueError("nonfinite filesystem evidence number: " + value)
    value = json.loads(read(path), object_pairs_hook=unique, parse_constant=nonfinite)
    require(type(value) is dict, "filesystem evidence must contain an object")
    return value


def file_record(path):
    raw = read(path)
    return {"bytes": len(raw), "sha256": sha(raw)}


def source_pins(source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    pins = {name: file_record(root / name) for name in SOURCE_FILES}
    for name, expected in (("filesystem_parity.hepta", OWNER_SOURCE),
                           ("filesystem_parity_packer.hepta", PACKER_SOURCE),
                           ("filesystem_parity_layout.json", LAYOUT_SOURCE),
                           ("filesystem_parity_composition.json", COMPOSITION_SOURCE)):
        exact(pins["native/" + name]["sha256"], expected, "filesystem source pin differs: " + name)
    exact(pins["scripts/hia_native_build.py"]["sha256"],
          "7b01d602d50835f2b73a2b7b39761c0cef08a372493985161d59184d52c0dcb2",
          "filesystem compiler driver differs")
    exact(pins["scripts/hia_native_loader.py"]["sha256"],
          "331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2",
          "filesystem native loader differs")
    proof = obj(root / "native/filesystem_parity_composition.json")
    exact(proof["source_sha256"], OWNER_SOURCE, "filesystem composition owner differs")
    exact({row["source"] for row in proof["imports"]},
          {"native/text_budget.hepta", "native/view_error.hepta"}, "filesystem imported owner set differs")
    for row in proof["imports"]:
        exact(pins[row["source"]]["sha256"], row["source_sha256"], "filesystem imported source differs")
    return pins


def native_receipt(directory, stem, *, source, produced, producer):
    directory = Path(directory)
    receipt = obj(directory / (stem + ".receipt.json"))
    stdout = obj(directory / (stem + ".stdout.log"))
    output = read(directory / (stem + ".output.bin"))
    expected = {"status": "returned", "abi_status": 0, "core_u32": len(produced),
                "result_u64": len(produced), "source_unchanged": True, "input_bytes": len(source),
                "input_sha256": sha(source), "source_sha256": sha(source), "artifact_sha256": producer,
                "image_sha256": producer, "output_sha256": sha(output),
                "forbidden_compiler_modules_loaded": [], "format": "flat-x86-64", "case": stem,
                "return_encoding": "zero-extended-u32"}
    for key, value in expected.items():
        exact(receipt.get(key), value, "filesystem native receipt differs: " + key)
    require(0 < len(produced) <= len(output) == 1 << 20, "filesystem native output extent differs")
    exact(output[:len(produced)], produced, "filesystem native product differs")
    exact(output[len(produced):], b"\xa5" * (len(output) - len(produced)), "filesystem native output tail changed")
    exact(read(directory / (stem + ".input.bin")), source, "filesystem actual native input differs")
    exact(read(directory / (stem + ".stderr.log")), b"", "filesystem native stderr is not empty")
    stdout_fields = {"abi_status", "core_u32", "forbidden_compiler_modules_loaded", "image_sha256",
                     "limits", "loader_operations", "native_elapsed_ns", "output_sha256", "output_unchanged",
                     "result_u64", "return_encoding", "source_sha256", "source_unchanged", "status", "workspace_header"}
    exact(set(stdout), stdout_fields, "filesystem actual stdout field set differs")
    for key, value in stdout.items():
        exact(receipt.get(key), value, "filesystem receipt differs from actual stdout: " + key)
    request = obj(directory / (stem + ".request.json"))
    exact(set(request), {"capacity", "format", "image", "image_sha256", "output", "source",
                         "source_sha256", "workspace_fill", "workspace_size"}, "filesystem request fields differ")
    for key, value in {"capacity": 1 << 20, "format": "flat-x86-64", "image_sha256": producer,
                       "source_sha256": sha(source), "workspace_fill": 0, "workspace_size": 1 << 20}.items():
        exact(request[key], value, "filesystem native request differs: " + key)
    for key, name in (("source", stem + ".input.bin"), ("output", stem + ".output.bin")):
        require(type(request[key]) is str and Path(request[key]).name == name, "filesystem invocation path differs")
    require(Path(request["source"]).parent == Path(request["output"]).parent, "filesystem invocation directories differ")
    image_name = "B3.image.bin" if stem == "module" else "module.image.bin"
    require(type(request["image"]) is str and Path(request["image"]).name == image_name, "filesystem producer path differs")
    return receipt


def inspect_elf(raw, image):
    exact(len(raw), ELF_BYTES, "filesystem ELF extent differs")
    exact(sha(raw), ELF_SHA, "filesystem ELF bytes differ")
    exact(raw[:16], b"\x7fELF\x02\x01\x01" + bytes(9), "filesystem ELF identity differs")
    exact(struct.unpack_from("<HHIQQQIHHHHHH", raw, 16),
          (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), "filesystem ELF header differs")
    exact(struct.unpack_from("<IIQQQQQQ", raw, 64),
          (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), "filesystem ELF RX segment differs")
    exact(struct.unpack_from("<IIQQQQQQ", raw, 120),
          (0x6474e551, 6, 0, 0, 0, 0, 0, 16), "filesystem ELF stack differs")
    prefix = bytearray(raw[:PREFIX_BYTES])
    prefix[96:112] = bytes(16)
    exact(sha(prefix), PREFIX_SHA, "filesystem fixed syscall boundary differs")
    exact(raw[PREFIX_BYTES:], image, "filesystem embedded HIA owner differs")
    return {"bytes": len(raw), "sha256": sha(raw), "dynamic_loader": False, "elf_type": "ET_EXEC",
            "entry": 0x4000b0, "interpreter": None, "libc": False, "machine": "EM_X86_64",
            "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"]}


def inspect_module(directory, kind, source, *, dependency=None):
    directory = Path(directory)
    name = "filesystem-parity" if kind == "owner" else "filesystem-parity-packer"
    image_sha = OWNER_IMAGE if kind == "owner" else PACKER_IMAGE
    caps = (128 << 20, 128 << 20, 256 << 20) if kind == "owner" else (8 << 20, 8 << 20, 32 << 20)
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
                "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
                "compiler_commit": COMMIT, "compiler_sha256": COMPILER, "source": name + ".hepta",
                "source_sha256": sha(source), "image": "module.image.bin", "image_sha256": image_sha,
                "input_capacity": caps[0], "output_capacity": caps[1], "workspace_capacity": caps[2],
                "standalone": None, "qualification": "development_fixed_point"}
    if kind == "owner":
        expected["buffer_profile"] = "history.v1"
    exact(obj(directory / "manifest.json"), expected, "filesystem module manifest differs: " + kind)
    exact(read(directory / (name + ".hepta")), source, "filesystem module source bytes differ")
    image = read(directory / "module.image.bin")
    exact(sha(image), image_sha, "filesystem compiled image differs: " + kind)
    receipt = native_receipt(directory, "module", source=source, produced=image, producer=COMPILER)
    exact(receipt.get("produced_bytes"), len(image), "filesystem compiler product length differs")
    exact(receipt.get("produced_sha256"), image_sha, "filesystem compiler product identity differs")
    require(type(receipt.get("produced_image")) is str and Path(receipt["produced_image"]).name == "module.image.bin",
            "filesystem compiler product name differs")
    built = obj(directory / "build.json")
    exact(set(built), {"compile_receipt", "compiler_dependency", "whole_runtime_replaced"}, "filesystem compile fields differ")
    exact(built["compile_receipt"], receipt, "filesystem compile record differs from actual receipt")
    exact(built["whole_runtime_replaced"], False, "filesystem compile record claims whole runtime")
    exact(sha(canonical(built["compiler_dependency"])), DEPENDENCY, "filesystem compiler dependency differs")
    if dependency is not None:
        exact(built["compiler_dependency"], dependency, "filesystem compiler checkout differs")
    files = COMPILE_FILES + (name + ".hepta",)
    return {"source_sha256": sha(source), "image_sha256": image_sha, "manifest": file_record(directory / "manifest.json"),
            "artifacts": {file: file_record(directory / file) for file in files}}, image


def inspect_bootstrap(directory, *, dependency=None):
    directory = Path(directory)
    record = obj(directory / "bootstrap.json")
    for key, value in {"schema": "hepta.runtime.native-bootstrap.v1", "generation_sha256": COMPILER,
                       "qualification": "development_fixed_point", "matching_source_cold_qualified": False}.items():
        exact(record.get(key), value, "filesystem bootstrap declaration differs: " + key)
    exact(sha(canonical(record["dependency"])), DEPENDENCY, "filesystem bootstrap dependency differs")
    if dependency is not None:
        exact(record["dependency"], dependency, "filesystem bootstrap checkout differs")
    exact(record["dependency"]["commit"], COMMIT, "filesystem bootstrap commit differs")
    exact(record["dependency"]["tree"], TREE, "filesystem bootstrap tree differs")
    exact(record["compiler_source_sha256"], record["dependency"]["files"]["examples/hia_bootstrap/selfhost.hepta"],
          "filesystem bootstrap source differs")
    for name in BOOTSTRAP_FILES[1:]:
        exact(sha(read(directory / name)), COMPILER, "filesystem bootstrap generation differs")
    return {name: file_record(directory / name) for name in BOOTSTRAP_FILES}


def bundle_contract(directory, pins, modules, bootstrap, layout, inspection, receipt):
    directory = Path(directory)
    return {"schema": "hepta.runtime.native-filesystem-parity.v1", "target": "linux-x86_64",
            "compiler_commit": COMMIT, "compiler_tree": TREE, "compiler_sha256": COMPILER,
            "compiler_dependency_sha256": DEPENDENCY, "source_files": pins,
            "transport": "u64-length-requests-u32-returns-u64-extents", "dynamic_memory": True,
            "elf": "filesystem-parity.elf", "elf_sha256": ELF_SHA,
            "owner_manifest": "owner/manifest.json", "packer_manifest": "packer/manifest.json",
            "modules": modules, "bootstrap_artifacts": bootstrap, "layout": layout,
            "inspection": inspection, "pack_receipt": receipt,
            "pack_files": {name: file_record(directory / name) for name in PACK_FILES},
            "runtime_python_required": False, "runtime_libc_required": False,
            "public_filesystem_handlers_complete": False, "production_activated": False,
            "whole_runtime_replaced": False}


def inspect_bundle(manifest_path, *, source_root=ROOT, dependency=None):
    root = Path(source_root).resolve(strict=True)
    manifest_path = Path(manifest_path).absolute()
    directory = manifest_path.parent
    pins = source_pins(root)
    metadata = obj(manifest_path)
    modules, images = {}, {}
    for kind in ("owner", "packer"):
        filename = "filesystem_parity.hepta" if kind == "owner" else "filesystem_parity_packer.hepta"
        modules[kind], images[kind] = inspect_module(directory / kind, kind, read(root / "native" / filename),
                                                    dependency=dependency)
    bootstrap = inspect_bootstrap(directory / "bootstrap", dependency=dependency)
    layout = obj(root / "native/filesystem_parity_layout.json")
    exact(read(directory / "layout.json"), read(root / "native/filesystem_parity_layout.json"), "filesystem packaged layout differs")
    executable = read(directory / "filesystem-parity.elf")
    inspection = inspect_elf(executable, images["owner"])
    frame = b"HFSPPK02" + struct.pack("<Q", len(images["owner"])) + images["owner"]
    receipt = native_receipt(directory, "pack", source=frame, produced=executable, producer=PACKER_IMAGE)
    expected = bundle_contract(directory, pins, modules, bootstrap, layout, inspection, receipt)
    exact(metadata, expected, "filesystem bundle contract differs")
    exact(source_pins(root), pins, "filesystem sources changed during artifact inspection")
    return {"schema": "hepta.runtime.filesystem-parity-build-evidence.v1", "status": "PASS",
            "manifest": file_record(manifest_path), "source_files": pins, "modules": modules,
            "bootstrap_artifacts": bootstrap, "pack_files": expected["pack_files"], "inspection": inspection,
            "layout": file_record(directory / "layout.json"), "fresh_cold_qualified": False,
            "public_filesystem_handlers_complete": False, "whole_runtime_replaced": False}


def build_filesystem_parity(hepta, build_root, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    build_root = Path(build_root).resolve()
    pins = source_pins(root)
    exact(read(root / "scripts/hia_native_filesystem_parity_build.py"), read(__file__), "loaded filesystem builder differs")
    builder = NativeBuild(hepta, build_root)
    exact(sha(builder.bootstrap().read_bytes()), COMPILER, "filesystem compiler image differs")
    exact(sha(canonical(builder.identity)), DEPENDENCY, "filesystem compiler checkout differs")
    destination = build_root / "filesystem-parity" / sha(canonical(pins))
    manifest = destination / "manifest.json"
    if manifest.exists():
        inspect_bundle(manifest, source_root=root, dependency=builder.identity)
        builder._recheck()
        return manifest
    compiled = {}
    for kind in ("owner", "packer"):
        name = "filesystem-parity" if kind == "owner" else "filesystem-parity-packer"
        filename = "filesystem_parity.hepta" if kind == "owner" else "filesystem_parity_packer.hepta"
        path = build_root / "modules" / name / "manifest.json"
        if not path.exists():
            path = builder.compile(name, root / "native" / filename, standalone=None,
                                   buffer_profile="history.v1" if kind == "owner" else "standard")
        inspect_module(path.parent, kind, read(root / "native" / filename), dependency=builder.identity)
        compiled[kind] = path
    destination.mkdir(parents=True, mode=0o700)
    for kind, path in compiled.items():
        folder = destination / kind
        folder.mkdir(mode=0o700)
        name = "filesystem-parity" if kind == "owner" else "filesystem-parity-packer"
        for filename in COMPILE_FILES + (name + ".hepta",):
            write_new(folder / filename, read(path.parent / filename))
    (destination / "bootstrap").mkdir(mode=0o700)
    for filename in BOOTSTRAP_FILES:
        write_new(destination / "bootstrap" / filename, read(build_root / "bootstrap" / filename))
    write_new(destination / "layout.json", read(root / "native/filesystem_parity_layout.json"))
    owner = read(destination / "owner/module.image.bin")
    frame = b"HFSPPK02" + struct.pack("<Q", len(owner)) + owner
    from tools.qualify_hia_selfhost import invoke
    receipt, raw = invoke(destination, "pack", destination / "packer/module.image.bin", frame)
    count = receipt.get("core_u32")
    require(type(count) is int and count == ELF_BYTES, "filesystem packer rejected the owner image")
    executable = raw[:count]
    inspection = inspect_elf(executable, owner)
    native_receipt(destination, "pack", source=frame, produced=executable, producer=PACKER_IMAGE)
    modules = {}
    for kind in ("owner", "packer"):
        filename = "filesystem_parity.hepta" if kind == "owner" else "filesystem_parity_packer.hepta"
        modules[kind], _ = inspect_module(destination / kind, kind, read(root / "native" / filename), dependency=builder.identity)
    bootstrap = inspect_bootstrap(destination / "bootstrap", dependency=builder.identity)
    metadata = bundle_contract(destination, pins, modules, bootstrap,
                               obj(root / "native/filesystem_parity_layout.json"), inspection, receipt)
    write_new(destination / "filesystem-parity.elf", executable, 0o500)
    exact(source_pins(root), pins, "filesystem sources changed during build")
    builder._recheck()
    write_new(manifest, json_bytes(metadata))
    inspect_bundle(manifest, source_root=root, dependency=builder.identity)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("--hepta and --build-root or their HIA environment variables are required")
    print(json.dumps({"manifest": str(build_filesystem_parity(args.hepta, args.build_root,
                                                             source_root=args.source_root))}, sort_keys=True))
