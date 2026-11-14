"""Build real HIA flat images and syscall-only Linux executables.

Python is the explicit build driver, never part of an emitted executable.
The fixed-point bootstrap is development evidence, not Hepta's cold gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

HEPTA_COMMIT = "f33d8da316de8fdf27b504371f1a5310997ff548"
HEPTA_TREE = "378bc0dc613befc7006f1514bd2229357ae0d07c"
ABI = "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
MAX_IMAGE = 1 << 20
INPUT_BYTES = 8 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 32 << 20
HERE = Path(__file__).resolve().parents[1]


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_new(path: Path, raw: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30).stdout


def check_dependency(root: Path) -> dict:
    """Check the real tracked bytes, including changes hidden by index flags."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("HIA native build requires Linux x86-64")
    if _git(root, "rev-parse", "HEAD").strip().decode() != HEPTA_COMMIT:
        raise ValueError("Hepta dependency commit differs from the pinned compiler")
    if _git(root, "rev-parse", "HEAD^{tree}").strip().decode() != HEPTA_TREE:
        raise ValueError("Hepta dependency tree differs from the pinned compiler")
    raw = _git(root, "ls-tree", "-rz", "HEAD", "--", "hepta", "tools",
               "examples/hia_bootstrap", "docs/HIA_SELFHOST_CORE_SUPPORT.json")
    files = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, blob = metadata.split()
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ValueError("unsupported compiler source tree entry")
        relative = name.decode("utf-8")
        path = root / relative
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.resolve() != path:
            raise ValueError("compiler input must be a regular unsymlinked file")
        data = path.read_bytes()
        oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if oid != blob.decode() or bool(info.st_mode & 0o111) != (mode == b"100755"):
            raise ValueError("compiler tracked bytes/mode changed: " + relative)
        files[relative] = digest(data)
    if not files:
        raise ValueError("empty compiler source inventory")
    return {"commit": HEPTA_COMMIT, "tree": HEPTA_TREE, "files": files}


class NativeBuild:
    """One explicit compiler workspace, reused across module builds."""
    def __init__(self, hepta_root: str | Path, build_root: str | Path):
        self.hepta = Path(hepta_root).resolve(strict=True)
        self.root = Path(build_root).resolve()
        self.identity = check_dependency(self.hepta)
        for name, module in tuple(sys.modules.items()):
            if name == "hepta" or name.startswith("hepta.") or name == "tools" or name.startswith("tools."):
                location = getattr(module, "__file__", None)
                if location and not Path(location).resolve().is_relative_to(self.hepta):
                    raise ValueError("a different Hepta/tool package was already imported")
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(self.hepta))
        from tools.hia_selfhost_contract import validate_contract
        self.contract = validate_contract()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.compiler = None
        self.compiler_sha256 = None

    def _recheck(self):
        if check_dependency(self.hepta) != self.identity:
            raise ValueError("compiler dependency changed during build")
        from tools.hia_selfhost_contract import validate_contract
        if validate_contract() != self.contract:
            raise ValueError("compiler support source closure changed during build")

    def bootstrap(self) -> Path:
        """Build once, or verify all bytes in an existing completed workspace."""
        if self.compiler is not None:
            if digest(self.compiler.read_bytes()) != self.compiler_sha256:
                raise ValueError("admitted native compiler image changed")
            return self.compiler
        folder = self.root / "bootstrap"
        receipt = folder / "bootstrap.json"
        if receipt.exists():
            data = json.loads(receipt.read_bytes())
            if data.get("schema") != "hepta.runtime.native-bootstrap.v1" or data.get("dependency") != self.identity:
                raise ValueError("cached bootstrap compiler identity differs")
            expected = data.get("generation_sha256")
            if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
                raise ValueError("cached bootstrap has no exact generation identity")
            for label in ("B1", "B2", "B3"):
                if digest((folder / (label + ".image.bin")).read_bytes()) != expected:
                    raise ValueError("cached compiler generation changed")
            if data.get("qualification") != "development_fixed_point":
                raise ValueError("unknown compiler qualification scope")
            self.compiler = folder / "B3.image.bin"
            self.compiler_sha256 = expected
            return self.compiler
        folder.mkdir(mode=0o700)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        source = (self.hepta / "examples/hia_bootstrap/selfhost.hepta").read_bytes()
        seed, seed_receipt = build_seed(folder)
        previous = seed
        generations = []
        records = []
        for label in ("B1", "B2", "B3"):
            previous, row = compile_stage(folder, label, previous, source,
                image_format="seed-shared" if label == "B1" else "flat-x86-64")
            generations.append(previous.read_bytes())
            records.append(row)
        if not generations[0] == generations[1] == generations[2]:
            raise ValueError("native HIA compiler fixed point differs")
        self._recheck()
        write_new(receipt, json_bytes({"schema": "hepta.runtime.native-bootstrap.v1",
            "dependency": self.identity, "compiler_source_sha256": digest(source),
            "generation_sha256": digest(generations[2]), "qualification": "development_fixed_point",
            "matching_source_cold_qualified": False, "seed_receipt": seed_receipt,
            "generation_receipts": records}))
        self.compiler = previous
        self.compiler_sha256 = digest(generations[2])
        return previous

    def compile(self, name: str, source_path: str | Path, *, standalone: str | None = "filter") -> Path:
        """Return a manifest for a real HIA-compiled three-buffer component."""
        if type(name) is not str or not re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("invalid native module name")
        if standalone not in {None, "filter", "stdio"}:
            raise ValueError("unknown native transport")
        compiler = self.bootstrap()
        compiler_raw = compiler.read_bytes()
        original_path = Path(source_path).resolve(strict=True)
        if original_path.suffix != ".hepta":
            raise ValueError("native source must use .hepta")
        source = original_path.read_bytes()
        if not 0 < len(source) <= MAX_IMAGE:
            raise ValueError("HIA source is outside the pinned compiler capacity")
        from hepta.hia_agent_assembly import assemble_program
        document = assemble_program(source).as_dict()
        entry = document["functions"][0]
        if [p["type"] for p in entry["params"]] != ["readbuf", "mutbuf", "mutbuf"] or entry["returns"] != ["u32"]:
            raise ValueError("native module requires the three-buffer u32 entry ABI")
        if document.get("exports"):
            raise ValueError("native module flat profile forbids scalar ELF exports")
        folder = self.root / "modules" / name
        folder.parent.mkdir(exist_ok=True, mode=0o700)
        folder.mkdir(mode=0o700)
        write_new(folder / (name + ".hepta"), source)
        from tools.qualify_hia_selfhost import compile_stage, invoke
        image, compiled = compile_stage(folder, "module", compiler, source)
        image_raw = image.read_bytes()
        if image_raw.startswith(b"\x7fELF"):
            raise ValueError("native module requires a flat borrowed-buffer image")
        manifest = {"schema": "hepta.runtime.native-module.v1", "name": name,
            "abi": ABI, "target": "linux-x86_64", "compiler_commit": HEPTA_COMMIT,
            "compiler_sha256": digest(compiler_raw), "source": name + ".hepta",
            "source_sha256": digest(source), "image": image.name,
            "image_sha256": digest(image_raw), "input_capacity": INPUT_BYTES,
            "output_capacity": OUTPUT_BYTES, "workspace_capacity": WORKSPACE_BYTES,
            "qualification": "development_fixed_point", "standalone": None}
        if standalone is not None:
            packer_source = HERE / "native" / ("stdio_packer.hepta" if standalone == "stdio" else "filter_packer.hepta")
            packer_bytes = packer_source.read_bytes()
            packer_cache = self.root / "packers" / digest(packer_bytes)
            if packer_cache.exists():
                packer_info = json.loads((packer_cache / "manifest.json").read_bytes())
                packer = packer_cache / "packer.image.bin"
                if (packer_info.get("source_sha256") != digest(packer_bytes)
                    or packer_info.get("compiler_sha256") != digest(compiler_raw)
                    or digest(packer.read_bytes()) != packer_info.get("image_sha256")):
                    raise ValueError("cached transport packer identity differs")
            else:
                packer_cache.mkdir(parents=True, mode=0o700)
                packer, packed_compile = compile_stage(packer_cache, "packer", compiler, packer_bytes)
                write_new(packer_cache / "source.hepta", packer_bytes)
                write_new(packer_cache / "manifest.json", json_bytes({
                    "source_sha256": digest(packer_bytes), "compiler_sha256": digest(compiler_raw),
                    "image_sha256": digest(packer.read_bytes()), "compile_receipt": packed_compile}))
            frame = struct.pack("<2Q", int.from_bytes(b"HIAFLT01", "little"), len(image_raw)) + image_raw
            record, raw = invoke(folder, "pack", packer, frame)
            count = record.get("core_u32")
            if (record.get("status") != "returned" or type(record.get("abi_status")) is not int
                or record["abi_status"] != 0 or type(count) is not int or not 0 < count <= min(MAX_IMAGE, len(raw))
                or record.get("source_unchanged") is not True or record.get("input_sha256") != digest(frame)
                or record.get("artifact_sha256") != digest(packer.read_bytes())
                or type(record.get("result_u64")) is not int or record["result_u64"] != count
                or record.get("output_sha256") != digest(raw)
                or type(record.get("input_bytes")) is not int or record["input_bytes"] != len(frame)
                or record.get("forbidden_compiler_modules_loaded") != []):
                raise ValueError("native HIA transport packer rejected the complete receipt")
            executable = raw[:count]
            from tools.qualify_hia_selfhost_cli import inspect_executable
            inspection = inspect_executable(executable)
            write_new(folder / (name + ".elf"), executable, 0o500)
            manifest["standalone"] = {"transport": standalone, "path": name + ".elf",
                "sha256": digest(executable), "packer_source_sha256": digest(packer_bytes),
                "runtime_python_required": False, "runtime_libc_required": False,
                "inspection": inspection, "pack_receipt": record}
        if original_path.read_bytes() != source or compiler.read_bytes() != compiler_raw:
            raise ValueError("native build input changed")
        self._recheck()
        write_new(folder / "build.json", json_bytes({"compile_receipt": compiled,
            "compiler_dependency": self.identity, "whole_runtime_replaced": False}))
        path = folder / "manifest.json"
        write_new(path, json_bytes(manifest))
        return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--name")
    parser.add_argument("--transport", choices=("filter", "stdio", "image"), default="filter")
    args = parser.parse_args()
    if bool(args.source) != bool(args.name):
        parser.error("--source and --name are required together")
    builder = NativeBuild(args.hepta, args.build_root)
    result = builder.compile(args.name, args.source,
        standalone=None if args.transport == "image" else args.transport) if args.source else builder.bootstrap()
    print(json.dumps({"result": str(result), "compiler_commit": HEPTA_COMMIT}))


if __name__ == "__main__":
    main()
