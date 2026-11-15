#!/usr/bin/env python3
"""Build the flat capture-path HIA owner and read its complete byte evidence.

The guarded cases are literal ABI checks, not original Rust comparisons.  The
reader imports no compiler, loader or FFI module and never executes an image.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_path_build.py"
OWNER = "native/shell_capture_path.hepta"
NAME = "shell-capture-path-owner"
SCHEMA = "hepta.runtime.shell-capture-path.v1"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
DEPENDENCY = "adebfbbab857cd87e9b8f975f522e51b7cd1ed8fd65a8108d29e941651b28b06"
GATE = "52682cdf9e13a3eaf3ad8f168112531b2f918ed6139f06b769665a2ddaec05d1"
RELOCATION = {"f10": "f14", "f11": "f15", "f63": "f16", "f64": "f17", "f65": "f18"}
INPUTS = (OWNER, "native/shell_capture_path_abi.md", "native/shell_capture_path_reuse.json",
          "native/shell_gate.hepta", DRIVER, "scripts/hia_native_build.py", "scripts/hia_native_loader.py")
INVALID, CAPACITY = 0xFFFFFFFF, 0xFFFFFFFE
DRIVER_BYTES = Path(__file__).read_bytes()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def integer(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def bad(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def ordinary(path):
    path = Path(path).absolute()
    need(".." not in path.parts, "noncanonical input path")
    for parent in reversed(path.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), "input parent is not an ordinary directory")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode), "input is not an ordinary file")
        raw = handle.read()
        after = os.fstat(handle.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size, "input changed while read")
    return raw


def member(root, name):
    need(type(name) is str and name and not Path(name).is_absolute()
         and all(part not in ("", ".", "..") for part in name.split("/")), "invalid evidence member")
    return Path(root) / name


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def snapshot(root):
    result = {name: ordinary(member(root, name)) for name in INPUTS}
    need(result[DRIVER] == DRIVER_BYTES, "executing capture builder differs from source root")
    return result


def scope():
    return {"native_flat_image": True, "literal_guarded_abi_checks": True,
            "host_runtime_required": False, "actual_environment_or_pid_acquisition": False,
            "actual_atomic_counter_or_capture_creation": False, "original_rust_compared": False,
            "matching_source_cold_qualified": False, "whole_runtime_replaced": False,
            "production_activated": False, "old_stack_removal_qualified": False}


def functions(raw):
    matches = list(re.finditer(rb"(?m)^fn (f[0-9]+)\(", raw))
    result = {}
    for index, match in enumerate(matches):
        name = match.group(1).decode()
        need(name not in result, "duplicate HIA function")
        end = raw.index(b"\nend\n", match.start()) + 5
        limit = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        need(end <= limit and not raw[end:limit].strip(), "unexpected bytes between HIA functions")
        result[name] = raw[match.start():end]
    need(result and "f0" in result, "HIA entry missing")
    return result


def reuse_proof(source):
    proof = decode(source["native/shell_capture_path_reuse.json"])
    need(proof.get("schema") == "hepta.runtime.shell-capture-path-reuse.v1", "reuse schema differs")
    need(sha(source["native/shell_gate.hepta"]) == GATE, "original path helper owner differs")
    for key, value in {"source": "native/shell_gate.hepta", "source_sha256": GATE,
                       "target": OWNER, "target_sha256": sha(source[OWNER]), "compiler_commit": COMPILER}.items():
        same(proof.get(key), value, "reuse binding differs: " + key)
    same(proof.get("relocation"), RELOCATION, "reuse function relocation differs")
    rows = proof.get("functions")
    need(type(rows) is list and len(rows) == len(RELOCATION), "reuse function set incomplete")
    original, target = functions(source["native/shell_gate.hepta"]), functions(source[OWNER])
    seen, checked = set(), []
    for row in rows:
        old, new = row["original_function"], row["new_function"]
        need(old in RELOCATION and new == RELOCATION[old] and old not in seen, "reuse function identity differs")
        seen.add(old)
        before, after = original[old], target[new]
        need(row["original_body"].encode() == before and row["new_body"].encode() == after,
             "reuse body differs from actual source")
        need(row["original_body_sha256"] == sha(before) and row["new_body_sha256"] == sha(after)
             and row.get("only_function_and_call_id_relocation") is True, "reuse body receipt differs")
        calls = re.findall(rb'"function"\s*:\s*"(f[0-9]+)"', before)
        need(all(call.decode() in RELOCATION for call in calls), "reuse original call closure incomplete")
        def replace(match):
            prefix, name = match.groups()
            return prefix + RELOCATION[name.decode()].encode()
        relocated = re.sub(rb'(?m)(^fn |"function"\s*:\s*")(f[0-9]+)\b', replace, before)
        need(relocated == after, "reuse changed bytes beyond function and call IDs")
        checked.append({"original_function": old, "new_function": new,
                        "original": pin(before), "relocated": pin(after)})
    same(sorted(seen), sorted(RELOCATION), "reuse omitted a function")
    for body in target.values():
        need(all(name.decode() in target for name in re.findall(rb'"function"\s*:\s*"(f[0-9]+)"', body)),
             "target HIA call closure incomplete")
    return {"manifest_sha256": sha(source["native/shell_capture_path_reuse.json"]),
            "functions": checked, "original_source_sha256": GATE,
            "only_function_and_call_id_relocation": True}


def request(op, first=b"", second=b"", *, present=0, pid=0, sequence=0):
    return b"HSHCPQ01" + struct.pack("<7Q", op, present, pid, sequence,
                                    len(first), len(second), 0) + first + second


def response(op, flag=0, sequence=0, fields=(b"", b"", b"", b"")):
    return b"HSHCPR01" + struct.pack("<9Q", op, 80 + sum(map(len, fields)), flag,
                                    sequence, *map(len, fields), 0) + b"".join(fields)


def entry_specs():
    """Independent literal expected bytes; never a host Path implementation."""
    capture = response(3, sequence=10, fields=(b"/tmp/octofs-jobs-7", b"7-9",
        b"/tmp/octofs-jobs-7/7-9.stdout.log", b"/tmp/octofs-jobs-7/7-9.stderr.log"))
    empty_capture = response(3, sequence=0, fields=(b"octofs-jobs-0", b"0-18446744073709551615",
        b"octofs-jobs-0/0-18446744073709551615.stdout.log",
        b"octofs-jobs-0/0-18446744073709551615.stderr.log"))
    raw_capture = response(3, sequence=1, fields=(b"/\xff/\x00//octofs-jobs-4294967295", b"4294967295-0",
        b"/\xff/\x00//octofs-jobs-4294967295/4294967295-0.stdout.log",
        b"/\xff/\x00//octofs-jobs-4294967295/4294967295-0.stderr.log"))
    semantic = [
        ("equal-empty", request(1), response(1, 1)),
        ("equal-leading-dot", request(1, b"./a", b"a"), response(1)),
        ("equal-components", request(1, b"a//./b/", b"a/b"), response(1, 1)),
        ("parent-preserved-interior", request(2, b"a//b/c"), response(2, 1, fields=(b"a//b", b"", b"", b""))),
        ("parent-root-none", request(2, b"///./"), response(2)),
        ("parent-leading-dot", request(2, b"./a"), response(2, 1, fields=(b".", b"", b"", b""))),
        ("parent-raw-bytes", request(2, b"/\xff/\x00/x"), response(2, 1, fields=(b"/\xff/\x00", b"", b"", b""))),
        ("capture-absent", request(3, pid=7, sequence=9), capture),
        ("capture-empty-wrap", request(3, present=1, sequence=(1 << 64) - 1), empty_capture),
        ("capture-raw", request(3, b"/\xff/\x00//", present=1, pid=0xFFFFFFFF), raw_capture),
    ]
    rows = [{"name": n, "category": "literal", "input": i, "expected": o,
             "output_capacity": len(o) + 23, "workspace_capacity": 160, "return": 80}
            for n, i, o in semantic]
    def field(raw, at, value):
        return raw[:at] + struct.pack("<Q", value) + raw[at + 8:]
    normal = request(1)
    invalid = [("empty", b""), ("short", normal[:63]), ("magic", b"X" + normal[1:]),
        ("operation", request(4)), ("trailing", normal + b"x"),
        ("overclaimed", field(normal, 40, (1 << 64) - 1)), ("reserved", field(normal, 56, 1)),
        ("eq-presence", request(1, present=1)), ("parent-second", request(2, second=b"x")),
        ("presence-range", request(3, present=2)), ("pid-range", request(3, pid=1 << 32)),
        ("absent-with-bytes", request(3, b"x"))]
    rows += [{"name": "invalid-" + n, "category": "transport-invalid", "input": i, "expected": None,
              "output_capacity": 127, "workspace_capacity": 160, "return": INVALID} for n, i in invalid]
    capacity = [
        ("output-zero", normal, 0, 160, CAPACITY, None),
        ("output-short", normal, 79, 160, CAPACITY, None),
        ("output-exact", normal, 80, 160, 80, response(1, 1)),
        ("capture-short", request(3, pid=7, sequence=9), len(capture) - 1, 160, CAPACITY, None),
        ("capture-exact", request(3, pid=7, sequence=9), len(capture), 160, 80, capture),
        ("workspace-zero", normal, 111, 0, CAPACITY, None),
        ("workspace-short", normal, 111, 127, CAPACITY, None),
        ("workspace-exact", normal, 111, 128, 80, response(1, 1)),
        ("invalid-before-capacity", b"X" + normal[1:], 111, 0, INVALID, None)]
    rows += [{"name": n, "category": "transport-capacity", "input": i, "expected": expected,
              "output_capacity": out, "workspace_capacity": work, "return": code}
             for n, i, out, work, code, expected in capacity]
    need(len(rows) == 31 and len({row["name"] for row in rows}) == len(rows), "guarded case registry differs")
    return rows


def guard(label, raw):
    index = ("input", "output", "workspace").index(label)
    return bytes([0xC1 + index]) * 16 + raw + bytes([0xD1 + index]) * 16


def read_entries(folder, metadata, module_sha):
    raw = ordinary(folder / "entries.json")
    rows = decode(raw)
    specs = entry_specs()
    need(type(rows) is list and len(rows) == len(specs), "guarded native entry set incomplete")
    previous, addresses = {}, {}
    prior_end, process_id = 0, None
    for index, (row, spec) in enumerate(zip(rows, specs)):
        need(type(row) is dict, "guarded entry is not an object")
        expected_fields = {"index": index, "name": spec["name"], "category": spec["category"],
            "input_capacity": len(spec["input"]), "output_capacity": spec["output_capacity"],
            "workspace_capacity": spec["workspace_capacity"], "return": spec["return"],
            "manifest_sha256": module_sha, "source_sha256": metadata["source_sha256"],
            "image_sha256": metadata["image_sha256"]}
        for name, value in expected_fields.items():
            same(row.get(name), value, "guarded entry binding differs: " + name)
        need(integer(row.get("pid"), 1) and integer(row.get("started_ns"), 1)
             and integer(row.get("finished_ns"), row["started_ns"])
             and row["started_ns"] >= prior_end, "guarded entry timing or process identity differs")
        process_id = row["pid"] if process_id is None else process_id
        need(row["pid"] == process_id, "guarded calls came from different processes")
        prior_end = row["finished_ns"]
        wc = spec["workspace_capacity"]
        need(integer(row.get("workspace_address"), 1), "guarded workspace address missing")
        same(row.get("workspace_reused"), wc in previous, "workspace reuse record differs")
        if wc in addresses:
            need(row["workspace_address"] == addresses[wc], "workspace reuse changed allocation")
        addresses[wc] = row["workspace_address"]
        files, arrays = {}, {}
        for label in ("input", "output", "workspace"):
            for phase in ("before", "after"):
                relative = f"entries/{index:03d}/{label}.{phase}.bin"
                body = ordinary(folder / relative)
                files[relative] = pin(body)
                arrays[label + "_" + phase] = body
        same(row.get("files"), files, "complete guarded array file identity differs")
        need(arrays["input_before"] == guard("input", spec["input"])
             and arrays["input_after"] == arrays["input_before"], "input or input guards changed")
        initial = guard("output", b"\xa7" * spec["output_capacity"])
        need(arrays["output_before"] == initial, "output initial bytes differ")
        expected = spec["expected"]
        if expected is None:
            need(arrays["output_after"] == initial, "refusal changed complete output")
        else:
            need(len(expected) <= spec["output_capacity"] and struct.unpack_from("<Q", expected, 16)[0] == len(expected),
                 "literal response extent differs")
            need(arrays["output_after"] == guard("output", expected + b"\xa7" * (spec["output_capacity"] - len(expected))),
                 "successful complete output, tail or guards differ")
        initial_work = previous.get(wc, guard("workspace", b"\x5c" * wc))
        after_work = arrays["workspace_after"]
        need(arrays["workspace_before"] == initial_work and len(after_work) == wc + 32,
             "workspace dirty reuse or capacity differs")
        need(after_work[:16] == initial_work[:16] and after_work[-16:] == initial_work[-16:]
             and after_work[16 + min(128, wc):-16] == initial_work[16 + min(128, wc):-16],
             "workspace outside scratch region changed")
        previous[wc] = after_work
    return {"entries": len(rows), "literal_semantic_entries": 10, "transport_entries": 21,
            "complete_guarded_arrays": 6 * len(rows), "entries_sha256": sha(raw),
            "dirty_workspace_reuse": True, "original_rust_compared": False}


def native_component(path, source):
    value = decode(ordinary(path))
    expected = {"schema": "hepta.runtime.native-module.v1", "name": NAME,
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": COMPILER, "compiler_sha256": B3, "source": NAME + ".hepta",
        "source_sha256": sha(source), "image": "module.image.bin",
        "input_capacity": 8 << 20, "output_capacity": 8 << 20, "workspace_capacity": 32 << 20,
        "qualification": "development_fixed_point", "standalone": None}
    image = ordinary(path.parent / "module.image.bin")
    need(0 < len(image) <= 1 << 20 and not image.startswith(b"\x7fELF"), "native flat image shape differs")
    expected["image_sha256"] = sha(image)
    same(value, expected, "native owner manifest differs")
    need(ordinary(path.parent / (NAME + ".hepta")) == source, "compiled source snapshot differs")
    built = decode(ordinary(path.parent / "build.json"))
    receipt = decode(ordinary(path.parent / "module.receipt.json"))
    same(receipt, built.get("compile_receipt"), "actual compiler receipt copies differ")
    input_bytes = ordinary(path.parent / "module.input.bin")
    output_bytes = ordinary(path.parent / "module.output.bin")
    need(input_bytes == source and len(output_bytes) >= len(image)
         and output_bytes[:len(image)] == image, "actual compiler input/output bytes differ")
    checks = {"status": "returned", "abi_status": 0, "core_u32": len(image), "result_u64": len(image),
        "source_unchanged": True, "forbidden_compiler_modules_loaded": [], "input_bytes": len(source),
        "input_sha256": sha(source), "artifact_sha256": B3, "image_sha256": B3,
        "format": "flat-x86-64", "produced_bytes": len(image), "produced_sha256": sha(image),
        "output_sha256": sha(output_bytes)}
    for key, expected_value in checks.items():
        same(receipt.get(key), expected_value, "actual native compilation differs: " + key)
    need(built.get("whole_runtime_replaced") is False, "native compilation scope differs")
    bootstrap = path.parent.parent.parent / "bootstrap"
    boot = decode(ordinary(bootstrap / "bootstrap.json"))
    need(boot.get("schema") == "hepta.runtime.native-bootstrap.v1"
         and boot.get("qualification") == "development_fixed_point"
         and boot.get("matching_source_cold_qualified") is False
         and boot.get("generation_sha256") == B3, "fixed compiler bootstrap differs")
    same(boot.get("dependency"), built.get("compiler_dependency"), "compiler dependency receipts differ")
    dependency = boot["dependency"]
    need(dependency.get("commit") == COMPILER and dependency.get("tree") == TREE
         and type(dependency.get("files")) is dict and dependency["files"], "compiler source identity incomplete")
    need(sha(encoded(dependency)) == DEPENDENCY, "fixed compiler complete source closure differs")
    for label in ("B1", "B2", "B3"):
        need(sha(ordinary(bootstrap / (label + ".image.bin"))) == B3, "fixed compiler generation bytes differ")
    return value, {"manifest": pin(ordinary(path)), "image": pin(image),
        "build": pin(ordinary(path.parent / "build.json")),
        "compile_receipt": pin(ordinary(path.parent / "module.receipt.json")),
        "input": pin(input_bytes), "output": pin(output_bytes),
        "bootstrap": pin(ordinary(bootstrap / "bootstrap.json"))}


def read_evidence(manifest, *, source_root=ROOT):
    """Pure source, compiler, reuse and complete guarded-array admission."""
    manifest, source_root = Path(manifest).absolute(), Path(source_root).absolute()
    folder, build_root = manifest.parent, manifest.parent.parent
    need(manifest.name == "manifest.json" and folder.name == "shell-capture-path", "capture TOP location differs")
    metadata = decode(ordinary(manifest))
    need(metadata.get("schema") == SCHEMA and metadata.get("status") == "PASS", "capture build incomplete")
    same(metadata.get("scope"), scope(), "capture build scope differs")
    source = snapshot(source_root)
    same(metadata.get("sources"), {name: pin(raw) for name, raw in source.items()}, "capture source closure changed")
    for name, raw in source.items():
        need(ordinary(member(folder / "source-snapshots", name)) == raw, "capture source snapshot changed: " + name)
    proof = reuse_proof(source)
    same(metadata.get("reuse_proof"), proof, "capture reuse proof changed")
    owner_name = "modules/" + NAME + "/manifest.json"
    need(metadata.get("owner_manifest") == owner_name, "capture owner path differs")
    owner = member(build_root, owner_name)
    owner_raw = ordinary(owner)
    need(metadata.get("owner_manifest_sha256") == sha(owner_raw), "capture owner manifest pin differs")
    owner_metadata, compiled = native_component(owner, source[OWNER])
    for key in ("source_sha256", "image_sha256"):
        need(metadata.get(key) == owner_metadata[key], "capture TOP owner byte identity differs")
    build_raw = ordinary(folder / "build-evidence.json")
    need(metadata.get("build_evidence_sha256") == sha(build_raw), "capture build receipt pin differs")
    built = decode(build_raw)
    need(built.get("status") == "PASS" and built.get("error") is None, "capture actual build did not complete")
    same(built.get("scope"), scope(), "capture actual build scope differs")
    same(built.get("sources"), metadata["sources"], "capture original build sources differ")
    same(built.get("compiled"), compiled, "capture compilation full byte receipts differ")
    need(type(built.get("compiler_workspace_preexisted")) is bool, "compiler cache provenance missing")
    need(integer(built.get("pid"), 1) and integer(built.get("started_ns"), 1)
         and integer(built.get("finished_ns"), built["started_ns"]), "capture actual build timing invalid")
    hepta = Path(built["compiler_source_root"])
    need(hepta.is_absolute(), "compiler source root is not absolute")
    dependency = decode(ordinary(build_root / "bootstrap/bootstrap.json"))["dependency"]
    for name, expected in dependency["files"].items():
        need(sha(ordinary(member(hepta, name))) == expected, "compiler source bytes changed: " + name)
    entries = read_entries(folder, owner_metadata, sha(owner_raw))
    same(built.get("guarded_checks"), entries, "capture guarded build record differs")
    same(metadata.get("guarded_entry_count"), entries["entries"], "capture guarded entry count differs")
    rows = decode(ordinary(folder / "entries.json"))
    need(all(row["pid"] == built["pid"] and built["started_ns"] <= row["started_ns"]
             <= row["finished_ns"] <= built["finished_ns"] for row in rows), "capture entry is outside actual build lifetime")
    return {"schema": "hepta.runtime.shell-capture-path-read.v1", "status": "PASS",
            "manifest_sha256": sha(ordinary(manifest)), "owner_manifest": str(owner),
            "owner_manifest_sha256": sha(owner_raw), "source_sha256": owner_metadata["source_sha256"],
            "image_sha256": owner_metadata["image_sha256"], "compiler_sha256": B3,
            "reuse_function_count": len(RELOCATION), "guarded_checks": entries, **scope()}


def import_build_module(root, name, source):
    path = root / ("scripts/" + name + ".py")
    need(ordinary(path) == source, "build module changed before import")
    spec = importlib.util.spec_from_file_location("_capture_" + name, path)
    need(spec is not None and spec.loader is not None, "build module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    need(ordinary(path) == source, "build module changed during import")
    return module


def execute_entries(folder, owner, metadata, loader):
    import ctypes
    module_sha = sha(ordinary(owner))
    native = loader.NativeModule(owner, manifest_sha256=module_sha)
    rows, workspaces = [], {}
    for index, spec in enumerate(entry_specs()):
        wc, oc = spec["workspace_capacity"], spec["output_capacity"]
        reused = wc in workspaces
        def array(label, raw):
            body = guard(label, raw)
            return (ctypes.c_ubyte * len(body)).from_buffer_copy(body)
        if not reused:
            workspaces[wc] = array("workspace", b"\x5c" * wc)
        arrays = {"input": array("input", spec["input"]), "output": array("output", b"\xa7" * oc),
                  "workspace": workspaces[wc]}
        files = {}
        for label, item in arrays.items():
            name = f"entries/{index:03d}/{label}.before.bin"
            raw = bytes(item)
            create(folder / name, raw)
            files[name] = pin(raw)
        started = time.monotonic_ns()
        with native._lock:
            returned = int(native._entry(ctypes.addressof(arrays["input"]) + 16, len(spec["input"]),
                ctypes.addressof(arrays["output"]) + 16, oc, ctypes.addressof(arrays["workspace"]) + 16, wc))
        finished = time.monotonic_ns()
        for label, item in arrays.items():
            name = f"entries/{index:03d}/{label}.after.bin"
            raw = bytes(item)
            create(folder / name, raw)
            files[name] = pin(raw)
        rows.append({"index": index, "name": spec["name"], "category": spec["category"],
            "input_capacity": len(spec["input"]), "output_capacity": oc, "workspace_capacity": wc,
            "return": returned, "manifest_sha256": module_sha, "source_sha256": metadata["source_sha256"],
            "image_sha256": metadata["image_sha256"], "files": files, "pid": os.getpid(),
            "started_ns": started, "finished_ns": finished,
            "workspace_address": ctypes.addressof(arrays["workspace"]) + 16, "workspace_reused": reused})
        (folder / "entries.json").write_bytes(encoded(rows))
    need(sha(ordinary(owner)) == module_sha, "module manifest changed during guarded calls")
    return read_entries(folder, metadata, module_sha)


def build_shell_capture_path(hepta, build_root, *, source_root=ROOT):
    source_root, build_root = Path(source_root).absolute(), Path(build_root).absolute()
    hepta = Path(hepta).absolute()
    folder = build_root / "shell-capture-path"
    need(not folder.exists() and not folder.is_symlink(), "capture build requires a fresh output folder")
    owner_path = build_root / "modules" / NAME / "manifest.json"
    need(not owner_path.parent.exists() and not owner_path.parent.is_symlink(), "capture owner output already exists")
    folder.mkdir(parents=True, mode=0o700)
    for parent in (folder, *folder.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), "capture build parent is not an ordinary directory")
    report = {"status": "RUNNING", "error": None, "scope": scope(), "pid": os.getpid(),
        "started_ns": time.monotonic_ns(), "compiler_source_root": str(hepta),
        "compiler_workspace_preexisted": (build_root / "bootstrap").exists()}
    def save():
        (folder / "build-evidence.json").write_bytes(encoded(report))
    save()
    try:
        source = snapshot(source_root)
        report["sources"] = {name: pin(raw) for name, raw in source.items()}
        proof = reuse_proof(source)
        for name, raw in source.items():
            create(member(folder / "source-snapshots", name), raw)
        save()
        sys.dont_write_bytecode = True
        build_module = import_build_module(source_root, "hia_native_build", source["scripts/hia_native_build.py"])
        loader = import_build_module(source_root, "hia_native_loader", source["scripts/hia_native_loader.py"])
        builder = build_module.NativeBuild(hepta, build_root)
        compiler = builder.bootstrap()
        need(sha(ordinary(compiler)) == B3, "actual compiler is not the fixed admitted B3")
        owner = builder.compile(NAME, member(folder / "source-snapshots", OWNER), standalone=None)
        need(owner == owner_path, "actual native build owner location differs")
        native, report["compiled"] = native_component(owner, source[OWNER])
        save()
        report["guarded_checks"] = execute_entries(folder, owner, native, loader)
        need(snapshot(source_root) == source, "capture source changed during build")
        builder._recheck()
        report["status"] = "PASS"
        report["finished_ns"] = time.monotonic_ns()
        save()
        top = {"schema": SCHEMA, "status": "PASS", "scope": scope(), "sources": report["sources"],
            "owner_manifest": owner.relative_to(build_root).as_posix(),
            "owner_manifest_sha256": sha(ordinary(owner)), "source_sha256": native["source_sha256"],
            "image_sha256": native["image_sha256"], "reuse_proof": proof,
            "guarded_entry_count": report["guarded_checks"]["entries"],
            "build_evidence_sha256": sha(ordinary(folder / "build-evidence.json"))}
        manifest = folder / "manifest.json"
        create(manifest, encoded(top))
        evidence = read_evidence(manifest, source_root=source_root)
        create(folder / "read-evidence.json", encoded(evidence))
        return manifest
    except BaseException as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
        report["finished_ns"] = time.monotonic_ns()
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--read-only", type=Path)
    args = parser.parse_args()
    try:
        if args.read_only is not None:
            need(args.hepta is None and args.build is None, "read-only does not accept build arguments")
            result = read_evidence(args.read_only, source_root=args.source_root)
        else:
            need(args.hepta is not None and args.build is not None, "--hepta and --build are required")
            manifest = build_shell_capture_path(args.hepta, args.build, source_root=args.source_root)
            result = {"status": "PASS", "manifest": str(manifest),
                      "evidence": read_evidence(manifest, source_root=args.source_root)}
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except BaseException as error:
        print(json.dumps({"status": "FAIL", "error": type(error).__name__ + ": " + str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
