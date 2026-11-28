"""Read and compare complete retained bytes. This module never executes code."""
from __future__ import annotations

import gzip
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import tarfile
import tomllib

from cases import calls, expected, frame, initial_output, initial_workspace, read_exact, read_trace, versions, NO_SEMANTIC
from common import (BASE, COMPILER_COMMIT, COMPILER_TREE, SDK_MODEL_SHA, SOURCE_SHA, TARGET_COMMIT,
                    document, encoded, packet, packets, read, require, safe_relative, sha, source_evidence, tree_files)

LIMITS = {"native-build": 300, "native-replay": 60, "rustc-version": 30,
          "cargo-version": 30, "cargo-build": 300, "cargo-metadata": 120, "original-replay": 60}
MODULE = "build/modules/context-protocol-policy"


def process(capture, label):
    record = document(capture / "processes" / (label + ".json"))
    require(record["schema"] == "hepta.runtime.context-protocol-process.v1" and record["label"] == label, "process identity")
    require(record["timeout_seconds"] == LIMITS[label], "process deadline changed")
    require(record["started"] is True and record["start_new_session"] is True and
            record["timed_out"] is False and type(record["returncode"]) is int and record["returncode"] == 0,
            "unsuccessful actual process")
    require(type(record["pid"]) is int and record["pid"] > 1 and record["pgid"] == record["pid"] and
            type(record["parent_pid"]) is int and record["parent_pid"] > 1, "process custody")
    require(type(record["elapsed_ns"]) is int and 0 < record["elapsed_ns"] <= (LIMITS[label] + 1) * 1_000_000_000,
            "process elapsed or deadline record")
    require("failure" not in record, "failed process receipt")
    for key in ("stdout", "stderr"):
        member = "processes/" + label + "." + key
        raw = read(capture / member)
        require(record[key] == {"path": member, "bytes": len(raw), "sha256": sha(raw)}, "process complete stream changed")
    if label == "original-replay":
        require(record["stdin"] == "semantic-input.bin" and record["stdin_sha256"] == sha(read(capture / "semantic-input.bin")), "original stdin custody")
    else:
        require(record["stdin"] is None and record["stdin_sha256"] is None, "unexpected process input")
    argv = record["command"]
    require(type(argv) is list and all(type(part) is str for part in argv), "process argv")
    if label in ("native-build", "native-replay"):
        name = "build.py" if label == "native-build" else "native.py"
        require(argv[1:4] == ["-I", "-S", "-B"] and argv[4].endswith("/" + BASE + "/" + name), "native process source dispatch")
        require("--source-pins-sha256" in argv, "native process source pin missing")
    elif label == "rustc-version":
        require(argv[1:] == ["+1.95.0", "--version", "--verbose"], "rustc version command")
    elif label == "cargo-version":
        require(argv[1:] == ["+1.95.0", "--version"], "cargo version command")
    elif label == "cargo-build":
        require(argv[1:4] == ["+1.95.0", "build", "--locked"] and argv[4:] == ["--bin", "g5-target-context-oracle"], "locked original build command")
    elif label == "cargo-metadata":
        require(argv[1:] == ["+1.95.0", "metadata", "--locked", "--format-version", "1"], "locked original metadata command")
    elif label == "original-replay":
        require(len(argv) == 1 and argv[0].endswith("/cargo-target/debug/g5-target-context-oracle"), "actual original replay command")
    return record


def git_tree(raw):
    result = {}
    at = 0
    while at < len(raw):
        space, zero = raw.index(b" ", at), raw.index(b"\0", at)
        require(space < zero and zero + 21 <= len(raw), "Git tree framing")
        name, mode = raw[space + 1:zero].decode(), raw[at:space].decode()
        require(name not in result and name not in (".", "..") and "/" not in name, "Git tree name")
        result[name] = (mode, raw[zero + 1:zero + 21].hex())
        at = zero + 21
    require(at == len(raw), "Git tree complete extent")
    return result


def compiler_sources(capture, dependency):
    proof = document(capture / "compiler-source.json")
    require(proof["commit"] == COMPILER_COMMIT and proof["tree"] == COMPILER_TREE, "compiler source identity")
    require(dependency == {"commit": COMPILER_COMMIT, "tree": COMPILER_TREE,
                           "files": {name: row["sha256"] for name, row in proof["files"].items()}}, "compiler source dependency closure")
    objects = {}

    def obj(kind, oid):
        key = kind + ":" + oid
        if key not in objects:
            raw = read(capture / "compiler-git" / (oid + "." + kind))
            require(hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid,
                    "compiler immutable Git object changed")
            objects[key] = raw
        return objects[key]

    require(obj("commit", COMPILER_COMMIT).startswith(b"tree " + COMPILER_TREE.encode() + b"\n"), "compiler root tree differs")
    for name, row in proof["files"].items():
        parts = safe_relative(name).split("/")
        oid = COMPILER_TREE
        for component in parts[:-1]:
            mode, oid = git_tree(obj("tree", oid))[component]
            require(mode == "40000", "compiler ancestor is not a tree")
        mode, blob = git_tree(obj("tree", oid))[parts[-1]]
        require(mode == row["git_mode"] and blob == row["git_blob"] and mode in ("100644", "100755"), "compiler Git source binding")
        path = capture / "compiler-source" / name
        raw = read(path)
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "compiler complete source changed")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == blob, "compiler original source blob changed")
        require(bool(path.stat().st_mode & 0o111) == (mode == "100755"), "compiler source executable mode changed")
    require(sorted(objects) == proof["git_objects"], "compiler Git source object coverage")
    require(set(tree_files(capture / "compiler-source")) == set(proof["files"]), "compiler source file set")
    contract = document(capture / "compiler-source/docs/HIA_SELFHOST_CORE_SUPPORT.json")
    for name, digest in contract["source_identity"]["files"].items():
        require(dependency["files"].get(name) == digest, "compiler cold source identity differs")
    return proof


def compile_receipt(capture, folder, label, compiler, source, output_name, image_format):
    directory = capture / folder
    record = document(directory / (label + ".receipt.json"))
    request = document(directory / (label + ".request.json"))
    input_raw = read(directory / (label + ".input.bin"))
    output = read(directory / (label + ".output.bin"))
    produced = read(directory / output_name)
    require(input_raw == source and request["source_sha256"] == sha(source), "compiler complete input differs")
    require(request["image_sha256"] == sha(compiler) and request["format"] == image_format, "compiler actual image binding")
    require(request["capacity"] == (1 << 20) and request["workspace_size"] == (1 << 20) and request["workspace_fill"] == 0,
            "compiler borrowed-buffer domain changed")
    require(Path(request["source"]).name == label + ".input.bin" and Path(request["output"]).name == label + ".output.bin", "compiler retained stream association")
    require(record["status"] == "returned" and type(record["abi_status"]) is int and record["abi_status"] == 0,
            "native compiler did not return successfully")
    require(type(record["core_u32"]) is int and record["core_u32"] == len(produced) and 0 < len(produced) <= (1 << 20), "compiled image extent")
    require(record["source_unchanged"] is True and record["forbidden_compiler_modules_loaded"] == [], "compiler source custody or fallback")
    require(record["input_sha256"] == sha(source) and record["input_bytes"] == len(source) and
            record["artifact_sha256"] == sha(compiler) and record["format"] == image_format, "compiler actual invocation source identity")
    require(record["produced_sha256"] == sha(produced) and record["produced_bytes"] == len(produced) and
            output[:len(produced)] == produced and record["output_sha256"] == sha(output) and len(output) == (1 << 20), "compiler complete output custody")
    require(record["result_u64"] == len(produced), "compiler full return value")
    runner = read(capture / "compiler-source/tools/hia_selfhost_child.py")
    require(record["runner_sha256"] == sha(runner), "compiler child source changed")
    actual = json.loads(read(directory / (label + ".stdout.log")))
    require(type(actual) is dict and all(record.get(key) == value for key, value in actual.items()), "compiler actual child stdout differs")
    require(read(directory / (label + ".stderr.log")) == b"", "compiler child emitted an unexpected error")
    return record


def build_evidence(capture, source):
    outer = process(capture, "native-build")
    actual = document(capture / "native-build.json")
    require(actual["pid"] == outer["pid"] and actual["ppid"] == outer["parent_pid"] and actual["pgid"] == outer["pgid"], "native build process attribution")
    require(actual["fresh_bootstrap"] is True and actual["reused_bootstrap"] is False and
            actual["matching_source_cold_qualified"] is False, "bootstrap qualification scope")
    require(actual["source_pins_sha256"] == source["pins_sha256"], "native build source manifest")
    boot = document(capture / "build/bootstrap/bootstrap.json")
    require(boot["schema"] == "hepta.runtime.native-bootstrap.v1" and boot["qualification"] == "development_fixed_point" and
            boot["matching_source_cold_qualified"] is False, "bootstrap receipt domain")
    require(actual["compiler_source_identity"] == boot["dependency"], "bootstrap dependency agreement")
    compiler_sources(capture, boot["dependency"])
    selfhost = read(capture / "compiler-source/examples/hia_bootstrap/selfhost.hepta")
    require(boot["compiler_source_sha256"] == sha(selfhost), "bootstrap compiler source")
    seed = read(capture / "build/bootstrap/B0.so")
    require(seed.startswith(b"\x7fELF"), "seed shared image missing")
    seed_receipt = document(capture / "build/bootstrap/B0.receipt.json")
    require(seed_receipt == boot["seed_receipt"] and seed_receipt["seed_only"] is True and seed_receipt["source_sha256"] == sha(selfhost), "explicit B0 trust boundary")
    for relative, digest in seed_receipt["loaded_seed_modules"].items():
        require(boot["dependency"]["files"].get(relative) == digest, "seed compiler module closure")
    previous = seed
    receipts, generations = [], []
    for label in ("B1", "B2", "B3"):
        row = compile_receipt(capture, "build/bootstrap", label, previous, selfhost,
                              label + ".image.bin", "seed-shared" if label == "B1" else "flat-x86-64")
        receipts.append(row)
        previous = read(capture / "build/bootstrap" / (label + ".image.bin"))
        generations.append(previous)
    require(generations[0] == generations[1] == generations[2] and sha(previous) == boot["generation_sha256"], "actual B1/B2/B3 fixed point")
    require(receipts == boot["generation_receipts"], "bootstrap individual receipt coverage")
    manifest_path = MODULE + "/manifest.json"
    manifest_raw = read(capture / manifest_path)
    manifest = json.loads(manifest_raw)
    require(actual["manifest"] == manifest_path and actual["manifest_sha256"] == sha(manifest_raw), "module manifest custody")
    image = read(capture / MODULE / "module.image.bin")
    owner = read(capture / "source/native/context_protocol_policy.hepta")
    require(read(capture / MODULE / "context-protocol-policy.hepta") == owner, "compiler copied HIA input differs")
    expected_manifest = {"schema": "hepta.runtime.native-module.v1", "name": "context-protocol-policy",
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": COMPILER_COMMIT, "compiler_sha256": sha(previous),
        "source": "context-protocol-policy.hepta", "source_sha256": SOURCE_SHA,
        "image": "module.image.bin", "image_sha256": sha(image),
        "input_capacity": 16 << 20, "output_capacity": 64 << 20, "workspace_capacity": 256 << 20,
        "qualification": "development_fixed_point", "standalone": None, "buffer_profile": "serde-json.v1"}
    require(manifest == expected_manifest, "exact flat serde-json module manifest")
    module_row = compile_receipt(capture, MODULE, "module", previous, owner, "module.image.bin", "flat-x86-64")
    build = document(capture / MODULE / "build.json")
    require(build["compile_receipt"] == module_row and build["compiler_dependency"] == boot["dependency"] and
            build["whole_runtime_replaced"] is False, "module compile receipt/source closure")
    return {"source_sha256": SOURCE_SHA, "image_sha256": sha(image), "image_bytes": len(image),
            "manifest_sha256": sha(manifest_raw), "compiler_sha256": sha(previous), "fresh_bootstrap": True,
            "matching_source_cold_qualified": False}


def native_evidence(capture, source, build):
    outer = process(capture, "native-replay")
    report = document(capture / "native/report.json")
    require(report["schema"] == "hepta.runtime.context-protocol-native.v1" and
            report["pid"] == outer["pid"] and report["ppid"] == outer["parent_pid"] and report["pgid"] == outer["pgid"], "actual native replay custody")
    require(report["source_pins_sha256"] == source["pins_sha256"] and report["manifest_sha256"] == build["manifest_sha256"], "native admitted source/image")
    require(report["complete_buffers"] is True and report["semantic_fallback"] is False and report["automatic_retries"] == 0, "native execution domain")
    sessions, rows = {}, []
    complete_bytes = 0
    semantic = []
    with gzip.open(capture / "native/trace.gz", "rb") as stream:
        for index, call in enumerate(calls()):
            item = read_trace(stream)
            require(item is not None, "omitted native case")
            row, arrays = item
            before_input, after_input, before_output, after_output, before_work, after_work = arrays
            code, payload = expected(call.wire, call.output_capacity)
            local, previous_output, previous_work = sessions.get(call.session, (0,
                initial_output(call.session, call.output_capacity), initial_workspace(call.session, call.workspace_capacity)))
            require(row == (b"HCPTRC01", index, call.semantic, call.session, local, code, len(call.wire),
                            call.output_capacity, call.workspace_capacity, 16, 16, 16, 0), "native row identity or result changed")
            require(before_input == (call.wire or b"\0") + b"\xd3" * 16 and after_input == before_input, "complete input changed")
            require(before_output == previous_output and before_work == previous_work, "dirty session ownership changed")
            require(after_work == before_work, "complete workspace changed")
            require(after_output == (before_output if payload is None else payload + before_output[32:]), "complete output or tail changed")
            sessions[call.session] = local + 1, after_output, after_work
            rows.append({"index": index, "name": call.name, "session": call.session, "local_call": local,
                "semantic": call.semantic, "code": code, "input_bytes": len(call.wire),
                "output_capacity": call.output_capacity, "workspace_capacity": call.workspace_capacity})
            complete_bytes += sum(map(len, arrays))
            if call.semantic != NO_SEMANTIC:
                require(call.semantic == len(semantic), "semantic case order")
                semantic.append(after_output[:32])
        require(read_trace(stream) is None, "unclaimed native record")
    require(report["calls"] == rows and report["native_calls"] == len(rows) == 1941 and
            report["semantic_cases"] == len(semantic) == 1480, "fixed complete native domain changed")
    require(read(capture / "native/semantic-output.bin") == b"".join(packet(raw) for raw in semantic), "native semantic stream differs from actual capture")
    require(read(capture / "processes/native-replay.stdout") == f"CONTEXT_PROTOCOL_NATIVE_PASS {len(rows)}\n".encode() and
            read(capture / "processes/native-replay.stderr") == b"", "native process complete logs")
    return {"semantic_cases": len(semantic), "native_calls": len(rows), "complete_before_after_buffer_bytes": complete_bytes,
            "native_seconds": outer["elapsed_ns"] / 1e9}, semantic


def registry_evidence(capture):
    registry = document(capture / "registry.json")
    require(registry["schema"] == "hepta.runtime.context-protocol-registry.v1", "registry schema")
    metadata = json.loads(read(capture / "processes/cargo-metadata.stdout"))
    locked = {(p["name"], p["version"]): p for p in tomllib.loads(read(capture / "source" / BASE / "oracle/Cargo.lock").decode())["package"] if "source" in p}
    actual_packages = {p["name"] + "-" + p["version"]: p for p in metadata["packages"] if p["source"] is not None}
    require(set(actual_packages) == set(registry["packages"]), "actual registry package inventory changed")
    files, byte_count = set(), 0
    for name, row in registry["packages"].items():
        key = row["name"], row["version"]
        require(name == "-".join(key) and key in locked and row["source"] == locked[key]["source"] and
                row["checksum"] == locked[key]["checksum"], "registry lock identity")
        require(row["metadata_id"] == actual_packages[name]["id"] and row["source"] == actual_packages[name]["source"], "actual metadata registry association")
        archive = read(capture / "registry" / (name + ".crate"))
        require(len(archive) == row["archive_bytes"] and sha(archive) == row["checksum"], "complete original registry archive changed")
        proof_raw = read(capture / "registry" / (name + ".source-proof.json"))
        proof = json.loads(proof_raw)
        require(sha(proof_raw) == row["source_proof_sha256"] and
                proof["schema"] == "hepta.runtime.context-protocol-registry-source.v1" and
                proof["package_sha256"] == row["checksum"], "actual registry source custody")
        originals = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if member.isdir():
                    continue
                require(member.isfile() and member.name.startswith(name + "/"), "registry retained member kind")
                relative = safe_relative(member.name[len(name) + 1:])
                require(relative not in originals, "duplicate registry file")
                raw = tar.extractfile(member).read()
                originals[relative] = sha(raw)
                byte_count += len(raw)
                if name == "rmcp-3.9.0" and relative == "src/model.rs":
                    require(raw == read(capture / "source" / BASE / "reference/sdk-model.rs") and sha(raw) == SDK_MODEL_SHA, "current SDK owner differs from the retained source")
        require(originals == row["actual_source_files"] == proof["actual_source_files"], "actual complete original registry source differs")
        metadata_hex = proof["cache_metadata_hex"]
        require(set(metadata_hex) <= {".cargo-ok", ".cargo-checksum.json"} and
                proof["actual_file_set"] == sorted(set(originals) | set(metadata_hex)), "actual registry file-set coverage")
        require(all(type(value) is str and bytes.fromhex(value).hex() == value for value in metadata_hex.values()), "complete registry bookkeeping bytes")
        if ".cargo-checksum.json" in metadata_hex:
            checksums = json.loads(bytes.fromhex(metadata_hex[".cargo-checksum.json"]))
            require(checksums["package"] == row["checksum"] and checksums["files"] in ({}, originals), "retained Cargo checksum metadata differs")
        require(proof["actual_manifest_sha256"] == originals["Cargo.toml"], "actual registry manifest identity")
        files.update((name + ".crate", name + ".source-proof.json"))
    require(set(tree_files(capture / "registry")) == files, "unclaimed registry source archive")
    require("rmcp-3.9.0" in registry["packages"] and "tokio-1.53.3" in registry["packages"], "current registry missing")
    return {"packages": len(registry["packages"]), "complete_source_bytes": byte_count}


def original_evidence(capture, semantic):
    records = {name: process(capture, name) for name in ("rustc-version", "cargo-version", "cargo-build", "cargo-metadata", "original-replay")}
    rustc = read(capture / "processes/rustc-version.stdout").decode()
    require(rustc.startswith("rustc 1.95.0 ") and "\nrelease: 1.95.0\n" in rustc and "\nhost: x86_64-unknown-linux-gnu\n" in rustc, "actual Rust version differs")
    require(read(capture / "processes/cargo-version.stdout").startswith(b"cargo 1.95.0 "), "actual Cargo version differs")
    for name, record in records.items():
        require(record["environment"]["RUSTUP_TOOLCHAIN"] == "1.95.0" and record["environment"]["CARGO_ENCODED_RUSTFLAGS"] == "", "controlled original compilation environment")
    build = document(capture / "original-build.json")
    binary = read(capture / "original/oracle.bin")
    require(binary.startswith(b"\x7fELF") and build["binary_sha256"] == sha(binary) and build["binary_bytes"] == len(binary), "actual original executable custody")
    require(build["binary_after_replay_sha256"] == sha(binary) and build["fresh_build"] is True and build["locked"] is True, "original binary/source lifetime")
    for name in ("Cargo.toml", "Cargo.lock", "main.rs", "original_policy.rs"):
        raw = read(capture / "original/workspace" / name)
        require(raw == read(capture / "source" / BASE / "oracle" / name), "actual original build source changed")
        require(build["workspace_sources"][name] == {"bytes": len(raw), "sha256": sha(raw)}, "original workspace source identity")
    registry = registry_evidence(capture)
    sentinel = object()
    with (capture / "processes/original-replay.stderr").open("rb") as actual_context:
        count = 0
        for index, (pair, actual_input, native, original) in enumerate(itertools.zip_longest(
                versions(), packets(capture / "semantic-input.bin"), semantic,
                packets(capture / "processes/original-replay.stdout"), fillvalue=sentinel)):
            require(all(item is not sentinel for item in (pair, actual_input, native, original)), "omitted original or semantic case")
            name, version = pair
            wanted_input = frame(version)
            require(actual_input == wanted_input, "complete original semantic input changed: " + name)
            require(original == native and len(original) == 32, "unchanged target function result differs: " + name)
            actual_header = read_exact(actual_context, 32)
            magic, number, present, size = struct.unpack("<8s3Q", actual_header)
            value = b"" if version is None else version.encode()
            require((magic, number, present, size) == (b"HCPCTX01", index, int(version is not None), len(value)), "actual resolved context descriptor differs")
            require(read_exact(actual_context, size) == value, "actual RequestContext protocol differs from the resolved input")
            count += 1
        footer = read_exact(actual_context, 32)
        require(struct.unpack("<8s3Q", footer) == (b"HCPCEND1", count, records["original-replay"]["pid"], 1), "actual original process completion/context assertion")
        require(actual_context.read(1) == b"", "unexpected original stderr suffix")
    require(count == 1480, "complete original resolved-version domain")
    return {"cases": count, "registry": registry, "rustc_version": rustc, "binary_sha256": sha(binary),
            "original_seconds": records["original-replay"]["elapsed_ns"] / 1e9}


def read_capture(capture, source_root, pins_sha):
    capture, source_root = Path(capture).absolute(), Path(source_root).absolute()
    source = source_evidence(source_root, pins_sha)
    retained = source_evidence(capture / "source", pins_sha)
    require(retained == source, "capture source closure differs from the admitted reader")
    expected_source_files = set(source["files"]) | {BASE + "/source-pins.json"}
    require(set(tree_files(capture / "source")) == expected_source_files, "retained source set changed")
    seal = document(capture / "CAPTURE.json")
    require(seal["schema"] == "hepta.runtime.context-protocol-capture.v1" and seal["source_pins_sha256"] == pins_sha, "capture schema/source")
    actual = tree_files(capture)
    del actual["CAPTURE.json"]
    require(actual == seal["files"], "complete capture file custody changed")
    require(set(path.name for path in (capture / "processes").iterdir()) ==
            {label + suffix for label in LIMITS for suffix in (".json", ".stdout", ".stderr")}, "process record coverage")
    build = build_evidence(capture, source)
    native, results = native_evidence(capture, source, build)
    original = original_evidence(capture, results)
    return {"schema": "hepta.runtime.context-protocol-qualified.v1", "status": "PASS",
        "source_pins_sha256": pins_sha, "capture_sha256": sha(read(capture / "CAPTURE.json")),
        "target_commit": TARGET_COMMIT, "build": build, "native": native, "original": original,
        "scope": "resolved Option<ProtocolVersion> feature predicates only",
        "metadata_peer_selection_qualified": False, "authentication_qualified": False,
        "public_handler_qualified": False, "whole_runtime_replaced": False,
        "production_activated": False, "old_stack_removal_qualified": False}
