# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit complete actual native and original SDK connection evidence.

Admission only reads retained files. It does not invoke a native module, infer
success from a source hash, or execute Rust. The explicit build entry is the
only process-launching function in this module.
"""
from pathlib import Path
import gzip
import hashlib
import json
import math
import os
import signal
import struct
import subprocess
import sys
import time

from connection_registry import (ADAPTER_SHA, CALL_HOLES, COMPILER, COMPILER_IMAGE,
    ELF_BYTES, ELF_SHA, FOLDERS, MODULES, PREFIX_BYTES, PREFIX_SHA, TESTS, source_pins)

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
REPLAYS = (
    ("direct-core", "message-core", "direct.stdout", "hia-message-decode-reference", 1321),
    ("direct-boundaries", "message-boundaries", "direct.stdout", "hia-message-decode-reference", 3461),
    ("transport-core", "transport-core", "transport.stdout", "hia-transport-decode-reference", 1343),
    ("transport-boundaries", "message-boundaries", "transport.stdout", "hia-transport-decode-reference", 3461),
    ("lifecycle-core", "lifecycle-core", "lifecycle.stdout", "hia-connection-context-reference", 1621),
    ("lifecycle-matrix", "lifecycle-matrix", "lifecycle.stdout", "hia-connection-context-reference", 582),
)
REMOVED_ENVIRONMENT = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "not a regular retained file: " + str(path))
    return path.read_bytes()


def object_at(path):
    result = json.loads(read(path))
    require(type(result) is dict, "expected an object: " + str(path))
    return result


def confined(root, value):
    root = Path(root).resolve(strict=True)
    path = Path(value)
    path = path if path.is_absolute() else root / path
    require(not path.is_symlink(), "retained symlink refused")
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(root), "retained artifact escaped workspace")
    return resolved


def artifact(output, values, path):
    path = confined(output, path)
    raw = read(path)
    values[path.relative_to(output).as_posix()] = sha(raw)
    return raw


def elapsed(value, maximum):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value < maximum,
            "invalid completed process duration")


def process_receipt(folder, name, record, command, cwd, limit, *, aggregate=False):
    out, err = read(folder / (name + ".stdout")), read(folder / (name + ".stderr"))
    # The shared qualifier fixes cwd to its source root but does not duplicate it
    # in each record. Our retained child records do include and bind the field.
    require(record.get("command") == list(map(str, command))
            and (record.get("cwd", str(cwd)) if aggregate else record.get("cwd")) == str(cwd)
            and type(record.get("exit_code")) is int and record["exit_code"] == 0
            and record.get("timed_out") is False and not record.get("start_error")
            and record.get("timeout_seconds") == limit, "completed command differs: " + name)
    elapsed(record.get("elapsed_seconds"), limit)
    require(record.get("stdout_sha256") == sha(out) and record.get("stderr_sha256") == sha(err),
            "completed streams differ: " + name)
    for key, size in (("stdout_bytes", len(out)), ("stderr_bytes", len(err))):
        if key in record:
            require(type(record[key]) is int and record[key] == size, "stream length differs")
    return out, err


def build_connection(hepta, build_root, source_root):
    """Run one actual 180-second build with the existing three-second cleanup."""
    root = Path(source_root).resolve(strict=True)
    build = Path(build_root).resolve()
    build.mkdir(parents=True, exist_ok=True)
    pins = source_pins(root)
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_native_connection.py"),
               "--hepta", str(Path(hepta).resolve(strict=True)), "--build-root", str(build)]
    env = {key: value for key, value in os.environ.items() if not key.startswith("HIA_")}
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    timed = False
    try:
        out, err = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed = True
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate(timeout=3)
    record = {"command": command, "cwd": str(root), "exit_code": process.returncode,
              "timed_out": timed, "timeout_seconds": 180, "cleanup_seconds": 3,
              "elapsed_seconds": time.monotonic() - started,
              "stdout_bytes": len(out), "stderr_bytes": len(err),
              "stdout_sha256": sha(out), "stderr_sha256": sha(err),
              "sources_before": pins, "sources_after": source_pins(root)}
    for suffix, raw in (("stdout", out), ("stderr", err), ("receipt.json", encoded(record))):
        (build / ("connection-build." + suffix)).write_bytes(raw)
    require(not timed and process.returncode == 0 and not err, "connection build failed")
    require(record["sources_after"] == pins, "connection source changed during build")
    path = build / "connection-build.json"
    require(json.loads(out) == {"manifest": str(path), "modules": 4, "actual_static_elfs": 1},
            "actual build summary differs")
    return path


def _module(root, output, key, reference, artifacts):
    path = confined(output, reference["path"])
    raw = artifact(output, artifacts, path)
    require(sha(raw) == reference["sha256"], "native manifest changed")
    meta = json.loads(raw)
    name, profile, source_hash, image_hash = MODULES[key]
    require(meta.get("schema") == "hepta.runtime.native-module.v1"
            and meta.get("compiler_commit") == COMPILER and meta.get("compiler_sha256") == COMPILER_IMAGE
            and meta.get("buffer_profile", "standard") == profile and meta.get("standalone") is None
            and meta.get("source_sha256") == source_hash and meta.get("image_sha256") == image_hash,
            "native module identity or profile differs")
    source = artifact(output, artifacts, path.parent / meta["source"])
    image = artifact(output, artifacts, path.parent / meta["image"])
    require(sha(source) == source_hash and source == read(root / "native" / (name + ".hepta"))
            and sha(image) == image_hash, "actual source or executable image differs")
    receipt = json.loads(artifact(output, artifacts, path.parent / "module.receipt.json"))
    compiled = json.loads(artifact(output, artifacts, path.parent / "build.json"))
    request = json.loads(artifact(output, artifacts, path.parent / "module.request.json"))
    native_out = artifact(output, artifacts, path.parent / "module.output.bin")
    native_in = artifact(output, artifacts, path.parent / "module.input.bin")
    stdout = artifact(output, artifacts, path.parent / "module.stdout.log")
    stderr = artifact(output, artifacts, path.parent / "module.stderr.log")
    observer = json.loads(stdout)
    require(set(observer) >= {"status", "abi_status", "core_u32", "result_u64", "source_unchanged",
            "source_sha256", "output_sha256", "image_sha256", "forbidden_compiler_modules_loaded"},
            "native compiler stdout incomplete")
    require(not stderr and all(receipt.get(k) == v for k, v in observer.items())
            and compiled.get("compile_receipt") == receipt
            and compiled.get("compiler_dependency", {}).get("commit") == COMPILER,
            "actual compiler result differs")
    require(receipt.get("status") == "returned" and receipt.get("abi_status") == 0
            and receipt.get("source_unchanged") is True and receipt.get("forbidden_compiler_modules_loaded") == []
            and receipt.get("source_sha256") == receipt.get("input_sha256") == source_hash
            and receipt.get("produced_sha256") == image_hash and receipt.get("produced_bytes") == len(image)
            and receipt.get("core_u32") == receipt.get("result_u64") == len(image)
            and receipt.get("image_sha256") == COMPILER_IMAGE, "actual compiler invocation failed")
    require(native_in == source and native_out[:len(image)] == image and sha(native_out) == receipt["output_sha256"]
            and len(native_out) == request.get("capacity") == 1048576
            and request.get("image_sha256") == COMPILER_IMAGE and request.get("source_sha256") == source_hash,
            "complete compiler byte buffers changed")
    return meta, image


def build_evidence(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    owner = report["modules"]["sdk_connection"]
    require(owner.get("builder") == "sdk_connection", "registry builder changed")
    path = confined(output, owner["manifest"])
    require(path == output / "build/connection-build.json" and sha(read(path)) == owner["sha256"],
            "registered build bundle differs")
    require(report.get("compiler_commit") == COMPILER and report.get("compiler_image_sha256") == COMPILER_IMAGE,
            "aggregate compiler changed")
    artifacts = {}
    bundle = json.loads(artifact(output, artifacts, path))
    pins = source_pins(root)
    require(bundle.get("schema") == "hepta.sdk-connection.build.v1" and bundle.get("sources") == pins
            and bundle.get("compiler_commit") == COMPILER and bundle.get("compiler_sha256") == COMPILER_IMAGE
            and set(bundle["modules"]) == set(MODULES), "build inventory or source custody differs")
    require(bundle.get("production_tool_dispatch_closed") is False
            and bundle.get("fixture_handler_is_test_only") is True
            and bundle.get("client_result_typed_normalization_closed") is False
            and bundle.get("fresh_cold_qualified") is False, "bounded scope was broadened")
    receipt = object_at(path.parent / "connection-build.receipt.json")
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_native_connection.py"),
               "--hepta", str(Path(report["compiler_checkout"]).resolve(strict=True)), "--build-root", str(path.parent)]
    out, err = process_receipt(path.parent, "connection-build", receipt, command, root, 180)
    require(not err and receipt.get("cleanup_seconds") == 3 and receipt.get("sources_before") == pins
            and receipt.get("sources_after") == pins
            and json.loads(out) == {"manifest": str(path), "modules": 4, "actual_static_elfs": 1},
            "build process evidence differs")
    for name in ["connection-build.receipt.json", "connection-build.stdout", "connection-build.stderr"]:
        artifact(output, artifacts, path.parent / name)
    members = {key: _module(root, output, key, reference, artifacts)
               for key, reference in bundle["modules"].items()}
    fixture_path = confined(output, bundle["fixture"]["path"])
    fixture_raw = artifact(output, artifacts, fixture_path)
    require(sha(fixture_raw) == bundle["fixture"]["sha256"], "fixture manifest changed")
    fixture = json.loads(fixture_raw)
    binary = artifact(output, artifacts, fixture_path.parent / fixture["executable"])
    require((len(binary), sha(binary)) == (ELF_BYTES, ELF_SHA)
            and (fixture.get("elf_bytes"), fixture.get("elf_sha256")) == (ELF_BYTES, ELF_SHA)
            and fixture.get("schema") == "hepta.sdk-connection.native-fixture.v1"
            and fixture.get("test_fixture_only") is True and fixture.get("production_runtime_handlers") is False
            and fixture.get("raw_frame_limit") == 8388608
            and fixture.get("prefix_bytes") == PREFIX_BYTES and fixture.get("prefix_sha256") == PREFIX_SHA,
            "actual fixture or scope differs")
    require(fixture.get("adapter_source_sha256") == ADAPTER_SHA == sha(read(root / "scripts/sdk_connection_adapter.S"))
            and fixture.get("builder_source_sha256") == pins["scripts/build_connection_fixture.py"]
            and fixture.get("generic_build_sha256") == pins["scripts/hia_native_build.py"]
            and fixture.get("generic_loader_sha256") == pins["scripts/hia_native_loader.py"]
            and fixture.get("compiler_commit") == COMPILER and fixture.get("compiler_sha256") == COMPILER_IMAGE,
            "fixed boundary provenance differs")
    prefix = bytearray(binary[:PREFIX_BYTES])
    struct.pack_into("<QQ", prefix, 96, 0, 0)
    at, images = PREFIX_BYTES, []
    require(fixture.get("call_order") == ["message", "connection", "fixture"] and len(fixture["members"]) == 3,
            "fixed image table changed")
    for index, (key, row, hole) in enumerate(zip(fixture["call_order"], fixture["members"], CALL_HOLES, strict=True)):
        meta, image = members[key]
        ref = bundle["modules"][key]
        require(row.get("id") == index and row.get("name") == key and row.get("manifest") == ref["path"]
                and row.get("manifest_sha256") == ref["sha256"] and row.get("offset") == at
                and row.get("call_displacement_offset") == hole and binary[hole - 1] == 0xe8
                and hole + 4 + struct.unpack_from("<i", binary, hole)[0] == at
                and binary[at:at + len(image)] == image and row.get("image_bytes") == len(image),
                "actual embedded image or call target differs")
        for field in ("source_sha256", "image_sha256", "buffer_profile", "input_capacity", "output_capacity", "workspace_capacity"):
            require(row.get(field) == meta.get(field, "standard" if field == "buffer_profile" else None),
                    "embedded member profile differs")
        struct.pack_into("<I", prefix, hole, 0)
        at += len(image)
        images.append(image)
    require(at == len(binary) and sha(prefix) == PREFIX_SHA, "complete fixed prefix differs")
    frame = artifact(output, artifacts, fixture_path.parent / "pack.input.bin")
    expected_frame = b"HRCNPK01" + b"".join(struct.pack("<Q", len(i)) for i in images) + b"".join(images)
    require(frame == expected_frame and fixture["pack_input_sha256"] == sha(frame), "packer input differs")
    pack = json.loads(artifact(output, artifacts, fixture_path.parent / "pack.result.json"))
    expected = {"schema": "hepta.sdk-connection.actual-packer-call.v1", "status": "returned", "result_u32": len(binary),
                "input_bytes": len(frame), "input_sha256": sha(frame), "output_bytes": len(binary), "output_sha256": sha(binary),
                "packer_manifest_sha256": bundle["modules"]["packer"]["sha256"], "source_and_canary_guards_checked": True}
    require(pack == expected and fixture.get("packer_manifest") == bundle["modules"]["packer"]["path"]
            and fixture.get("packer_manifest_sha256") == expected["packer_manifest_sha256"], "actual packer result differs")
    for child in fixture_path.parent.iterdir():
        if child.is_file():
            artifact(output, artifacts, child)
    require(read(fixture_path.parent / "adapter.S") == read(root / "scripts/sdk_connection_adapter.S")
            and prefix[176:] == read(fixture_path.parent / "adapter.bin"), "assembled boundary bytes differ")
    processes = json.loads(read(fixture_path.parent / "processes.json"))
    require([r.get("name") for r in processes] == ["assemble", "relocations", "objcopy", "symbols"], "adapter process domain differs")
    directory = fixture_path.parent
    commands = [["as", "--64", str(directory / "adapter.S"), "-o", str(directory / "adapter.o")],
                ["readelf", "-r", str(directory / "adapter.o")],
                ["objcopy", "-O", "binary", "--only-section=.text", str(directory / "adapter.o"), str(directory / "adapter.bin")],
                ["nm", "-n", str(directory / "adapter.o")]]
    for record, command in zip(processes, commands, strict=True):
        _, err = process_receipt(directory, record["name"], record, command, root, 30)
        require(not err, "adapter tool emitted unexpected stderr")
    fixture_process = object_at(path.parent / "connection-fixture-process.json")
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_connection_fixture.py"),
               "--hepta", str(Path(report["compiler_checkout"]).resolve(strict=True)), "--runtime", str(root),
               "--build-root", str(path.parent), "--name", "sdk-connection"]
    for key in ("message", "connection", "fixture"):
        command += ["--" + key + "-manifest", bundle["modules"][key]["path"]]
    observed, err = process_receipt(path.parent, "connection-fixture", fixture_process, command, root, 120)
    require(not err and json.loads(observed) == {"manifest": str(fixture_path), "elf_sha256": ELF_SHA, "elf_bytes": ELF_BYTES},
            "actual fixture build summary differs")
    for name in ["connection-fixture-process.json", "connection-fixture.stdout", "connection-fixture.stderr"]:
        artifact(output, artifacts, path.parent / name)
    index = object_at(root / "tests/hia_native/connection_reference_cases.json")
    require(bundle.get("reference_index_sha256") == sha(read(root / "tests/hia_native/connection_reference_cases.json"))
            and bundle.get("reference_files") == index["files"], "retained case inventory differs")
    data = confined(output, bundle["reference_data"])
    for name, want in index["files"].items():
        body = artifact(output, artifacts, data / name)
        require((len(body), sha(body), body.count(b"\n")) == (want["bytes"], want["sha256"], want["lines"]),
                "complete reference bytes differ")
    return {"schema": "hepta.sdk-connection.build-evidence.v1", "sources": pins,
            "bundle_sha256": sha(read(path)), "elf_sha256": ELF_SHA, "artifact_sha256": artifacts}


def test_commands(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    bundle = object_at(confined(output, report["modules"]["sdk_connection"]["manifest"]))
    commands = {name: [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name)] for name in TESTS}
    commands[TESTS[-1]] += ["--manifest", bundle["fixture"]["path"], "--output", str(output / "connection-native/controls")]
    return commands


def test_environment(output):
    output = Path(output).resolve()
    return {"HIA_CONNECTION_BUILD": str(output / "build/connection-build.json"),
            "HIA_CONNECTION_OUTPUT_DIR": str(output / "connection-native")}


def _completed(root, output, report, completed, name, command):
    record, summary = completed(output, report, name)
    out, err = process_receipt(output, name, record, command, root, 180, aggregate=True)
    require(not err and json.loads(out) == summary and summary.get("status") == "PASS", "complete actual test stdout differs")
    return record, summary


def _rows(output, artifacts, folder, descriptor):
    path = folder / descriptor["file"]
    compressed = artifact(output, artifacts, path)
    raw = gzip.decompress(compressed)
    require((len(raw), sha(raw), raw.count(b"\n")) == (descriptor["raw_bytes"], descriptor["raw_sha256"], descriptor["rows"]),
            "complete compressed native rows differ")
    return list(map(json.loads, raw.splitlines()))


def native_evidence(root, output, report, completed_test_summary, create=False):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    built = build_evidence(root, output, report)
    bundle = object_at(output / "build/connection-build.json")
    artifacts = dict(built["artifact_sha256"])
    corpus, summaries, records = {}, {}, []
    commands = test_commands(root, output, report)
    for name, folder in zip(TESTS, FOLDERS, strict=True):
        check, summary = _completed(root, output, report, completed_test_summary, name, commands[name])
        path = output / "connection-native" / folder
        require(object_at(path / "result.json") == summary and summary.get("sources") == built["sources"]
                and summary.get("build_sha256") == built["bundle_sha256"], "actual native result custody differs")
        for p in [path / "result.json", output / (name + ".stdout"), output / (name + ".stderr")]:
            artifact(output, artifacts, p)
        records.append({"name": name, **{k: check[k] for k in ("command", "exit_code", "timed_out", "timeout_seconds", "stdout_sha256", "stderr_sha256")}})
        summaries[folder] = summary
        if folder == "controls":
            require(summary.get("controls") == 16 and summary.get("state_calls") == 45
                    and summary.get("message_calls") == 5 and summary.get("actual_elf_processes") == 12
                    and summary.get("elf_sha256") == ELF_SHA, "native control domain changed")
            raw = artifact(output, artifacts, path / "controls.json")
            require(sha(raw) == summary.get("controls_sha256"), "controls receipt changed")
            rows = json.loads(raw)
            labels = ["initialize-and-reinitialize-capacity-atomicity", "malformed-private-frames-atomic", "corrupt-state-refusal", "exact-response-capacity",
                      "ordinary", "final-frame-no-newline", "empty", "blank-lines", "BOM-CRLF", "invalid-syntax-between-frames",
                      "one-byte-fragments", "usage", "exact-8MiB-line-CRLF", "exact-8MiB-final-frame", "over-limit-no-partial-output", "large-escaped-id"]
            require([row.get("control") for row in rows] == labels, "native control inventory incomplete")
            require(rows[1].get("cases") == 19 and rows[2].get("cases") == 8 and rows[3].get("bytes") == 896
                    and all(row.get("status") == "PASS" for row in rows[:4]), "state/capacity control counts differ")
            for row in rows[4:]:
                out, err = bytes.fromhex(row["stdout_hex"]), bytes.fromhex(row["stderr_hex"])
                require(not err and row["stdout_bytes"] == len(out) and sha(out) == row["stdout_sha256"]
                        and sha(err) == row["stderr_sha256"] and row["command"][0] == bundle["fixture"]["path"].replace("manifest.json", "sdk-connection-fixture.elf")
                        and row["exit_code"] == ({"usage": 64, "over-limit-no-partial-output": 3}.get(row["control"], 0)),
                        "actual transport control completion differs")
            continue
        require(summary.get("production_tool_dispatch_closed") is False
                and summary.get("client_result_typed_normalization_closed") is False, "native scope broadened")
        for file, expected in summary["artifacts"].items():
            raw = artifact(output, artifacts, path / file)
            require((len(raw), sha(raw)) == (expected["bytes"], expected["sha256"]), "test artifact changed")
        expected_domains = {"message": {"message-core": 1321, "message-boundaries": 3461},
                            "transport": {"transport-core": 1343, "message-boundaries": 3461},
                            "connection": {"lifecycle-core": 1621, "lifecycle-matrix": 582},
                            "elf": {"lifecycle-core": 1621, "lifecycle-matrix": 582}}[folder]
        require(set(summary["exports"]) == set(expected_domains), "native exported domains differ")
        counts = {"processes": 0, "responses": 0, "events": 0}
        for domain, descriptor in summary["exports"].items():
            rows = _rows(output, artifacts, path, descriptor)
            cases = list(map(json.loads, read(Path(bundle["reference_data"]) / domain / "requests.jsonl").splitlines()))
            require(len(rows) == len(cases) == expected_domains[domain]
                    and [r["label"] for r in rows] == [r["label"] for r in cases], "native rows omitted or reordered")
            corpus[(path / descriptor["file"]).relative_to(output).as_posix()] = artifacts[(path / descriptor["file"]).relative_to(output).as_posix()]
            if folder in ("connection", "elf"):
                originals = list(map(json.loads, read(Path(bundle["reference_data"]) / domain / "lifecycle.stdout").splitlines()))
                for case, row, original in zip(cases, rows, originals, strict=True):
                    expected = b"".join(e["response_raw"].encode() for e in original["events"] if "response_raw" in e)
                    if folder == "elf":
                        request = b"\n".join(bytes.fromhex(e["wire_hex"]) if "wire_hex" in e else e["wire"].encode() for e in case["events"]) + b"\n"
                        actual = bytes.fromhex(row["stdout_hex"])
                        require(row.get("exit_code") == 0 and row.get("timed_out") is False and row.get("timeout_seconds") == 10
                                and row.get("stderr_hex") == "" and row.get("command") == [str(Path(bundle["fixture"]["path"]).parent / "sdk-connection-fixture.elf")]
                                and row.get("input_sha256") == sha(request) and row.get("input_bytes") == len(request)
                                and row.get("stdout_sha256") == sha(actual) and row.get("stderr_sha256") == sha(b""),
                                "actual ELF invocation differs")
                        elapsed(row.get("elapsed_seconds"), 10)
                    else:
                        actual = b"".join(bytes.fromhex(value) for value in row["response_hex"])
                        require(bytes.fromhex(row["eof_hex"])[:16] == b"HRCNS001\x06\0\0\0\0\0\0\0", "EOF admission missing")
                    require(actual == expected, "complete native response bytes differ")
                    counts["processes"] += 1
                    counts["responses"] += actual.count(b"\n")
                    counts["events"] += len(case["events"])
        if folder == "message":
            require(summary["counts"] == {"native_message_calls": 4782, "domains": 2}, "direct message domain incomplete")
        elif folder == "transport":
            require(summary["counts"] == {"cases": 4804, "native_message_calls": 4813,
                    "parsed_messages": 2610, "transport_error_responses": 1355}, "raw transport domain incomplete")
        else:
            require(counts == {"processes": 2203, "responses": 6126, "events": 6414}, "complete session domain differs")
            if folder == "elf":
                require(summary["counts"] == {"actual_processes": 2203, "empty_path_launches": 2203, "input_events": 6414, "response_lines": 6126}
                        and summary.get("elf_sha256") == ELF_SHA and summary.get("runtime_python_or_rust") is False
                        and summary.get("fixture_handler_is_test_only") is True, "actual ELF scope differs")
            else:
                require(summary["counts"] == {"sessions": 2203, "message_calls": 6374, "connection_calls": 8577,
                        "fixture_calls": 3020, "context_joins": 2791, "response_lines": 6126, "eof_calls": 2203},
                        "persistent session domain incomplete")
    compatibility = {"schema": "hepta.sdk-connection.native-result.v1", "status": "PASS", "sources": built["sources"],
                     "build": str(output / "build/connection-build.json"), "build_sha256": built["bundle_sha256"],
                     "records": records, "summaries": summaries, "artifact_sha256": artifacts, "corpus_sha256": corpus,
                     "original_replay_cases": sum(r[4] for r in REPLAYS), "actual_native_elf_processes": 2215,
                     "production_tool_dispatch_closed": False, "client_result_typed_normalization_closed": False}
    path = output / "connection-native/result.json"
    raw = encoded(compatibility)
    if create:
        require(not path.exists(), "compatibility result is create-only")
        path.write_bytes(raw)
    else:
        require(read(path) == raw, "compatibility result is not derived from actual completed tests")
    artifact(output, artifacts, path)
    return {"schema": "hepta.sdk-connection.native-evidence.v1", "sources": built["sources"],
            "artifact_sha256": artifacts, "corpus_sha256": corpus, "compatibility_result_sha256": sha(raw),
            "actual_native_elf_processes": 2215, "native_calls_added_by_evidence_admission": 0,
            "production_tool_dispatch_closed": False, "client_result_typed_normalization_closed": False}


def checked_native_result(root, result_path):
    """Read-only reference-side custody of a previously collected native result."""
    root, result_path = Path(root).resolve(strict=True), Path(result_path).resolve(strict=True)
    output = result_path.parents[1]
    result = object_at(result_path)
    require(result.get("schema") == "hepta.sdk-connection.native-result.v1" and result.get("status") == "PASS"
            and result.get("sources") == source_pins(root) and result.get("original_replay_cases") == 11789
            and result.get("actual_native_elf_processes") == 2215 and result.get("production_tool_dispatch_closed") is False
            and result.get("client_result_typed_normalization_closed") is False, "native input scope or custody differs")
    for name, digest in result["artifact_sha256"].items():
        require(sha(read(confined(output, name))) == digest, "native artifact changed before reference: " + name)
    require(len(result.get("records", [])) == 5 and [r.get("name") for r in result["records"]] == list(TESTS)
            and set(result["summaries"]) == set(FOLDERS), "native actual process inventory incomplete")
    for row in result["records"]:
        require(row.get("exit_code") == 0 and row.get("timed_out") is False and row.get("timeout_seconds") == 180
                and sha(read(output / (row["name"] + ".stdout"))) == row["stdout_sha256"]
                and sha(read(output / (row["name"] + ".stderr"))) == row["stderr_sha256"], "native process receipt changed")
    bundle = confined(output, result["build"])
    require(sha(read(bundle)) == result["build_sha256"], "native bundle changed before reference")
    return result


def compare_replay_to_native(root, native_result, replay, actual_stdout):
    """Join complete freshly observed originals to previously executed HIA rows."""
    result = checked_native_result(root, native_result)
    output = Path(native_result).resolve(strict=True).parents[1]
    bundle = object_at(result["build"])
    label, domain, original_name, binary, count = replay
    actual = list(map(json.loads, actual_stdout.splitlines()))
    cases = list(map(json.loads, read(Path(bundle["reference_data"]) / domain / "requests.jsonl").splitlines()))
    require(len(actual) == len(cases) == count, "full reference replay count differs")
    require([r["label"] for r in actual] == [r["label"] for r in cases], "reference rows reordered")
    def exported(suite):
        descriptor = result["summaries"][suite]["exports"][domain]
        folder = output / "connection-native" / suite
        return _rows(output, {}, folder, descriptor)
    if label.startswith("direct-"):
        sys.path.insert(0, str(Path(root) / "tests/hia_native"))
        from connection_test_context import compare_projection
        transports = {r["label"]: r for r in map(json.loads, read(Path(bundle["reference_data"]) / domain / "transport.stdout").splitlines())}
        native = exported("message")
        for case, observed, row in zip(cases, actual, native, strict=True):
            require(row["label"] == case["label"], "direct native row reordered")
            compare_projection(bytes.fromhex(case["hex"]), bytes.fromhex(row["projection_hex"]), observed, transports[case["label"]])
    elif label.startswith("transport-"):
        native = exported("transport")
        for observed, row in zip(actual, native, strict=True):
            require(row["label"] == observed["label"] and row["response_raw"] == observed["response_raw"], "actual transport response differs")
            messages = [bytes.fromhex(value) for value in row["projections_hex"]]
            kinds = {1: "request", 2: "notification", 3: "response", 4: "error"}
            parsed = [kinds[struct.unpack_from("<Q", value, 8)[0]] for value in messages if struct.unpack_from("<Q", value, 8)[0] in kinds]
            require(parsed == [r["kind"] for r in observed["messages"]], "actual transport typed sequence differs")
    else:
        native, processes = exported("connection"), exported("elf")
        for observed, state, process in zip(actual, native, processes, strict=True):
            expected = b"".join(e["response_raw"].encode() for e in observed["events"] if "response_raw" in e)
            require(state["label"] == process["label"] == observed["label"]
                    and bytes.fromhex(process["stdout_hex"]) == expected
                    and b"".join(bytes.fromhex(raw) for raw in state["response_hex"]) == expected,
                    "actual original and HIA complete wire bytes differ")
    return {"name": label, "cases": count, "complete_original_bytes": len(actual_stdout),
            "original_stdout_sha256": sha(actual_stdout), "native_rows_joined": count,
            "actual_native_calls_added_by_comparison": 0}


def original_evidence(root, output, report, completed_test_summary):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    native = native_evidence(root, output, report, completed_test_summary)
    folder = output / "connection-original"
    original = object_at(folder / "result.json")
    require(original.get("schema") == "hepta.sdk-connection.original-result.v1" and original.get("status") == "PASS"
            and original.get("sources") == source_pins(root) and original.get("cases") == 11789
            and original.get("actual_original_processes") == 6 and original.get("fresh_actual_cargo_build") is True
            and original.get("native_calls_added") == 0 and original.get("production_tool_dispatch_closed") is False,
            "original reference scope differs")
    check, summary = completed_test_summary(output, report, "connection-rust-compare")
    command = [sys.executable, "-I", "-B", str(root / "tests/hia_native/compare_sdk_connection_original.py"),
               "--repo", str(root), "--native-results", str(output / "connection-native/result.json"),
               "--output", str(folder), "--cargo", original["cargo"], "--rustc", original["rustc"]]
    out, err = process_receipt(output, "connection-rust-compare", check, command, root, 180, aggregate=True)
    require(not err and json.loads(out) == summary == original, "complete original wrapper stdout differs")
    artifacts = dict(native["artifact_sha256"])
    for name, digest in original["artifacts"].items():
        raw = artifact(output, artifacts, folder / name)
        require(sha(raw) == digest, "original artifact differs: " + name)
    for path in [folder / "result.json", output / "connection-rust-compare.stdout", output / "connection-rust-compare.stderr"]:
        artifact(output, artifacts, path)
    from hia_native_connection_reference import check_project
    preparation = object_at(folder / "project/reference-inputs.json")
    identity = object_at(root / "tests/hia_native/connection_reference/source-identity.json")
    check_project(folder / "project", preparation)
    require(preparation.get("source_identity_sha256") == sha(read(root / "tests/hia_native/connection_reference/source-identity.json"))
            and preparation.get("files") == identity["files"] and len(preparation.get("packages", [])) == 100
            and preparation.get("original_sources") == identity["original_sources"]
            and preparation.get("original_blocks") == identity["original_blocks"], "exact original project binding differs")
    for name in identity["files"]:
        require(read(folder / "project" / name) == read(root / "tests/hia_native/connection_reference" / name), "copied original project changed")
    env = original.get("environment", {})
    require(env.get("removed") == list(REMOVED_ENVIRONMENT) and env.get("removed_prefixes") == ["HIA_"]
            and env.get("RUSTC") == original["rustc"] and env.get("CARGO_TARGET_DIR") == str(folder / "target")
            and env.get("offline") in (True, False), "reference environment domain differs")
    records = original.get("processes", [])
    require([r.get("name") for r in records] == ["rustc-version", "cargo-build", *[r[0] for r in REPLAYS]],
            "complete original process inventory differs")
    rustc, cargo = Path(original["rustc"]), Path(original["cargo"])
    require(sha(read(rustc.resolve(strict=True))) == original["rustc_sha256"]
            and sha(read(cargo.resolve(strict=True))) == original["cargo_sha256"], "selected Rust tools changed")
    stdout, stderr = process_receipt(folder, "rustc-version", records[0], [str(rustc), "--version", "--verbose"], root, 10)
    require(not stderr and b"release: 1.95.0\n" in stdout, "original Rust version differs")
    command = [str(cargo), "build", "--release", "--locked", "--bins"] + (["--offline"] if env["offline"] else [])
    process_receipt(folder, "cargo-build", records[1], command, folder / "project", 120)
    require(set(original["binaries"]) == {r[3] for r in REPLAYS}, "three reference binaries incomplete")
    for name, value in original["binaries"].items():
        binary = folder / "target/release" / name
        raw = artifact(output, artifacts, binary)
        require(value.get("path") == str(binary) and value.get("bytes") == len(raw)
                and value.get("sha256_before") == value.get("sha256_after") == sha(raw), "reference executable changed")
    joins = []
    bundle = object_at(output / "build/connection-build.json")
    for replay, record in zip(REPLAYS, records[2:], strict=True):
        name, domain, expected_name, binary, count = replay
        request = read(Path(bundle["reference_data"]) / domain / "requests.jsonl")
        require(record.get("input_bytes") == len(request) and record.get("input_sha256") == sha(request), "actual replay input differs")
        stdout, stderr = process_receipt(folder, name, record, [str(folder / "target/release" / binary)], folder / "project", 120)
        require(not stderr and stdout == read(Path(bundle["reference_data"]) / domain / expected_name), "complete actual original bytes differ")
        joins.append(compare_replay_to_native(root, output / "connection-native/result.json", replay, stdout))
    require(original.get("joins") == joins and original.get("native_result_sha256") == native["compatibility_result_sha256"],
            "complete actual original/native joins differ")
    require(native_evidence(root, output, report, completed_test_summary) == native, "native evidence changed during original admission")
    return {"schema": "hepta.sdk-connection.original-evidence.v1", "status": "PASS", "cases": 11789,
            "original_processes": 6, "fresh_cargo_builds": 1, "reference_binaries": 3, "registry_packages": 100,
            "artifact_sha256": artifacts, "corpus_sha256": native["corpus_sha256"],
            "native_calls_added_by_evidence_admission": 0, "rust_calls_added_by_evidence_admission": 0,
            "production_tool_dispatch_closed": False, "client_result_typed_normalization_closed": False}
