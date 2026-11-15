# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only admission of actual public registry builds and complete replays.

Only build_public_registry launches a process. All verification functions read
retained bytes and completion records; none executes a native or Rust owner.
"""
from pathlib import Path
import collections
import gzip
import hashlib
import json
import math
import os
import signal
import stat
import struct
import subprocess
import sys
import time

from public_registry_registry import (COMPILER, COMPILER_IMAGE, TESTS, FOLDERS,
    REMOVED_ENVIRONMENT, profile, source_pins)

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "retained file is not regular: " + str(path))
    return path.read_bytes()


def object_at(path):
    value = json.loads(read(path))
    require(type(value) is dict, "retained object expected")
    return value


def confined(root, value):
    root = Path(root).resolve(strict=True)
    path = Path(value)
    path = path if path.is_absolute() else root / path
    require(not path.is_symlink(), "retained symlink refused")
    actual = path.resolve(strict=True)
    require(actual.is_relative_to(root), "retained artifact escaped its build")
    return actual


def keep(root, artifacts, value):
    path = confined(root, value)
    raw = read(path)
    artifacts[path.relative_to(root).as_posix()] = sha(raw)
    return raw


def duration(value, limit):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value < limit,
        "actual process duration differs")


def completed(folder, name, row, command, cwd, limit, aggregate=False):
    out, err = read(folder / (name + ".stdout")), read(folder / (name + ".stderr"))
    require(row.get("command") == list(map(str, command))
        and (row.get("cwd", str(cwd)) if aggregate else row.get("cwd")) == str(cwd)
        and type(row.get("exit_code")) is int and row["exit_code"] == 0
        and row.get("timed_out") is False and not row.get("start_error")
        and row.get("timeout_seconds") == limit, "actual completed command differs: " + name)
    duration(row.get("elapsed_seconds"), limit)
    require(row.get("stdout_sha256") == sha(out) and row.get("stderr_sha256") == sha(err),
        "actual process streams changed: " + name)
    for key, count in (("stdout_bytes", len(out)), ("stderr_bytes", len(err))):
        if key in row:
            require(type(row[key]) is int and row[key] == count, "actual process stream length differs")
    return out, err


def build_public_registry(hepta, build_root, source_root):
    root, build = Path(source_root).resolve(strict=True), Path(build_root).resolve()
    build.mkdir(parents=True, exist_ok=True)
    pins = source_pins(root)
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_public_registry.py"),
        "--hepta", str(Path(hepta).resolve(strict=True)), "--build-root", str(build)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("HIA_")}
    begin = time.monotonic()
    process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)
    timed = False
    try:
        out, err = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed = True
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate(timeout=3)
    row = dict(command=command, cwd=str(root), exit_code=process.returncode, timed_out=timed,
        timeout_seconds=180, cleanup_seconds=3, elapsed_seconds=time.monotonic() - begin,
        stdout_sha256=sha(out), stdout_bytes=len(out), stderr_sha256=sha(err), stderr_bytes=len(err),
        sources_before=pins, sources_after=source_pins(root), outer_parent_death_cleanup_qualified=False)
    for suffix, raw in (("stdout", out), ("stderr", err), ("receipt.json", encoded(row))):
        (build / ("public-registry-build." + suffix)).write_bytes(raw)
    require(not timed and process.returncode == 0 and not err, "actual public registry build failed")
    require(row["sources_after"] == pins, "public registry sources changed during build")
    manifest = build / "public-registry-build.json"
    require(json.loads(out) == {"manifest": str(manifest), "modules": 18, "actual_static_elfs": 1},
        "actual public registry build summary differs")
    verify_build(root, manifest)
    return manifest


def compile_evidence(root, build, row, reference, artifacts):
    path = confined(build, reference["path"])
    raw = keep(build, artifacts, path)
    require(sha(raw) == reference["sha256"], "compiled manifest changed")
    meta = json.loads(raw)
    require(meta.get("schema") == "hepta.runtime.native-module.v1"
        and meta.get("compiler_commit") == COMPILER and meta.get("compiler_sha256") == COMPILER_IMAGE
        and meta.get("buffer_profile", "standard") == row["buffer_profile"] and meta.get("standalone") is None
        and meta.get("source_sha256") == row["source_sha256"] and meta.get("image_sha256") == row["image_sha256"],
        "compiled source/image/profile differs")
    source = keep(build, artifacts, path.parent / meta["source"])
    image = keep(build, artifacts, path.parent / meta["image"])
    require(source == read(root / row["source"]) and sha(source) == row["source_sha256"]
        and sha(image) == row["image_sha256"], "compiled source or image bytes changed")
    receipt = json.loads(keep(build, artifacts, path.parent / "module.receipt.json"))
    built = json.loads(keep(build, artifacts, path.parent / "build.json"))
    request = json.loads(keep(build, artifacts, path.parent / "module.request.json"))
    complete_in = keep(build, artifacts, path.parent / "module.input.bin")
    complete_out = keep(build, artifacts, path.parent / "module.output.bin")
    stdout = keep(build, artifacts, path.parent / "module.stdout.log")
    stderr = keep(build, artifacts, path.parent / "module.stderr.log")
    observer = json.loads(stdout)
    require(type(observer) is dict and set(observer) >= {"status", "abi_status", "core_u32", "result_u64",
        "source_unchanged", "source_sha256", "output_sha256", "image_sha256", "forbidden_compiler_modules_loaded"},
        "actual compiler observer is incomplete")
    require(not stderr and all(receipt.get(k) == v for k, v in observer.items())
        and built.get("compile_receipt") == receipt and built.get("compiler_dependency", {}).get("commit") == COMPILER,
        "actual compiler process result differs")
    require(receipt.get("status") == "returned" and receipt.get("abi_status") == 0
        and receipt.get("source_unchanged") is True and receipt.get("forbidden_compiler_modules_loaded") == []
        and receipt.get("source_sha256") == receipt.get("input_sha256") == row["source_sha256"]
        and receipt.get("produced_sha256") == row["image_sha256"] and receipt.get("produced_bytes") == len(image)
        and receipt.get("core_u32") == receipt.get("result_u64") == len(image)
        and receipt.get("image_sha256") == COMPILER_IMAGE, "actual HIA compiler invocation did not succeed")
    require(complete_in == source and complete_out[:len(image)] == image
        and sha(complete_out) == receipt["output_sha256"] and len(complete_out) == request.get("capacity") == 1048576
        and request.get("image_sha256") == COMPILER_IMAGE and request.get("source_sha256") == row["source_sha256"],
        "complete actual compiler buffers differ")
    return meta, image


def verify_build(root, bundle_path):
    root, bundle_path = Path(root).resolve(strict=True), Path(bundle_path).resolve(strict=True)
    build = bundle_path.parent
    require(bundle_path.name == "public-registry-build.json", "public build name changed")
    graph, pins, artifacts = profile(root), source_pins(root), {}
    bundle = json.loads(keep(build, artifacts, bundle_path))
    expected = [*graph["members"], {"name": "packer", **graph["packer"]}]
    require(bundle.get("schema") == "hepta.public-registry.build.v1" and bundle.get("sources") == pins
        and bundle.get("compiler_commit") == COMPILER and bundle.get("compiler_sha256") == COMPILER_IMAGE
        and set(bundle.get("modules", {})) == {row["name"] for row in expected}
        and all(bundle.get(k) is False for k in ("production_activated", "public_request_audit_closed",
            "public_request_result_lifecycle_closed", "fresh_cold_qualified")), "public build inventory/scope changed")
    modules = {row["name"]: compile_evidence(root, build, row, bundle["modules"][row["name"]], artifacts) for row in expected}
    manifest = confined(build, bundle["executable"]["path"])
    raw = keep(build, artifacts, manifest)
    require(manifest == build / "public-registry-elf/manifest.json" and sha(raw) == bundle["executable"]["sha256"],
        "public executable manifest changed")
    native = json.loads(raw)
    require(native.get("schema") == "hepta.runtime.public-registry-native.v1" and native.get("source_map") == pins
        and native.get("compiler_commit") == COMPILER and native.get("compiler_sha256") == COMPILER_IMAGE
        and native.get("call_edges") == graph["call_edges"] and native.get("only_effect_owner") == 1
        and native.get("adapter_source_sha256") == graph["adapter_source_sha256"] == sha(read(root / graph["adapter_source"]))
        and all(native.get(k) is False for k in ("caller_configuration_installation", "production_activated",
            "public_request_audit_closed", "public_request_result_lifecycle_closed", "fresh_cold_qualified")),
        "public fixed boundary or scope differs")
    binary = manifest.parent / native["executable"]
    elf = keep(build, artifacts, binary)
    require(binary.name == "public-runtime.elf" and stat.S_IMODE(binary.stat().st_mode) == 0o500
        and (len(elf), sha(elf)) == (graph["elf_bytes"], graph["elf_sha256"])
        and (native.get("elf_bytes"), native.get("elf_sha256")) == (len(elf), sha(elf))
        and native.get("prefix_bytes") == graph["prefix_bytes"] and native.get("prefix_sha256") == graph["prefix_sha256"],
        "actual static ELF differs")
    prefix = bytearray(elf[:graph["prefix_bytes"]])
    struct.pack_into("<QQ", prefix, 96, 0, 0)
    require(len(native["members"]) == 17, "fixed public image count changed")
    images, at = [], len(prefix)
    for expected, member in zip(graph["members"], native["members"], strict=True):
        meta, image = modules[expected["name"]]
        reference = bundle["modules"][expected["name"]]
        require(member == {**expected, "manifest": reference["path"], "manifest_sha256": reference["sha256"]},
            "embedded image descriptor differs")
        for key in ("buffer_profile", "input_capacity", "output_capacity", "workspace_capacity"):
            require(meta.get(key, "standard" if key == "buffer_profile" else None) == member[key], "embedded ABI differs")
        hole = member["call_displacement_offset"]
        require(member["offset"] == at and elf[at:at + len(image)] == image and elf[hole - 1] == 0xe8
            and hole + 4 + struct.unpack_from("<i", elf, hole)[0] == at, "actual native call target differs")
        struct.pack_into("<I", prefix, hole, 0)
        images.append(image)
        at += len(image)
    require(at == len(elf) and sha(prefix) == graph["prefix_sha256"], "actual fixed kernel prefix differs")
    frame = keep(build, artifacts, manifest.parent / "pack.input.bin")
    require(frame == b"HPRTMCP1" + b"".join(struct.pack("<Q", len(image)) for image in images) + bytes(8) + b"".join(images)
        and (len(frame), sha(frame)) == (graph["frame_bytes"], graph["frame_sha256"]), "complete packer input changed")
    packer = bundle["modules"]["packer"]
    require(native.get("packer_manifest") == packer["path"] and native.get("packer_manifest_sha256") == packer["sha256"],
        "native packer image binding changed")
    receipt = json.loads(keep(build, artifacts, manifest.parent / "pack-process.json"))
    command = [sys.executable, "-I", "-B", str(root / "scripts/public_registry_pack_child.py"),
        "--manifest", packer["path"], "--input", str(manifest.parent / "pack.input.bin"), "--output", str(binary)]
    out, err = completed(manifest.parent, "pack", receipt, command, root, 30)
    for suffix in ("stdout", "stderr"):
        keep(build, artifacts, manifest.parent / ("pack." + suffix))
    observed = json.loads(out)
    require(not err and set(observed) == {"status", "native_result_code", "source_unchanged", "manifest_sha256",
        "input_sha256", "input_bytes", "output_sha256", "output_bytes", "output_capacity", "workspace_capacity",
        "elapsed_nanoseconds", "forbidden_compiler_modules_loaded"}, "actual native packer observer differs")
    require(observed["status"] == "returned" and observed["source_unchanged"] is True
        and observed["native_result_code"] == observed["output_bytes"] == observed["output_capacity"] == len(elf)
        and observed["input_bytes"] == len(frame) and observed["input_sha256"] == sha(frame)
        and observed["manifest_sha256"] == packer["sha256"] and observed["output_sha256"] == sha(elf)
        and observed["workspace_capacity"] == 4096 and observed["forbidden_compiler_modules_loaded"] == []
        and type(observed["elapsed_nanoseconds"]) is int and observed["elapsed_nanoseconds"] > 0,
        "actual packer execution/custody differs")
    return {"schema": "hepta.public-registry.build-evidence.v1", "sources": pins,
        "bundle_sha256": sha(read(bundle_path)), "artifact_sha256": artifacts,
        "elf_sha256": sha(elf), "compiled_roles": 18, "actual_static_elfs": 1}


def build_evidence(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    row = report["modules"]["public_registry"]
    require(row.get("builder") == "public_registry", "public aggregate owner changed")
    manifest = confined(output, row["manifest"])
    require(manifest == output / "build/public-registry-build.json" and sha(read(manifest)) == row["sha256"]
        and report.get("compiler_commit") == COMPILER and report.get("compiler_image_sha256") == COMPILER_IMAGE,
        "registered public build identity changed")
    result = verify_build(root, manifest)
    artifacts = {"build/" + name: digest for name, digest in result["artifact_sha256"].items()}
    receipt = object_at(manifest.parent / "public-registry-build.receipt.json")
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_public_registry.py"),
        "--hepta", str(Path(report["compiler_checkout"]).resolve(strict=True)), "--build-root", str(manifest.parent)]
    out, err = completed(manifest.parent, "public-registry-build", receipt, command, root, 180)
    require(not err and json.loads(out) == {"manifest": str(manifest), "modules": 18, "actual_static_elfs": 1}
        and receipt.get("cleanup_seconds") == 3 and receipt.get("sources_before") == receipt.get("sources_after") == result["sources"]
        and receipt.get("outer_parent_death_cleanup_qualified") is False, "actual public build completion differs")
    for name in ("receipt.json", "stdout", "stderr"):
        keep(output, artifacts, manifest.parent / ("public-registry-build." + name))
    return {**result, "artifact_sha256": artifacts}


def test_commands(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    bundle = object_at(confined(output, report["modules"]["public_registry"]["manifest"]))
    manifest = Path(bundle["executable"]["path"])
    meta = object_at(manifest)
    base = {name: [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name)] for name in TESTS}
    base[TESTS[0]] += ["--binary", str(manifest.parent / meta["executable"]),
        "--output", str(output / "public-registry-native/cases"), "--label", "native"]
    for name, folder in zip(TESTS[1:], FOLDERS[1:], strict=True):
        base[name] += ["--manifest", str(manifest), "--output", str(output / "public-registry-native" / folder)]
    return base


def verify_cases(root, folder, binary_sha, domain):
    root, folder = Path(root).resolve(strict=True), Path(folder).resolve(strict=True)
    sys.path.insert(0, str(root / "tests/hia_native"))
    from public_registry_cases import cases, compact
    expected = cases()
    require(len(expected) == 152 and sum(len(c["events"]) for c in expected) == 1038
        and sum(e["response"] for c in expected for e in c["events"]) == 1036, "complete fixed session domain changed")
    require(read(folder / "cases.json") == compact(expected) + b"\n", "retained public case list differs")
    summary = object_at(folder / "result.json")
    raw, process_raw = read(folder / "output.jsonl"), read(folder / "processes.jsonl")
    require(summary.get("status") == "PASS" and summary.get("domain") == domain
        and summary.get("binary_sha256") == binary_sha and summary.get("cases_sha256") == sha(compact(expected))
        and summary.get("planned_sessions") == summary.get("completed_sessions") == 152
        and summary.get("actual_responses") == 1036 and summary.get("outer_audit_result_lifecycle_closed") is False
        and (summary.get("output_sha256"), summary.get("output_bytes")) == (sha(raw), len(raw))
        and (summary.get("processes_sha256"), summary.get("processes_bytes")) == (sha(process_raw), len(process_raw)),
        "complete actual public session report differs")
    rows, receipts = list(map(json.loads, raw.splitlines())), list(map(json.loads, process_raw.splitlines()))
    require(len(rows) == len(receipts) == 152, "actual public sessions incomplete")
    executable_paths = set()
    for case, row, receipt in zip(expected, rows, receipts, strict=True):
        replies = [event for event in case["events"] if event["response"]]
        require(row.get("label") == receipt.get("label") == case["label"] and len(row.get("rows", [])) == len(replies)
            and row.get("exit_code") == 0 and row.get("stderr_sha256") == row.get("stdout_tail_sha256") == sha(b""),
            "actual public session output ordering/termination differs")
        for event, result in zip(replies, row["rows"], strict=True):
            require(result["request_hex"] == event["hex"] and type(json.loads(bytes.fromhex(result["response_hex"]))) is dict,
                "actual public request/response alignment differs")
        request = b"".join(bytes.fromhex(e["hex"]) + b"\n" for e in case["events"])
        stdout = b"".join(bytes.fromhex(r["response_hex"]) + b"\n" for r in row["rows"])
        require(type(receipt.get("command")) is list and len(receipt["command"]) == 3
            and receipt["command"][1] == "--runtime-config" and receipt.get("cwd") == str(root)
            and receipt.get("environment") == {"PATH": "", "LC_ALL": "C"}
            and receipt.get("exit_code") == 0 and receipt.get("timed_out") is False
            and receipt.get("timeout_seconds_per_response") == 10 and receipt.get("request_events") == len(case["events"])
            and receipt.get("input_sha256") == sha(request) and receipt.get("input_bytes") == len(request)
            and receipt.get("stdout_sha256") == sha(stdout) and receipt.get("stdout_bytes") == len(stdout)
            and receipt.get("stderr_sha256") == sha(b"") and receipt.get("stderr_bytes") == 0,
            "actual public process invocation or complete streams differ")
        duration(receipt.get("elapsed_seconds"), 10 * (len(replies) + 1))
        executable_paths.add(receipt["command"][0])
    require(len(executable_paths) == 1, "session executable changed within the complete replay")
    executable = read(Path(next(iter(executable_paths))))
    require(sha(executable) == binary_sha and len(executable) == summary.get("binary_bytes"), "actual session executable changed")
    return {"sessions": 152, "responses": 1036, "input_events": 1038,
        "output_sha256": sha(raw), "output_bytes": len(raw), "processes_sha256": sha(process_raw)}


CONTROL_COUNTS = {"native_router_calls": 119, "decoder_calls": 7, "connection_calls": 7,
    "fixture_child_acks": 6, "diagnostic_nonzero_controls": 3, "receipt_refusals": 48, "envelope_refusals": 12,
    "private_input_refusals": 28, "capacity_refusals": 8}
CONTROL_GROUPS = ["private-header-and-span-before-publication", "fixed-receipts-and-child-envelope-admission",
    "exact-default-errors-and-sorted-real-catalog", "output-measurement-and-next-request-after-capacity"]
ELF_COUNTS = {"above_old_parser_node_limit_controls": 1, "actual_mode_transition_controls": 5,
    "actual_processes": 12, "actual_regex_configurations": 1, "actual_responses": 34,
    "caller_mode_cli_refusals": 4, "embedded_images_verified": 17, "eof_released_lock_controls": 2,
    "exact_8mib_final_eof_controls": 1, "exact_8mib_frame_controls": 1, "fatal_released_lock_controls": 2,
    "held_lock_controls": 2, "ignored_transport_then_real_route_controls": 2, "immutable_authority_controls": 6,
    "large_escaped_id_controls": 1, "overlong_fatal_no_partial_reply_controls": 1, "regex_before_state_effect_refusals": 1}


def native_evidence(root, output, report, completed_test_summary, create=False):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    built = build_evidence(root, output, report)
    bundle = object_at(output / "build/public-registry-build.json")
    manifest = Path(bundle["executable"]["path"])
    graph = profile(root)
    artifacts, corpus, summaries, records = dict(built["artifact_sha256"]), {}, {}, []
    commands = test_commands(root, output, report)
    for name, folder_name in zip(TESTS, FOLDERS, strict=True):
        folder = output / "public-registry-native" / folder_name
        row, summary = completed_test_summary(output, report, name)
        out, _ = completed(output, name, row, commands[name], root, 180, aggregate=True)
        require(json.loads(out) == summary == object_at(folder / "result.json") and summary.get("status") == "PASS",
            "actual public native test completion/result differs")
        for path in (folder / "result.json", output / (name + ".stdout"), output / (name + ".stderr")):
            keep(output, artifacts, path)
        records.append({"name": name, **{k: row[k] for k in ("command", "exit_code", "timed_out", "timeout_seconds", "stdout_sha256", "stderr_sha256")}})
        summaries[folder_name] = summary
        if folder_name == "cases":
            verify_cases(root, folder, graph["elf_sha256"], "native")
            for item in ("cases.json", "output.jsonl", "processes.jsonl"):
                raw = keep(output, artifacts, folder / item)
                corpus[(folder / item).relative_to(output).as_posix()] = sha(raw)
        elif folder_name == "controls":
            require(summary.get("groups") == CONTROL_GROUPS and summary.get("elf_sha256") == graph["elf_sha256"]
                and all(summary.get(k) == v for k, v in CONTROL_COUNTS.items()), "actual private receipt/control domain changed")
        else:
            require(summary.get("groups") == 5 and summary.get("counts") == ELF_COUNTS
                and summary.get("manifest_sha256") == bundle["executable"]["sha256"]
                and summary.get("test_source_sha256") == built["sources"]["tests/hia_native/" + name]
                and summary.get("source_unchanged") is True and summary.get("kernel_loaded_static_elf") is True
                and summary.get("synthetic_child_completions") is False and summary.get("original_rust_executed_here") is False
                and summary.get("public_audit_result_lifecycle_closed") is False,
                "actual ELF authority/framing domain differs")
            packed = keep(output, artifacts, folder / "transcript.jsonl.gz")
            require((len(packed), sha(packed)) == (summary.get("transcript_bytes"), summary.get("transcript_sha256")),
                "complete ELF transcript changed")
            rows = list(map(json.loads, gzip.decompress(packed).splitlines()))
            require(len(rows) == 34 and collections.Counter(row["kind"] for row in rows)
                == {"request": 31, "eof-frame": 1, "overlong-frame": 1, "startup-refusal": 1},
                "complete ELF transcript inventory changed")
            for observed in rows:
                request, response = bytes.fromhex(observed["request_hex"]), bytes.fromhex(observed["response_hex"])
                if observed["kind"] == "request":
                    require(json.loads(request)["id"] == json.loads(response)["id"], "actual ELF reply ID differs")
                elif observed["kind"] == "startup-refusal":
                    require(request == b"" and response == b"host `h` privileged action `inspect` has invalid argument regex\n",
                        "actual regex startup order differs")
                else:
                    require(len(request) > 8388608 and len(response.splitlines()) == (2 if observed["kind"] == "eof-frame" else 1),
                        "actual frame bound/partial output observation differs")
            corpus[(folder / "transcript.jsonl.gz").relative_to(output).as_posix()] = sha(packed)
    compatibility = {"schema": "hepta.public-registry.native-result.v1", "status": "PASS", "sources": built["sources"],
        "build": str(output / "build/public-registry-build.json"), "build_sha256": built["bundle_sha256"],
        "records": records, "summaries": summaries, "artifact_sha256": artifacts, "corpus_sha256": corpus,
        "actual_elf_processes": 164, "actual_elf_responses": 1070, "explicit_fixture_router_calls": 119,
        "public_audit_result_lifecycle_closed": False}
    path = output / "public-registry-native/result.json"
    raw = encoded(compatibility)
    if create:
        require(not path.exists(), "native aggregate result is create-only")
        path.write_bytes(raw)
    else:
        require(read(path) == raw, "native aggregate result is not derived from the complete actual tests")
    keep(output, artifacts, path)
    return {"schema": "hepta.public-registry.native-evidence.v1", "sources": built["sources"],
        "artifact_sha256": artifacts, "corpus_sha256": corpus, "native_result_sha256": sha(raw),
        "actual_elf_processes": 164, "actual_elf_responses": 1070,
        "native_calls_added_by_evidence_admission": 0, "public_audit_result_lifecycle_closed": False}


def original_evidence(root, output, report, completed_test_summary):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    native = native_evidence(root, output, report, completed_test_summary)
    folder = output / "public-registry-original"
    original = object_at(folder / "result.json")
    require(original.get("schema") == "hepta.public-registry.original-result.v1" and original.get("status") == "PASS"
        and original.get("sources") == source_pins(root) and original.get("fresh_actual_cargo_build") is True
        and original.get("native_processes_in_recipe") == original.get("original_processes_in_recipe") == 152
        and original.get("native_responses_in_recipe") == original.get("original_responses_in_recipe") == 1036
        and original.get("locked_registry_dependencies") == 100 and original.get("sdk_installed_files_verified") == 175
        and original.get("sdk_source_files_verified") == 65
        and original.get("config_source_blocks") == 54 and original.get("public_server_blocks") == 10
        and original.get("hia_catalog_predicate_blocks") == 1 and original.get("public_audit_result_lifecycle_closed") is False,
        "complete actual original scope differs")
    command = [sys.executable, "-I", "-B", str(root / "tests/hia_native/compare_public_registry_original.py"),
        "--repo", str(root), "--build", str(output / "build/public-registry-build.json"), "--output", str(folder),
        "--cargo", original["cargo"], "--rustc", original["rustc"], "--rustfmt", original["rustfmt"]]
    if original["environment"]["offline"]:
        command += ["--offline"]
    row, summary = completed_test_summary(output, report, "public-registry-rust-compare")
    out, err = completed(output, "public-registry-rust-compare", row, command, root, 180, aggregate=True)
    printed = {k: v for k, v in original.items() if k not in ("sources", "native_build_evidence", "processes", "artifacts", "sdk_files")}
    require(not err and json.loads(out) == summary == printed, "actual original wrapper stdout differs")
    artifacts = dict(native["artifact_sha256"])
    for name, digest in original["artifacts"].items():
        require(sha(keep(output, artifacts, folder / name)) == digest, "actual original artifact changed: " + name)
    for path in (folder / "result.json", output / "public-registry-rust-compare.stdout", output / "public-registry-rust-compare.stderr"):
        keep(output, artifacts, path)
    from hia_native_public_registry_reference import check_project
    prepared = object_at(folder / "project/reference-inputs.json")
    check_project(root, folder / "project", prepared)
    require(prepared.get("config_source_blocks") == 54 and prepared.get("public_server_blocks") == 10
        and prepared.get("hia_catalog_predicate_blocks") == 1 and len(prepared["packages"]) == 100
        and prepared.get("original_outer_call_tool_included") is False, "original project binding differs")
    graph, bundle = profile(root), object_at(output / "build/public-registry-build.json")
    require(original.get("build_sha256") == sha(read(output / "build/public-registry-build.json"))
        and original.get("native_build_evidence") == verify_build(root, output / "build/public-registry-build.json"),
        "reference does not bind the actual native images")
    reference = folder / "target/release/hia-runtime-config-mcp"
    actual = read(reference)
    require(original["original_binary"] == {"path": str(reference), "bytes": len(actual),
        "sha256_before": sha(actual), "sha256_after": sha(actual)}, "actual original binary changed")
    env = original["environment"]
    require(env.get("removed") == list(REMOVED_ENVIRONMENT) and env.get("removed_prefixes") == ["HIA_"]
        and env.get("RUSTC") == original["rustc"] and env.get("CARGO_TARGET_DIR") == str(folder / "target")
        and type(env.get("offline")) is bool, "original build environment differs")
    records = original["processes"]
    require([r.get("name") for r in records] == ["rustc-version", "rustfmt-check", "cargo-fetch", "cargo-build", "catalog", "native-sessions", "original-sessions"],
        "actual original process domain differs")
    offline = ["--offline"] if env["offline"] else []
    binary = Path(bundle["executable"]["path"]).parent / "public-runtime.elf"
    commands = [([original["rustc"], "--version", "--verbose"], root, 10),
        ([original["rustfmt"], "--edition", "2021", "--check", "--config", "hard_tabs=true,skip_children=true", str(folder / "project/mcp/oracle_mcp.rs")], root, 15),
        ([original["cargo"], "fetch", "--locked", *offline], folder / "project", 120),
        ([original["cargo"], "build", "--release", "--locked", "--bin", "hia-runtime-config-mcp", *offline], folder / "project", 120),
        ([str(reference), "--catalog"], folder / "project", 15)]
    commands += [([sys.executable, "-I", "-B", str(root / "tests/hia_native/run_public_registry_cases.py"),
        "--binary", str(executable), "--output", str(folder / label), "--label", label], root, 120)
        for label, executable in (("native", binary), ("original", reference))]
    for record, (argv, cwd, limit) in zip(records, commands, strict=True):
        observed, error = completed(folder, record["name"], record, argv, cwd, limit)
        if record["name"] == "rustc-version":
            require(not error and b"release: 1.95.0\n" in observed, "actual original Rust version changed")
        if record["name"] in ("native-sessions", "original-sessions"):
            label = record["name"].split("-")[0]
            require(not error and json.loads(observed) == object_at(folder / label / "result.json"), "actual session wrapper summary differs")
    catalog = object_at(root / "tests/hia_native/public_registry_catalog.json")
    require(read(folder / "catalog.stdout") == (catalog["legacy"] + "\n" + catalog["modern"] + "\n").encode()
        and not read(folder / "catalog.stderr"), "actual original catalog bytes differ")
    left = verify_cases(root, folder / "native", graph["elf_sha256"], "native")
    right = verify_cases(root, folder / "original", sha(actual), "original")
    require(read(folder / "native/output.jsonl") == read(folder / "original/output.jsonl")
        and left["output_sha256"] == right["output_sha256"] == original.get("complete_output_sha256")
        and left["output_bytes"] == right["output_bytes"] == original.get("complete_output_bytes")
        and original.get("complete_byte_equality") is True, "complete native/original bytes differ")
    for tool, digest in original["tool_sha256"].items():
        require(sha(read(Path(tool).resolve(strict=True))) == digest, "selected original tool changed")
    require(set(original["tool_sha256"]) == {original["cargo"], original["rustc"], original["rustfmt"]}, "original tool inventory differs")
    crate = read(folder / "rmcp-3.4.1.crate")
    require(sha(crate) == original.get("sdk_crate_sha256") == "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898"
        and len(original["sdk_files"]) == 175, "locked SDK source inventory differs")
    import io, tarfile
    sdk_files = {}
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
        for item in archive:
            if item.isfile() and item.name.startswith("rmcp-3.4.1/"):
                name = item.name.removeprefix("rmcp-3.4.1/")
                body = archive.extractfile(item).read()
                require(read(folder / "sdk" / name) == body and name not in sdk_files, "retained SDK source differs from crate")
                sdk_files[name] = {"bytes": len(body), "sha256": sha(body)}
    require(sdk_files == original["sdk_files"] and sum(name.startswith("src/") for name in sdk_files) == 65,
        "complete SDK source map differs")
    require(native_evidence(root, output, report, completed_test_summary) == native, "native evidence changed during original admission")
    return {"schema": "hepta.public-registry.original-evidence.v1", "status": "PASS", "sources": source_pins(root),
        "artifact_sha256": artifacts, "corpus_sha256": native["corpus_sha256"],
        "native_processes_in_original_recipe": 152, "original_processes": 152,
        "native_responses_in_original_recipe": 1036, "original_responses": 1036,
        "original_builds": 1, "locked_registry_dependencies": 100,
        "native_calls_added_by_evidence_admission": 0, "rust_calls_added_by_evidence_admission": 0,
        "public_audit_result_lifecycle_closed": False}
