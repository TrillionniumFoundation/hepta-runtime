#!/usr/bin/env python3
"""Execute every outcome projection and retain complete guarded native buffers.

The semantic input corpus is constructed by shell_outcome_cases. This module
does not calculate expected Shell text. Original Rust comparison is separate.
Private transport refusals and allocator pressure are counted independently.
The evidence reader performs ordinary file reads and pure byte validation only.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[2]
DRIVER = "tests/hia_native/shell_outcome_state.py"
CASES = "tests/hia_native/shell_outcome_cases.py"
BUILDER = "scripts/hia_native_shell_outcome_build.py"
SCHEMA = "hepta.runtime.shell-outcome-native-corpus.v1"
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
ARRAY_NAMES = ("input_before", "input_after", "output_before", "output_after",
               "workspace_before", "workspace_after")
BASELINES = ("stream-merge-0-0", "stream-merge-9-10", "errno--1",
             "error-priority-5-0-0", "promotion-2-1-1")
ALLOCATOR_SIZE = 16 * 1024 * 1024
ALLOCATOR_SLACK = 80 * 1024 * 1024
MASK = (1 << 64) - 1
INVALID = 0xffffffff
CAPACITY = 0xfffffffe
SCOPE = {
    "native_entry_executed": True, "original_rust_compared": False,
    "foreground_result_projection": True, "promotion_result_projection": True,
    "filesystem_reads_qualified": False, "production_shell_execution_qualified": False,
    "production_activated": False, "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False, "matching_source_full_cold_qualified": False,
    "physical_over_4gib_test_in_ordinary_corpus": False,
}


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def normalized(value):
    return json.loads(canonical(value))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def byte_pin(raw):
    return {"size": len(raw), "sha256": digest(raw)}


def duplicate_free(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate outcome evidence field")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=duplicate_free)


def regular(path):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "ordinary evidence file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_size) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_size):
        os.close(fd)
        raise ValueError("evidence file changed during admission")
    return os.fdopen(fd, "rb")


def read(path):
    with regular(path) as stream:
        return stream.read()


def file_pin(path):
    hasher = hashlib.sha256()
    size = 0
    with regular(path) as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            hasher.update(block)
    return {"size": size, "sha256": hasher.hexdigest()}


def save(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def save_json(path, value):
    save(path, (canonical(value) + "\n").encode())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "source reader module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def modules():
    builder = load("hia_shell_outcome_native_builder", ROOT / BUILDER)
    cases = load("hia_shell_outcome_native_cases", ROOT / CASES)
    need(Path(builder.__file__).resolve() == (ROOT / BUILDER).resolve(),
         "outcome builder module location")
    return builder, cases


def sources():
    return {name: file_pin(ROOT / name) for name in (DRIVER, CASES, BUILDER)}


def capacity(wire):
    # This is a fixture allocation, never a Shell decision or public input cap.
    return max(4096, 3 * len(wire) + 4096)


def word(wire, offset, value):
    result = bytearray(wire)
    struct.pack_into("<Q", result, offset, value)
    return bytes(result)


def controls(cases, baselines):
    result = []
    def add(name, wire, returned=INVALID, output=4096, workspace=128, fill=0xb8,
            body=None):
        result.append({"name": name, "wire": wire, "returned": returned,
                       "output_capacity": output, "workspace_capacity": workspace,
                       "workspace_fill": fill, "body": body})
    empty = cases.frame()
    for length in (0, 1, 7, 8, 16, 104, 111):
        add("short-frame-" + str(length), empty[:length])
    add("magic", b"X" + empty[1:])
    for value in (0, 4, MASK):
        add("operation-" + str(value), word(empty, 8, value))
    add("trailing-byte", empty + b"x")
    for offset in (72, 80, 88, 96, 104):
        add("length-overflow-" + str(offset), word(empty, offset, MASK))
    for field, offset in (("wait", 16), ("stdout", 32), ("stderr", 48)):
        for kind in (5, MASK):
            add("result-kind-" + field + "-" + str(kind), word(empty, offset, kind))
    for field, kind_offset, value_offset in (("wait", 16, 24), ("stdout", 32, 40), ("stderr", 48, 56)):
        for value in (0x80000000, 0xffffffff, 0xffffffff7fffffff):
            wire = word(word(empty, kind_offset, 2), value_offset, value)
            add("i32-carrier-" + field + "-" + str(value), wire)
    add("foreground-unused-pid", cases.frame(pid=1))
    add("foreground-unused-command", cases.frame(command=b"x"))
    add("foreground-unused-id", cases.frame(id=b"x"))
    add("wait-ok-payload", cases.frame(wait_error=b"x"))
    for field in ("stdout", "stderr"):
        add("read-ok-errno-" + field, cases.frame(**{field + "_errno": 1}))
    for field, payload, value in (("wait", "wait_error", "wait_value"),
                                  ("stdout", "stdout", "stdout_errno"),
                                  ("stderr", "stderr", "stderr_errno")):
        add("display-value-" + field, cases.frame(**{field + "_kind": 1, value: 1}))
        for raw in (b"\xff", b"\xed\xa0\x80"):
            add("display-utf8-" + field + "-" + raw.hex(),
                cases.frame(**{field + "_kind": 1, payload: raw}))
        add("os-error-payload-" + field, cases.frame(**{field + "_kind": 2, payload: b"x"}))
        for kind in (3, 4):
            add("constant-error-value-" + field + "-" + str(kind),
                cases.frame(**{field + "_kind": kind, value: 1}))
            add("constant-error-payload-" + field + "-" + str(kind),
                cases.frame(**{field + "_kind": kind, payload: b"x"}))
    for field in ("wait_kind", "wait_value", "stdout_kind", "stdout_errno",
                  "stderr_kind", "stderr_errno"):
        add("promotion-unused-" + field, cases.frame(op=2, **{field: 1}))
    for field in ("wait_error", "stdout", "stderr"):
        add("promotion-payload-" + field, cases.frame(op=2, **{field: b"x"}))
    add("promotion-pid-overflow", cases.frame(op=2, pid=1 << 32))
    for field in ("command", "id"):
        add("promotion-utf8-" + field, cases.frame(op=2, **{field: b"\xff"}))
    for kind in (0, 1, 3, 4):
        add("errno-operation-kind-" + str(kind), cases.frame(op=3, wait_kind=kind))
    for field in ("stdout_kind", "stdout_errno", "stderr_kind", "stderr_errno", "pid"):
        add("errno-operation-unused-" + field,
            cases.frame(op=3, wait_kind=2, **{field: 1}))
    for field in ("wait_error", "stdout", "stderr", "command", "id"):
        add("errno-operation-payload-" + field,
            cases.frame(op=3, wait_kind=2, **{field: b"x"}))
    add("invalid-before-capacity", b"bad", output=0, workspace=0)
    for size in (0, 1, 127):
        add("workspace-short-" + str(size), empty, CAPACITY, workspace=size)
    for size in (0, 1, 39):
        add("output-header-short-" + str(size), empty, CAPACITY, output=size)
    for name in BASELINES:
        baseline = baselines[name]
        add("output-one-short-" + name, baseline["wire"], CAPACITY,
            output=len(baseline["body"]) - 1)
        add("output-exact-" + name, baseline["wire"], 40,
            output=len(baseline["body"]), body=baseline["body"])
    baseline = baselines["stream-merge-9-10"]
    for fill in (0, 1, 0x7f, 0xff):
        add("workspace-dirty-" + str(fill), baseline["wire"], 40,
            fill=fill, body=baseline["body"])
    baseline = baselines["stream-merge-0-0"]
    add("workspace-extra-byte", baseline["wire"], 40, workspace=129, body=baseline["body"])
    need(len({row["name"] for row in result}) == len(result), "duplicate transport control name")
    return result


def put_arrays(stream, arrays):
    start = stream.tell()
    for name in ARRAY_NAMES:
        raw = arrays[name]
        packed = zlib.compress(raw, 1)
        stream.write(struct.pack("<QQ", len(raw), len(packed)))
        stream.write(packed)
    return start, stream.tell() - start


def exact(stream, length):
    raw = stream.read(length)
    need(len(raw) == length, "truncated native evidence")
    return raw


def get_arrays(stream, sizes):
    start = stream.tell()
    arrays = {}
    for name in ARRAY_NAMES:
        raw_size, packed_size = struct.unpack("<QQ", exact(stream, 16))
        need(raw_size == sizes[name] and 0 < packed_size <= raw_size + raw_size // 256 + 1024,
             "guarded buffer compressed extent")
        packed = exact(stream, packed_size)
        decoder = zlib.decompressobj()
        raw = decoder.decompress(packed, raw_size + 1)
        need(len(raw) == raw_size and decoder.eof and not decoder.unused_data and
             not decoder.unconsumed_tail, "complete bounded buffer decompression")
        arrays[name] = raw
    return arrays, start, stream.tell() - start


def array_sizes(wire, outcap, workcap):
    return {name: (len(wire) if name.startswith("input") else
                   outcap if name.startswith("output") else workcap) + 32
            for name in ARRAY_NAMES}


def verify_entry(entry, arrays, wire, outcap, workcap, workfill, native, *, pid, sequence,
                 returned, body, outer=None):
    for field in ("pid", "entry", "returned", "extent", "input_length", "output_capacity",
                  "workspace_capacity", "output_fill", "workspace_fill"):
        need(type(entry.get(field)) is int, "actual native integer metadata required")
    need(entry.get("status") == "returned" and entry.get("pid") == pid and
         type(pid) is int and pid > 0 and entry.get("entry") == sequence and
         entry.get("returned") == returned and type(entry.get("returned")) is int and
         entry.get("extent") == (len(body) if body is not None else 0) and
         entry.get("input_length") == len(wire) and entry.get("output_capacity") == outcap and
         entry.get("workspace_capacity") == workcap and entry.get("output_fill") == 0xa7 and
         entry.get("workspace_fill") == workfill and
         entry.get("manifest_sha256") == native["manifest"]["sha256"] and
         entry.get("shared_sha256") == native["build_evidence"]["shared_sha256"] and
         entry.get("allocator_sha256") == native["build_evidence"]["allocator_sha256"],
         "actual native entry metadata differs")
    for key in ("started_unix_ns", "finished_unix_ns", "elapsed_ns"):
        need(type(entry.get(key)) is int and entry[key] >= 0, "native entry clock")
    need(entry["finished_unix_ns"] >= entry["started_unix_ns"], "native entry time order")
    if outer is not None:
        need(outer["started_unix_ns"] <= entry["started_unix_ns"] <=
             entry["finished_unix_ns"] <= outer["finished_unix_ns"], "entry outside actual process interval")
    need(set(arrays) == set(ARRAY_NAMES) and
         entry.get("arrays") == {name: byte_pin(arrays[name]) for name in ARRAY_NAMES},
         "complete actual native buffer bytes")
    wanted_input = b"1" * 16 + wire + b"2" * 16
    wanted_output = b"A" * 16 + b"\xa7" * outcap + b"B" * 16
    wanted_workspace = b"Q" * 16 + bytes([workfill]) * workcap + b"R" * 16
    need(arrays["input_before"] == wanted_input and arrays["input_after"] == wanted_input and
         arrays["output_before"] == wanted_output and arrays["workspace_before"] == wanted_workspace,
         "complete input or initialized fixture storage differs")
    extent = len(body) if body is not None else 0
    wanted_after = wanted_output if body is None else b"A" * 16 + body + b"\xa7" * (outcap - extent) + b"B" * 16
    need(arrays["output_after"] == wanted_after and
         arrays["workspace_after"][:16] == b"Q" * 16 and
         arrays["workspace_after"][-16:] == b"R" * 16,
         "actual output prefix, refusal, tail or workspace guards differ")
    expected_guards = {"input_unchanged": True, "input_guards": True, "output_guards": True,
                       "workspace_guards": True, "output_tail_unchanged": True,
                       "output_unchanged": body is None}
    need(entry.get("guards") == expected_guards, "buffer observations disagree with complete bytes")


def row_for(index, name, group, operation, request_offset, response_offset,
            buffer_offset, buffer_bytes, entry):
    return {"index": index, "name": name, "group": group, "operation": operation,
            "request_offset": request_offset, "response_offset": response_offset,
            "buffers_offset": buffer_offset, "buffers_bytes": buffer_bytes, "invocation": entry}


def line(stream):
    raw = stream.readline()
    need(raw and raw.endswith(b"\n"), "missing complete native entry row")
    result = decode(raw)
    need(raw == (canonical(result) + "\n").encode(), "noncanonical native entry row")
    return result


def response(stream, cases, available):
    offset = stream.tell()
    returned, extent = struct.unpack("<QQ", exact(stream, 16))
    need(returned == 40 and 40 <= extent <= available - offset - 16, "semantic native response extent")
    body = exact(stream, extent)
    cases.decode_body(body)
    return offset, body


def operation_envelope(wire, body, cases):
    op = struct.unpack_from("<Q", wire, 8)[0]
    value = cases.decode_body(body)
    need((op == 1 and value["kind"] in (0, 1) and value["uri"] is None) or
         (op == 2 and value["kind"] == 0 and value["uri"] is not None) or
         (op == 3 and value["kind"] == 2 and value["uri"] is None),
         "operation response ABI differs")


def native_binding(manifest, builder):
    path = Path(manifest).resolve(strict=True)
    return {"manifest_path": str(path), "manifest": file_pin(path),
            "build_evidence": builder.read_evidence(path, source_root=ROOT)}


def allocation_wire(cases):
    return cases.frame(stdout=b"A" * ALLOCATOR_SIZE)


def allocation_worker(manifest, output):
    import resource
    builder, cases = modules()
    output.mkdir(parents=True, exist_ok=False)
    native = native_binding(manifest, builder)
    wire = allocation_wire(cases)
    with builder.NativeOutcome(manifest, source_root=ROOT) as module:
        statm = Path("/proc/self/statm").read_bytes()
        page = os.sysconf("SC_PAGE_SIZE")
        vm_size = int(statm.split()[0]) * page
        before = resource.getrlimit(resource.RLIMIT_AS)
        applied = vm_size + ALLOCATOR_SLACK
        need((before[1] == resource.RLIM_INFINITY or applied <= before[1]) and
             (before[0] == resource.RLIM_INFINITY or applied <= before[0]),
             "allocator control requires its bounded address-space headroom")
        started = time.time_ns()
        resource.setrlimit(resource.RLIMIT_AS, (applied, before[1]))
        observed_limit = resource.getrlimit(resource.RLIMIT_AS)
        try:
            value = module.call(wire, 4096)
        finally:
            resource.setrlimit(resource.RLIMIT_AS, before)
        restored = resource.getrlimit(resource.RLIMIT_AS)
        finished = time.time_ns()
        need(value["entry"]["returned"] == CAPACITY and value["body"] is None,
             "actual allocator pressure did not produce private capacity refusal")
        with (output / "buffers.bin").open("xb") as stream:
            offset, size = put_arrays(stream, value["arrays"])
        save_json(output / "entry.json", value["entry"])
        save_json(output / "limits.json", {
            "schema": "hepta.runtime.shell-outcome-allocation-control.v1",
            "pid": os.getpid(), "statm_before_hex": statm.hex(), "page_size": page,
            "vm_size_before": vm_size, "rlimit_before": list(before),
            "rlimit_applied": list(observed_limit), "rlimit_restored": list(restored),
            "started_unix_ns": started, "finished_unix_ns": finished,
            "slack_bytes": ALLOCATOR_SLACK, "input_payload_bytes": ALLOCATOR_SIZE,
            "buffers_offset": offset, "buffers_bytes": size, "native": native,
            "original_log_read_error": False, "capacity_refusal": True,
        })
    print(canonical({"status": "PASS", "returned": CAPACITY, "pid": os.getpid()}))


def run_allocation(output, manifest):
    import subprocess
    folder = output / "allocator"
    python = Path(sys.executable).resolve()
    python_before = file_pin(python)
    save(output / "allocation.python.bin", read(python))
    command = [str(python), "-I", "-B", str(ROOT / DRIVER),
               "--native-manifest", str(manifest), "--allocation-worker", str(folder)]
    started = time.time_ns()
    clock = time.monotonic_ns()
    child = subprocess.Popen(command, cwd=ROOT, env=ENVIRONMENT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timeout = False
    try:
        stdout, stderr = child.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        timeout = True
        child.kill()
        stdout, stderr = child.communicate()
    record = {"command": command, "cwd": str(ROOT), "environment": ENVIRONMENT,
              "python": python_before, "python_after": file_pin(python), "pid": child.pid,
              "exit_code": child.returncode, "timed_out": timeout, "timeout_seconds": 45,
              "started_unix_ns": started, "finished_unix_ns": time.time_ns(),
              "elapsed_ns": time.monotonic_ns() - clock,
              "stdout": byte_pin(stdout), "stderr": byte_pin(stderr)}
    save(output / "allocation.stdout", stdout)
    save(output / "allocation.stderr", stderr)
    save_json(output / "allocation.process.json", record)
    need(not timeout and child.returncode == 0 and stderr == b"" and
         record["python"] == record["python_after"], "allocator control process failed")
    return record


def read_allocation(folder, report, cases):
    process = decode(read(folder / "allocation.process.json"))
    record = report["allocation_process"]
    need(process == record and type(process.get("pid")) is int and process["pid"] > 0 and
         type(process.get("exit_code")) is int and process["exit_code"] == 0 and
         process.get("timed_out") is False and process.get("timeout_seconds") == 45 and
         process.get("cwd") == report["recorded_source_root"] and
         process.get("environment") == ENVIRONMENT and
         type(process.get("elapsed_ns")) is int and process["elapsed_ns"] >= 0,
         "actual allocation control process")
    argv = process["command"]
    need(len(argv) == 8 and argv[1:3] == ["-I", "-B"] and
         argv[3] == str(Path(report["recorded_source_root"]) / DRIVER) and
         argv[4:6] == ["--native-manifest", report["native"]["manifest_path"]] and
         argv[6:] == ["--allocation-worker", str(Path(report["recorded_directory"]) / "allocator")] and
         Path(argv[0]).is_absolute() and
         type(process["python"]["size"]) is int and process["python"]["size"] > 0 and
         len(process["python"]["sha256"]) == 64 and
         process["python"] == process.get("python_after") == file_pin(folder / "allocation.python.bin"),
         "allocation process exact command/tool binding")
    for channel in ("stdout", "stderr"):
        raw = read(folder / ("allocation." + channel))
        need(byte_pin(raw) == process[channel], "allocation process complete stream")
    need(read(folder / "allocation.stderr") == b"" and
         read(folder / "allocation.stdout") == (canonical({"status": "PASS", "returned": CAPACITY,
                                                          "pid": process["pid"]}) + "\n").encode(),
         "allocation process successful actual report")
    limits = decode(read(folder / "allocator/limits.json"))
    need(limits.get("schema") == "hepta.runtime.shell-outcome-allocation-control.v1" and
         limits.get("pid") == process["pid"] and limits.get("native") == report["native"] and
         limits.get("slack_bytes") == ALLOCATOR_SLACK and
         limits.get("input_payload_bytes") == ALLOCATOR_SIZE and
         limits.get("capacity_refusal") is True and limits.get("original_log_read_error") is False,
         "allocator pressure scope")
    statm = bytes.fromhex(limits["statm_before_hex"])
    page = limits["page_size"]
    need(type(page) is int and page > 0 and page & (page - 1) == 0 and
         limits["vm_size_before"] == int(statm.split()[0]) * page and
         limits["rlimit_restored"] == limits["rlimit_before"] and
         limits["rlimit_applied"] == [limits["vm_size_before"] + ALLOCATOR_SLACK,
                                      limits["rlimit_before"][1]] and
         process["started_unix_ns"] <= limits["started_unix_ns"] <=
         limits["finished_unix_ns"] <= process["finished_unix_ns"], "actual address-space pressure limits")
    wire = allocation_wire(cases)
    with regular(folder / "allocator/buffers.bin") as stream:
        arrays, offset, size = get_arrays(stream, array_sizes(wire, 4096, 128))
        need(offset == limits["buffers_offset"] == 0 and size == limits["buffers_bytes"] and
             stream.read(1) == b"", "allocation complete actual buffers")
    entry = decode(read(folder / "allocator/entry.json"))
    verify_entry(entry, arrays, wire, 4096, 128, 0xb8, report["native"],
                 pid=process["pid"], sequence=1, returned=CAPACITY, body=None, outer=process)
    need(limits["started_unix_ns"] <= entry["started_unix_ns"] <= entry["finished_unix_ns"] <=
         limits["finished_unix_ns"], "allocation entry outside applied limit interval")
    return entry


def expected_counts(cases, specifications, recipes):
    values = normalized(cases.counts(specifications))
    invalid = sum(row["returned"] == INVALID for row in recipes)
    short = sum(row["returned"] == CAPACITY for row in recipes)
    positive = sum(row["returned"] == 40 for row in recipes)
    values.update(native_control_cases=len(recipes) + 1, invalid_frame_refusals=invalid,
                  private_capacity_refusals=short + 1, allocator_pressure_refusals=1,
                  positive_transport_controls=positive,
                  actual_native_entries=len(specifications) + len(recipes) + 1,
                  complete_guarded_buffer_snapshots=6 * (len(specifications) + len(recipes) + 1))
    return values


def artifact_names():
    return ("requests.bin", "responses.bin", "entries.jsonl", "buffers.bin",
            "controls/entries.jsonl", "controls/buffers.bin",
            "allocator/entry.json", "allocator/buffers.bin", "allocator/limits.json",
            "allocation.process.json", "allocation.stdout", "allocation.stderr", "allocation.python.bin",
            *("sources/" + name for name in (DRIVER, CASES, BUILDER)))


def read_evidence(folder, native_manifest=None):
    """Validate all retained bytes, source bindings and actual native entries."""
    folder = Path(folder).resolve(strict=True)
    report_raw = read(folder / "report.json")
    report = decode(report_raw)
    need(report.get("schema") == SCHEMA and report.get("status") == "PASS" and
         report.get("error") is None and report.get("scope") == SCOPE, "outcome native run incomplete")
    need(Path(report["recorded_directory"]).is_absolute() and
         Path(report["recorded_source_root"]).is_absolute(), "recorded outcome directory")
    builder, cases = modules()
    expected_sources = sources()
    need(report.get("sources") == expected_sources, "current outcome test source changed")
    for name, value in expected_sources.items():
        need(file_pin(folder / "sources" / name) == value, "retained outcome test source differs")
    manifest = Path(native_manifest or report["native"]["manifest_path"]).resolve(strict=True)
    admitted = native_binding(manifest, builder)
    # Recorded paths identify the actual invocation. Relocated evidence still
    # requires the explicit current manifest and identical complete build bytes.
    need(report["native"]["manifest"] == admitted["manifest"] and
         report["native"]["build_evidence"] == admitted["build_evidence"] and
         Path(report["native"]["manifest_path"]).is_absolute(), "current outcome native build differs")
    need(report.get("files") == {name: file_pin(folder / name) for name in artifact_names()},
         "complete native corpus artifact inventory")
    execution = report["execution"]
    need(type(execution.get("pid")) is int and execution["pid"] > 0 and
         type(execution.get("started_unix_ns")) is int and
         type(execution.get("finished_unix_ns")) is int and
         execution["started_unix_ns"] <= execution["finished_unix_ns"], "native run interval")
    specifications = cases.specifications()
    baselines = {}
    available = report["files"]["responses.bin"]["size"]
    with regular(folder / "requests.bin") as requests, regular(folder / "responses.bin") as responses, \
         regular(folder / "entries.jsonl") as rows, regular(folder / "buffers.bin") as buffers:
        for index, case in enumerate(specifications):
            wire = cases.frame(**case["fields"])
            request_offset = requests.tell()
            need(exact(requests, 8) == struct.pack("<Q", len(wire)) and
                 exact(requests, len(wire)) == wire, "registered semantic input changed: " + case["name"])
            response_offset, body = response(responses, cases, available)
            operation_envelope(wire, body, cases)
            outcap = capacity(wire)
            arrays, buffer_offset, buffer_size = get_arrays(buffers, array_sizes(wire, outcap, 128))
            row = line(rows)
            verify_entry(row["invocation"], arrays, wire, outcap, 128, 0xb8, report["native"],
                         pid=execution["pid"], sequence=index + 1, returned=40, body=body, outer=execution)
            expected = row_for(index, case["name"], case["group"], case["fields"].get("op", 1),
                               request_offset, response_offset, buffer_offset, buffer_size, row["invocation"])
            need(row == expected, "actual semantic entry inventory differs")
            if case["name"] in BASELINES:
                baselines[case["name"]] = {"wire": wire, "body": body}
        need(requests.read(1) == responses.read(1) == rows.read(1) == buffers.read(1) == b"",
             "extra native semantic evidence")
    need(set(baselines) == set(BASELINES), "transport baseline semantic coverage")
    recipes = controls(cases, baselines)
    with regular(folder / "controls/entries.jsonl") as rows, regular(folder / "controls/buffers.bin") as buffers:
        for index, recipe in enumerate(recipes):
            wire, outcap, workcap = recipe["wire"], recipe["output_capacity"], recipe["workspace_capacity"]
            arrays, buffer_offset, buffer_size = get_arrays(buffers, array_sizes(wire, outcap, workcap))
            row = line(rows)
            verify_entry(row["invocation"], arrays, wire, outcap, workcap, recipe["workspace_fill"],
                         report["native"], pid=execution["pid"],
                         sequence=len(specifications) + index + 1,
                         returned=recipe["returned"], body=recipe["body"], outer=execution)
            need(row == {"index": index, "name": recipe["name"], "buffers_offset": buffer_offset,
                         "buffers_bytes": buffer_size, "invocation": row["invocation"]},
                 "registered transport control differs")
        need(rows.read(1) == buffers.read(1) == b"", "extra transport control entries")
    read_allocation(folder, report, cases)
    counts = expected_counts(cases, specifications, recipes)
    need(report.get("counts") == counts and report.get("control_names") ==
         [row["name"] for row in recipes] + ["allocator-address-space-pressure"],
         "exact native semantic/control counts")
    need(sources() == expected_sources, "outcome reader source changed during validation")
    return {"schema": "hepta.runtime.shell-outcome-native-evidence.v1", "status": "PASS",
            "report_sha256": digest(report_raw), "recorded_directory": report["recorded_directory"],
            "counts": counts, "controls": report["control_names"],
            "guards": {"complete_guarded_buffer_snapshots": counts["complete_guarded_buffer_snapshots"],
                       "inputs_unchanged": counts["actual_native_entries"],
                       "guarded_boundaries_verified": counts["actual_native_entries"],
                       "refusal_outputs_unchanged": counts["invalid_frame_refusals"] + counts["private_capacity_refusals"],
                       "success_tails_unchanged": counts["semantic_cases"] + counts["positive_transport_controls"]},
            "sources": expected_sources, "native": report["native"], "files": report["files"],
            "current_source_bytes_verified": True, **SCOPE}


def run(manifest, output):
    builder, cases = modules()
    manifest = Path(manifest).resolve(strict=True)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "controls").mkdir()
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None, "scope": SCOPE,
              "recorded_directory": str(output), "recorded_source_root": str(ROOT),
              "sources": sources(), "native": native_binding(manifest, builder),
              "execution": {"pid": os.getpid(), "started_unix_ns": time.time_ns()}}
    def publish():
        temporary = output / "report.next.json"
        save_json(temporary, report)
        os.replace(temporary, output / "report.json")
    publish()
    try:
        for name in report["sources"]:
            save(output / "sources" / name, read(ROOT / name))
        specifications = cases.specifications()
        baselines = {}
        with builder.NativeOutcome(manifest, source_root=ROOT) as module:
            with (output / "requests.bin").open("xb") as requests, (output / "responses.bin").open("xb") as responses, \
                 (output / "entries.jsonl").open("xb") as rows, (output / "buffers.bin").open("xb") as buffers:
                for index, case in enumerate(specifications):
                    wire = cases.frame(**case["fields"])
                    request_offset, response_offset = requests.tell(), responses.tell()
                    requests.write(struct.pack("<Q", len(wire)) + wire)
                    value = module.call(wire, capacity(wire))
                    need(value["entry"]["returned"] == 40 and value["body"] is not None,
                         "semantic native entry refused: " + case["name"])
                    operation_envelope(wire, value["body"], cases)
                    responses.write(struct.pack("<QQ", 40, len(value["body"])) + value["body"])
                    buffer_offset, buffer_size = put_arrays(buffers, value["arrays"])
                    row = row_for(index, case["name"], case["group"], case["fields"].get("op", 1),
                                  request_offset, response_offset, buffer_offset, buffer_size, value["entry"])
                    rows.write((canonical(row) + "\n").encode())
                    if case["name"] in BASELINES:
                        baselines[case["name"]] = {"wire": wire, "body": value["body"]}
            recipes = controls(cases, baselines)
            with (output / "controls/entries.jsonl").open("xb") as rows, \
                 (output / "controls/buffers.bin").open("xb") as buffers:
                for index, recipe in enumerate(recipes):
                    value = module.call(recipe["wire"], recipe["output_capacity"],
                                        recipe["workspace_capacity"],
                                        workspace_fill=recipe["workspace_fill"])
                    need(value["entry"]["returned"] == recipe["returned"] and value["body"] == recipe["body"],
                         "native transport control differs: " + recipe["name"])
                    buffer_offset, buffer_size = put_arrays(buffers, value["arrays"])
                    rows.write((canonical({"index": index, "name": recipe["name"],
                                            "buffers_offset": buffer_offset, "buffers_bytes": buffer_size,
                                            "invocation": value["entry"]}) + "\n").encode())
        report["allocation_process"] = run_allocation(output, manifest)
        report["counts"] = expected_counts(cases, specifications, recipes)
        report["control_names"] = [row["name"] for row in recipes] + ["allocator-address-space-pressure"]
        report["files"] = {name: file_pin(output / name) for name in artifact_names()}
        need(sources() == report["sources"] and native_binding(manifest, builder) == report["native"],
             "outcome source/native image changed during execution")
        report["execution"]["finished_unix_ns"] = time.time_ns()
        report["status"] = "PASS"
    except Exception as error:
        report["execution"]["finished_unix_ns"] = time.time_ns()
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
    publish()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(output, native_manifest=manifest)
            save_json(output / "evidence.json", evidence)
        except Exception as error:
            report["status"] = "FAIL"
            report["error"] = "retained native evidence: " + type(error).__name__ + ": " + str(error)
            publish()
    return report


def audit_read_only():
    def audit(event, args):
        need(event not in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
                           "os.exec", "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function"),
             "read-only evidence attempted execution: " + event)
        if event == "open" and args and isinstance(args[0], (str, bytes)):
            path = os.fsdecode(args[0])
            need(not path.startswith("/proc/"), "read-only evidence attempted process inspection")
    sys.addaudithook(audit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--audit-read-only", action="store_true")
    parser.add_argument("--allocation-worker", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.audit_read_only:
            audit_read_only()
        print(canonical(read_evidence(args.verify, native_manifest=args.native_manifest)))
        return 0
    need(args.native_manifest is not None, "--native-manifest required")
    if args.allocation_worker:
        allocation_worker(args.native_manifest.resolve(), args.allocation_worker.resolve())
        return 0
    need(args.output is not None and not args.audit_read_only, "--output required for native execution")
    report = run(args.native_manifest, args.output)
    print(canonical({"status": report["status"], "error": report["error"],
                     "report": str(Path(args.output).resolve() / "report.json"),
                     "counts": report.get("counts"), "whole_runtime_replaced": False}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
