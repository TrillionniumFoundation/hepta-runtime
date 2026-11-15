#!/usr/bin/env python3
"""Compare the HIA blocking capture-file leaf with fresh, actually traced Rust calls.

The original executable calls the linked Rust standard library. Python prepares
owned fixtures and reads complete traces; it never substitutes an expected
errno, fabricated descriptor, or synthetic original call for an execution.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_file_qualification.py"
REFERENCE = "scripts/hia_native_shell_capture_file_reference.py"
HELPERS = "scripts/hia_native_shell_process_reference.py"
NATIVE = "tests/hia_native/shell_capture_file_io.py"
TRACE_SYNTAX = "scripts/hia_native_shell_capture_mkdir_qualification.py"
SOURCES = (DRIVER, REFERENCE, HELPERS, NATIVE, TRACE_SYNTAX)
SCHEMA = "hepta.runtime.shell-capture-file-original-comparison.v1"
TIMEOUT = 30
BEGIN, END = b"HSHCFRUST-BEGIN\n", b"HSHCFRUST-END\n"
TRACE_ARGUMENTS = ("-ff", "-xx", "-v", "-X", "verbose",
                   "-e", "trace=execve,execveat,open,openat,openat2,unlink,unlinkat,close,close_range,dup,dup2,dup3,fcntl,newfstatat,statx,write")
CASE_FILES = ("spec.json", "input.bin", "stdout.bin", "stderr.bin", "before.json",
              "after.json", "execution.json", "retirement.json")
SCOPE = {
    "original_blocking_file_compared": True,
    "original_tests": 0,
    "all_syscall_path_strings_unabridged": False,
    "complete_caller_input_retained": True,
    "native_phase_cases_added_by_reference": 0,
    "tokio_async_cancellation_qualified": False,
    "glibc_thread_cancellation_qualified": False,
    "native_invalid_lifecycle_replayed_as_rust": False,
    "transferred_receiver_cleanup": "kernel process termination, not an HIA or Rust semantic DROP",
    "distinct_process_fd_numbers_equated": False,
    "capture_preparation_qualified": False,
    "registry_publication_qualified": False,
    "production_activated": False,
    "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False,
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    need(specification is not None and specification.loader is not None, "reader module unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def modules(runtime):
    sys.path.insert(0, str(runtime / "scripts"))
    native = load("file_comparison_native", runtime / NATIVE)
    reference = load("file_comparison_reference", runtime / REFERENCE)
    helper = load("file_comparison_process_helpers", runtime / HELPERS)
    need(native.ordinary(runtime / DRIVER) == native.ordinary(Path(__file__)),
         "executing comparison source differs from current source")
    return native, reference, helper


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def exact(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def source_pins(runtime, native):
    return {name: pin(native.ordinary(runtime / name)) for name in SOURCES}


def environment(output):
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(output / "temporary")}


# Retain and bind the complete previously reviewed strict trace grammar.
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_shell_capture_mkdir_qualification import words, c_bytes, integer, directory_fd, record, path_key


def parse_trace(raw, executable, env, original_path, stdout, stderr):
    text = raw.decode("ascii")
    need(text.endswith("\n") and "\r" not in text and "\0" not in text, "trace complete ASCII framing")
    lines = text.splitlines()
    need(lines and lines[-1] == "+++ exited with 0 +++", "tracee did not exit normally")
    events = [record(line) for line in lines[:-1]]
    need(sum(event[0] in ("execve", "execveat") for event in events) == 1,
         "original executable changed during the traced process")
    name, argv, returned, error = events[0]
    need(name == "execve" and len(argv) == 3 and returned == error == 0, "actual original execve")
    need(c_bytes(argv[0]) == os.fsencode(executable), "actual original executable path")
    need([c_bytes(item) for item in words(argv[1], "[", "]")] == [os.fsencode(executable)],
         "actual original argument vector")
    expected_env = [os.fsencode(key + "=" + value) for key, value in env.items()]
    exact([c_bytes(item).hex() for item in words(argv[2], "[", "]")],
          [item.hex() for item in expected_env], "actual original environment vector")
    markers, writes = [], []
    written = {1: bytearray(), 2: bytearray()}
    for index, (name, args, returned, error) in enumerate(events):
        if name != "write":
            continue
        need(len(args) == 3 and integer(args[0]) in written, "unexpected original output descriptor")
        fd, data = integer(args[0]), c_bytes(args[1])
        need(integer(args[2]) == len(data) == returned and error == 0, "incomplete original traced write")
        written[fd].extend(data); writes.append((index, fd))
        if fd == 2 and data in (BEGIN, END):
            markers.append((index, data))
    need(bytes(written[1]) == stdout and bytes(written[2]) == stderr,
         "traced original writes differ from complete captured process streams")
    need(len(markers) == 2 and [data for _, data in markers] == [BEGIN, END], "std-call marker order/count")
    first, last = (index for index, _ in markers)
    need(all(index > last for index, fd in writes if fd == 1), "original response preceded completed file operation")
    # A dynamically linked original needs real read-only loader opens before
    # main. They are retained but are not mislabeled as File::create effects.
    for name, args, returned, error in events[1:first]:
        need(name in ("open", "openat", "newfstatat", "statx", "close", "fcntl"),
             "unregistered original effect before the blocking file call")
        if name in ("open", "openat"):
            offset = int(name == "openat")
            need(len(args) in (2 + offset, 3 + offset), "pre-call loader open framing")
            c_bytes(args[offset])
            flags = integer(args[offset + 1])
            need(flags & 3 == 0 and flags & (0x40 | 0x200) == 0,
                 "original created or opened a writable file before the blocking call")
    operations = []
    for name, args, returned, error in events[first + 1:last]:
        fd, dirfd, flags, mode = None, None, 0, 0
        if name == "openat":
            need(len(args) == 4 and directory_fd(args[0]) == -100
                 and integer(args[2]) == 0x80241 and integer(args[3]) == 0o666,
                 "actual original openat flags/mode/dirfd")
            need((error == 0 and 0 <= returned <= 0x7fffffff) or returned == -error,
                 "original openat raw return domain")
            action, syscall, path_text = 1, 257, args[1]
            dirfd, flags, mode = -100, integer(args[2]), integer(args[3])
        elif name == "unlink":
            need(len(args) == 1 and returned == -error, "actual original unlink arguments/result")
            action, syscall, path_text = 2, 87, args[0]
        elif name == "close":
            need(len(args) == 1 and 0 <= integer(args[0]) <= 0x7fffffff and returned == -error,
                 "actual original close arguments/result")
            action, syscall, path_text, fd = 3, 3, None, integer(args[0])
        else:
            raise ValueError("unregistered effect inside the actual standard-library file call: " + name)
        shortened = path_text is not None and path_text.endswith('"...')
        if shortened:
            displayed = c_bytes(path_text[:-3])
            # The complete caller input remains independent of this explicitly
            # shortened strace path display. Undisplayed bytes are not observed.
            need(action == 1 and error == 36 and returned == -36
                 and last - first == 2 and not operations
                 and len(displayed) == 4095 and len(original_path) == 4100
                 and b"\0" not in original_path and displayed == original_path[:4095],
                 "unqualified shortened syscall path display")
            path = original_path
        else:
            path = b"" if path_text is None else c_bytes(path_text)
            displayed = path
        operations.append(dict(action=action, syscall=syscall, path=path, errno=error, raw=returned,
                               dirfd=dirfd, flags=flags, mode=mode, fd=fd,
                               displayed_path=displayed, path_display_shortened=shortened))
    need(all(event[0] == "write" for event in events[last + 1:]),
         "additional original file/descriptor call after the completed operation")
    return operations, dict(syscalls=len(operations), total_traced_syscalls=len(events),
                            openat=sum(row["action"] == 1 for row in operations),
                            unlink=sum(row["action"] == 2 for row in operations),
                            close=sum(row["action"] == 3 for row in operations),
                            fcntl_inside_original_file_call=0,
                            shortened_path_displays=sum(row["path_display_shortened"] for row in operations))

def native_result(raw):
    need(len(raw) == 48 and raw[:8] == b"HSHCFR01", "complete native file result")
    extent, operation, kind, error, token = struct.unpack_from("<5Q", raw, 8)
    need(extent == 48 and operation in (1, 2, 3, 4) and kind in (0, 1, 2)
         and ((kind == 1 and 1 <= error <= 4095) or (kind != 1 and error == 0)),
         "native file result domain")
    return dict(operation=operation, kind=kind, error=error, token=token)


def original_plan(spec, native_case, native):
    exact(native_case["spec"], spec, "native paired file specification")
    wires, results = native_case["requests"], native_case["results"]
    need(len(wires) == len(results) == 1 + len(spec["lifecycle"]), "native request inventory")
    ret, raw = results[0]
    need(ret == 48, "native initial original operation did not publish")
    first = native_result(raw)
    need(first["operation"] == spec["operation"] in (1, 2), "initial original operation")
    lifecycle, replayed, refused = [], [], []
    for index, (wire, (returned, body)) in enumerate(zip(wires[1:], results[1:]), 2):
        op, kind = struct.unpack_from("<2Q", wire, 8)
        if returned == native.INVALID:
            need(body == b"", "native refusal unexpectedly has a body")
            refused.append(index)
        else:
            need(returned == 48, "unqualified native lifecycle return")
            row = native_result(body)
            need(row["operation"] == kind, "native lifecycle operation mismatch")
            if op == 2:
                replayed.append(index)
            else:
                need(op == 1 and kind in (3, 4) and row["kind"] == row["error"] == 0,
                     "unregistered successful lifecycle operation")
                lifecycle.append((index, kind, row["token"]))
    disposition, applied, lifecycle_index = (1 if spec["operation"] == 1 else 0), 0, None
    if spec["operation"] == 1 and first["kind"] == 0:
        need(first["token"] > 0 and len(lifecycle) == 1, "successful original file custody plan")
        lifecycle_index, kind, token = lifecycle[0]
        disposition = applied = 1 if kind == 3 else 2
        need(token == (0 if kind == 3 else first["token"]), "native held capability transfer")
    else:
        need(not lifecycle and first["token"] == 0, "failed/unlink file has an owned lifecycle")
    return dict(disposition=disposition, applied_disposition=applied,
                lifecycle_request=lifecycle_index, native_initial=first,
                native_request_count=len(wires), native_replayed_requests=replayed,
                native_refused_requests=refused)


def input_for(spec, work, plan, native):
    path = native.path_for(spec, work)
    return b"HSHCFRQ1" + struct.pack("<7Q", 1, spec["operation"], len(path), plan["disposition"], 0, 0, 0) + path


def logical_tree(native, rows):
    native.check_tree(rows)
    keys = ("path_hex", "kind", "mode", "uid", "gid", "nlink", "payload_hex", "target_hex")
    return [{key: row[key] for key in keys if key in row} for row in rows]


def verify_original_outcome(spec, path, plan, operations, result):
    absent = (1 << 64) - 1
    expected = dict(operation=spec["operation"], kind=0, error=0, applied_disposition=0, actual_fd=absent)
    if b"\0" in path:
        need(not operations, "local original NUL error issued a filesystem call")
        expected["kind"] = 2
    elif spec["operation"] == 2:
        need(len(operations) == 1 and operations[0]["action"] == 2, "original unlink is not single-shot")
        if operations[0]["errno"]:
            expected.update(kind=1, error=operations[0]["errno"])
    else:
        need(operations, "original create has no actual open")
        final = None
        cursor = 0
        while cursor < len(operations):
            row = operations[cursor]
            need(row["action"] == 1, "original create issued a non-open before completion")
            cursor += 1
            if row["errno"] != 4:
                final = row
                break
        need(final is not None, "original open retry did not complete")
        if final["errno"]:
            expected.update(kind=1, error=final["errno"])
        else:
            need(0 <= final["raw"] <= 0x7fffffff, "original successful descriptor domain")
            expected.update(actual_fd=final["raw"], applied_disposition=plan["disposition"])
            if plan["disposition"] == 1:
                need(cursor < len(operations) and operations[cursor]["action"] == 3
                     and operations[cursor]["fd"] == final["raw"], "original drop did not close its owned descriptor")
                cursor += 1
        need(cursor == len(operations), "unrequested original file effect or repeated owned close")
    exact(result, expected, "original complete response differs from actual standard-library effects")
    first = plan["native_initial"]
    exact({key: result[key] for key in ("operation", "kind", "error")},
          {key: first[key] for key in ("operation", "kind", "error")},
          "original/native operation, result or errno differs")
    need(result["applied_disposition"] == plan["applied_disposition"], "original/native custody disposition differs")


def compare_operations(spec, original, native_case, work, native_work, original_result):
    observed = native_case["operations"]
    need(len(original) == len(observed), "original/native syscall count differs")
    native_fd, original_fd = None, None
    for index, (left, right) in enumerate(zip(original, observed)):
        need(left["action"] == right["action"] and left["syscall"] == right["syscall"]
             and left["errno"] == right["errno"], "original/native actual syscall identity or errno differs: " + str(index))
        raw = right["raw"] if right["raw"] < 1 << 63 else right["raw"] - (1 << 64)
        if left["action"] == 1:
            need(left["dirfd"] == -100 and right["actual_fd"] == (1 << 64) - 100
                 and left["flags"] == right["args"][2] == 0x80241
                 and left["mode"] == right["args"][3] == 0o666, "original/native open flags, mode or dirfd differs")
            if left["errno"] == 0:
                need(original_fd is None and native_fd is None and 0 <= raw <= 0x7fffffff,
                     "multiple or invalid successful original/native descriptor")
                original_fd, native_fd = left["raw"], raw
            else:
                need(left["raw"] == raw, "original/native raw open error differs")
        else:
            need(left["raw"] == raw, "original/native actual raw syscall result differs")
            if left["action"] == 3:
                need(left["fd"] == original_fd and right["actual_fd"] == native_fd,
                     "original/native close did not consume corresponding owned descriptors")
        native_path = bytes.fromhex(right["path_hex"])
        need(path_key(left["path"], work, spec["absolute_under_work"]) ==
             path_key(native_path, native_work, spec["absolute_under_work"]),
             "original/native actual syscall path differs: " + str(index))
    if original_fd is not None:
        need(original_fd == original_result["actual_fd"], "original reported descriptor differs from successful open")
    return dict(original_fd=original_fd, native_fd=native_fd,
                raw_descriptor_numbers_required_equal=False,
                mapping_basis="each process's actual successful open and matching owned close/retained transfer")

def trace_command(tracer, executable, folder, wire):
    # strace 6.19 interprets -s 0 as zero displayed string bytes. Derive a
    # complete bound from this actual request/argv/environment instead.
    strings = [wire[64:], os.fsencode(executable), BEGIN, END, bytes(48)]
    strings.extend(os.fsencode(key + "=" + value) for key, value in environment(folder.parent.parent).items())
    extent = max(len(value) for value in strings) + 1
    return [str(tracer), *TRACE_ARGUMENTS, "-s", str(extent),
            "-o", str(folder / "syscall.trace"), "--", str(executable)]


def decoded_result(raw):
    need(len(raw) == 48 and raw[:8] == b"HSHCFO01", "complete original file response framing")
    operation, kind, error, disposition, fd = struct.unpack_from("<5Q", raw, 8)
    need(operation in (1, 2) and kind in (0, 1, 2)
         and ((kind == 1 and 1 <= error <= 4095) or (kind != 1 and error == 0)), "original file error domain")
    if operation == 1 and kind == 0:
        need(disposition in (1, 2) and 0 <= fd <= 0x7fffffff, "original successful file ownership domain")
    else:
        need(disposition == 0 and fd == (1 << 64) - 1, "original absent file ownership domain")
    return dict(operation=operation, kind=kind, error=error, applied_disposition=disposition, actual_fd=fd)

def read_case(folder, spec, native_case, native, helper, build, tracer_identity,
              build_finished, *, retired=True):
    folder = Path(folder).absolute()
    native.plain_dir(folder)
    receipt = native.read_json(folder / "execution.json")
    trace_name = receipt.get("trace_file")
    need(type(trace_name) is str and re.fullmatch(r"syscall\.trace\.[1-9][0-9]*", trace_name), "actual trace filename")
    expected_files = set(CASE_FILES) | {trace_name}
    if not retired:
        expected_files.remove("retirement.json"); expected_files.add("work")
    need(set(os.listdir(folder)) == expected_files, "original case retained member inventory")
    exact(native.read_json(folder / "spec.json"), spec, "registered original file case changed")
    need(folder.name == spec["name"] and spec["original_file_operation"] is True,
         "original file operation case domain")
    work = folder / "work"
    plan = original_plan(spec, native_case, native)
    wire = input_for(spec, work, plan, native)
    need(native.ordinary(folder / "input.bin") == wire, "complete actual original input differs")
    before, after = (native.read_json(folder / leaf) for leaf in ("before.json", "after.json"))
    stdout, stderr, trace = (native.ordinary(folder / leaf) for leaf in ("stdout.bin", "stderr.bin", trace_name))
    executable = build["executable"]["launch_path"]
    env = environment(folder.parent.parent)
    expected = {"schema": "hepta.runtime.shell-capture-file-original-execution.v1",
                "case": spec["name"], "case_directory": str(folder), "cwd": str(work),
                "command": trace_command(tracer_identity["launch_path"], executable, folder, wire),
                "environment": env, "umask": spec["umask"], "deadline_seconds": TIMEOUT,
                "original_executable_before": build["executable"], "original_executable_after": build["executable"],
                "tracer_before": tracer_identity, "tracer_after": tracer_identity,
                "stdin": pin(wire), "stdout": pin(stdout), "stderr": pin(stderr), "trace": pin(trace),
                "trace_files_observed": [trace_name], "exit_code": 0, "timed_out": False, "error": None}
    for key, value in expected.items():
        exact(receipt.get(key), value, "original process binding differs: " + key)
    need(stderr == BEGIN + END, "complete original std-call markers")
    target_pid = int(trace_name.rsplit(".", 1)[1])
    need(type(receipt.get("tracer_pid")) is int and receipt["tracer_pid"] > 1
         and type(receipt.get("target_pid")) is int and receipt["target_pid"] == target_pid
         and target_pid > 1 and target_pid != receipt["tracer_pid"]
         and type(receipt.get("producer_pid")) is int and receipt["producer_pid"] > 1,
         "actual tracer/tracee process identities")
    start, finish = receipt.get("started_ns"), receipt.get("finished_ns")
    need(type(start) is int and type(finish) is int and 0 < start <= finish
         and type(receipt.get("duration_ns")) is int and receipt["duration_ns"] == finish - start
         and finish - start <= TIMEOUT * 1_000_000_000, "actual original process timing")
    need(type(receipt.get("started_unix_ns")) is int and type(receipt.get("finished_unix_ns")) is int
         and build_finished <= receipt["started_unix_ns"] <= receipt["finished_unix_ns"],
         "original call predates the fresh reference build")
    need(type(receipt.get("uid")) is int and type(receipt.get("gid")) is int
         and (receipt["uid"], receipt["gid"]) == (before[0]["uid"], before[0]["gid"]),
         "actual original fixture account")
    need(receipt["uid"] != 0, "original file corpus requires the actual unprivileged account")
    operations, counts = parse_trace(trace, executable, env, native.path_for(spec, work), stdout, stderr)
    need(counts["shortened_path_displays"] == int(spec["name"] == "path_too_long"),
         "registered original path display coverage differs")
    result = decoded_result(stdout)
    verify_original_outcome(spec, native.path_for(spec, work), plan, operations, result)
    native_root = Path(receipt["native_case_directory"]) / "work"
    custody = compare_operations(spec, operations, native_case, work, native_root, result)
    native.verify_trees(spec, before, after, [after], receipt)
    exact(logical_tree(native, before), logical_tree(native, native_case["before"]),
          "original/native initial logical tree differs")
    exact(logical_tree(native, after), logical_tree(native, native_case["after"]),
          "original/native final logical tree differs")
    validation = {"schema": "hepta.runtime.shell-capture-file-original-case.v1", "status": "PASS",
                  "name": spec["name"], "result": result, "original_plan": plan,
                  "filesystem": {"initial_entries": len(before), "final_entries": len(after)},
                  "trace_counts": counts, "descriptor_correspondence": custody,
                  "trace_file": trace_name, "trace": pin(trace), "target_pid": target_pid,
                  "tracer_pid": receipt["tracer_pid"], "complete_input": pin(wire),
                  "complete_response": pin(stdout),
                  "complete_native_responses": [{"return_value": ret, **pin(body)} for ret, body in native_case["results"]],
                  "absolute_owned_prefix_mapping": spec["absolute_under_work"],
                  "syscall_path_displays": [{"complete_caller_path_hex": row["path"].hex(),
                      "displayed_path_hex": row["displayed_path"].hex(),
                      "complete_path_displayed": not row["path_display_shortened"]} for row in operations],
                  "native_case_directory": receipt["native_case_directory"], **SCOPE}
    if retired:
        native.verify_retirement(folder, after)
    else:
        exact(native.tree_snapshot(work), after, "original tree changed before retirement")
    return validation

def run_case(folder, spec, native_case, native_case_directory, native, helper, build,
             tracer_identity, build_finished):
    folder.mkdir(mode=0o700)
    work = folder / "work"
    native.setup_case(work, spec)
    before = native.tree_snapshot(work)
    plan = original_plan(spec, native_case, native)
    wire = input_for(spec, work, plan, native)
    for leaf, data in (("spec.json", encoded(spec)), ("input.bin", wire), ("before.json", encoded(before))):
        native.write_new(folder / leaf, data)
    executable = build["executable"]["launch_path"]
    command = trace_command(tracer_identity["launch_path"], executable, folder, wire)
    env = environment(folder.parent.parent)
    start, unix = time.monotonic_ns(), time.time_ns()
    process, stdout, stderr, timed_out, error = None, b"", b"", False, None
    original_before = helper.tool_identity(Path(executable))
    tracer_before = helper.tool_identity(Path(tracer_identity["launch_path"]))
    try:
        process = subprocess.Popen(command, cwd=work, env=env, umask=spec["umask"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        stdout, stderr = process.communicate(wire, timeout=TIMEOUT)
    except BaseException as failure:
        timed_out = isinstance(failure, subprocess.TimeoutExpired)
        error = type(failure).__name__ + ": " + str(failure)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
    finished, finished_unix = time.monotonic_ns(), time.time_ns()
    after = native.tree_snapshot(work)
    traces = sorted(path.name for path in folder.iterdir() if path.name.startswith("syscall.trace."))
    trace_name = traces[0] if len(traces) == 1 else None
    trace = native.ordinary(folder / trace_name) if trace_name else b""
    target = int(trace_name.rsplit(".", 1)[1]) if trace_name and trace_name.rsplit(".", 1)[1].isdigit() else None
    receipt = {"schema": "hepta.runtime.shell-capture-file-original-execution.v1", "case": spec["name"],
               "case_directory": str(folder), "native_case_directory": str(native_case_directory),
               "command": command, "cwd": str(work), "environment": env, "umask": spec["umask"],
               "uid": os.geteuid(), "gid": os.getegid(), "producer_pid": os.getpid(),
               "tracer_pid": process.pid if process else None, "target_pid": target,
               "trace_file": trace_name, "trace_files_observed": traces,
               "started_ns": start, "finished_ns": finished, "duration_ns": finished - start,
               "started_unix_ns": unix, "finished_unix_ns": finished_unix, "deadline_seconds": TIMEOUT,
               "exit_code": process.returncode if process else None, "timed_out": timed_out, "error": error,
               "original_executable_before": original_before, "original_executable_after": helper.tool_identity(Path(executable)),
               "tracer_before": tracer_before, "tracer_after": helper.tool_identity(Path(tracer_identity["launch_path"])),
               "stdin": pin(wire), "stdout": pin(stdout), "stderr": pin(stderr), "trace": pin(trace)}
    for leaf, data in (("stdout.bin", stdout), ("stderr.bin", stderr), ("after.json", encoded(after)),
                       ("execution.json", encoded(receipt))):
        native.write_new(folder / leaf, data)
    try:
        checked = read_case(folder, spec, native_case, native, helper, build, tracer_identity, build_finished, retired=False)
    except BaseException as failure:
        failed = {"status": "FAIL", "type": type(failure).__name__, "message": str(failure)}
        native.write_new(folder / "failure.json", encoded(failed))
        native.write_new(folder / "retirement.json", native.packed(native.retire(work, after)))
        raise
    native.write_new(folder / "retirement.json", native.packed(native.retire(work, after)))
    return read_case(folder, spec, native_case, native, helper, build, tracer_identity, build_finished)

def admitted(runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker):
    build = reference.read_evidence(runtime, reference_build, rustc, linker)
    need(build.get("status") == "PASS", "fresh original reference strong reader")
    build_report = helper.decode(helper.read(reference_build, "result.json"))
    finished = max(row["finished_unix_ns"] for row in build_report["processes"])
    original = {"path": str(reference_build), "report": pin(helper.read(reference_build, "result.json")), "evidence": build}
    evidence = native.read_evidence(native_corpus, native_manifest, require_full=True)
    need(evidence.get("status") == "PASS" and evidence["counts"]["cases"] == 34
         and evidence["counts"]["retired_fixtures"] == 34
         and evidence["physical_controls"]["physical_negative_controls"] == 15,
         "complete native file corpus/retirement/control admission")
    baseline = {"path": str(native_corpus), "manifest": {"path": str(native_manifest), **pin(native.ordinary(native_manifest))},
                "report": pin(native.ordinary(native_corpus / "report.json")), "evidence": evidence}
    specifications = [spec for spec in native.case_specs() if spec["original_file_operation"]]
    need(len(specifications) == 32 and all(spec["operation"] in (1, 2) for spec in specifications),
         "complete original file case inventory")
    return build, finished, original, baseline, specifications

def retained_inventory(output, specifications, native):
    names = ["source-snapshots/" + name for name in SOURCES]
    for spec in specifications:
        folder = output / "cases" / spec["name"]
        trace = native.read_json(folder / "execution.json")["trace_file"]
        need(type(trace) is str and re.fullmatch(r"syscall\.trace\.[1-9][0-9]*", trace), "retained trace path")
        names.extend("cases/" + spec["name"] + "/" + leaf for leaf in (*CASE_FILES, trace))
    names.extend(("strace-version.stdout", "strace-version.stderr", "strace-version.execution.json"))
    return {name: pin(native.ordinary(output / name)) for name in names}


def read_evidence(runtime, reference_build, native_corpus, native_manifest, output,
                  rustc=None, linker=None, tracer=Path("/usr/bin/strace")):
    runtime, reference_build, native_corpus, native_manifest, output = (
        Path(value).absolute() for value in (runtime, reference_build, native_corpus, native_manifest, output))
    native, reference, helper = modules(runtime)
    report = native.read_json(output / "result.json")
    need(report.get("schema") == SCHEMA and report.get("status") == "PASS" and report.get("error") is None,
         "original file comparison incomplete")
    need(report.get("recorded_directory") == str(output) and report.get("runtime") == str(runtime), "comparison recorded paths")
    exact(report.get("scope"), SCOPE, "comparison scope changed")
    sources = source_pins(runtime, native)
    exact(report.get("sources"), sources, "comparison current source changed")
    for name in SOURCES:
        need(helper.read(output, "source-snapshots/" + name) == helper.read(runtime, name), "comparison complete source snapshot")
    build, finished, original, baseline, specifications = admitted(
        runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker)
    exact(report.get("reference_build"), original, "original build binding changed")
    exact(report.get("native_corpus"), baseline, "native corpus binding changed")
    identity = helper.tool_identity(tracer)
    exact(report.get("tracer"), identity, "actual tracing tool changed")
    version = report.get("tracer_version")
    helper.completed_process(output, "strace-version", version, [identity["launch_path"], "--version"], output, TIMEOUT)
    need(helper.read(output, "strace-version.stderr") == b"" and
         helper.read(output, "strace-version.stdout").startswith(b"strace -- version "), "actual tracing tool version query")
    exact(report.get("execution_environment"), environment(output), "comparison environment changed")
    need(set(os.listdir(output / "cases")) == {spec["name"] for spec in specifications}, "original case directory inventory")
    results = []
    for spec in specifications:
        native_folder = native_corpus / "cases" / spec["name"]
        current = native.read_case(native_folder, native_manifest)
        receipt = native.read_json(output / "cases" / spec["name"] / "execution.json")
        need(receipt.get("native_case_directory") == str(native_folder), "original comparison bound to a different native case")
        results.append(read_case(output / "cases" / spec["name"], spec, current, native, helper, build, identity, finished))
    exact(report.get("cases"), results, "original complete case results changed")
    exact(report.get("files"), retained_inventory(output, specifications, native), "original complete retained bytes changed")
    need(len({row["target_pid"] for row in results}) == len(results), "original cases reused a process")
    counts = {"paired_real_filesystem_cases": len(results), "actual_original_processes": len(results),
              "actual_tracer_processes": len(results), "actual_tracer_version_queries": 1,
              "retired_original_fixtures": len(results),
              "original_syscalls": sum(row["trace_counts"]["syscalls"] for row in results),
              "original_openat": sum(row["trace_counts"]["openat"] for row in results),
              "original_unlink": sum(row["trace_counts"]["unlink"] for row in results),
              "original_owned_close": sum(row["trace_counts"]["close"] for row in results),
              "original_ownership_transfers": sum(row["result"]["applied_disposition"] == 2 for row in results),
              "shortened_path_displays": sum(row["trace_counts"]["shortened_path_displays"] for row in results),
              "native_fresh_invalid_cases_not_replayed_as_original": 2}
    exact(report.get("counts"), counts, "original comparison counts changed")
    return {"schema": "hepta.runtime.shell-capture-file-original-evidence.v1", "status": "PASS",
            "report_sha256": pin(native.ordinary(output / "result.json"))["sha256"],
            "counts": counts, "fresh_original_build_qualified": True,
            "complete_native_corpus_and_controls_verified": True, **SCOPE}


def run(runtime, reference_build, native_corpus, native_manifest, output,
        rustc=None, linker=None, tracer=Path("/usr/bin/strace")):
    output.mkdir(parents=True, exist_ok=False)
    (output / "cases").mkdir(); (output / "temporary").mkdir()
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None, "recorded_directory": str(output),
              "runtime": str(runtime), "scope": {**SCOPE, "original_blocking_file_compared": False}, "cases": []}
    def save():
        (output / "result.json").write_bytes(encoded(report))
    save()
    try:
        native, reference, helper = modules(runtime)
        report["sources"] = source_pins(runtime, native)
        for name in SOURCES:
            destination = output / "source-snapshots" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            native.write_new(destination, helper.read(runtime, name))
        build, finished, original, baseline, specifications = admitted(
            runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker)
        report.update(reference_build=original, native_corpus=baseline, tracer=helper.tool_identity(tracer),
                      execution_environment=environment(output))
        row = helper.process(output, "strace-version", [report["tracer"]["launch_path"], "--version"],
                             output, report["execution_environment"], TIMEOUT)
        report["tracer_version"] = row; save()
        need(row["passed"], "actual strace version query failed")
        for spec in specifications:
            native_folder = native_corpus / "cases" / spec["name"]
            current = native.read_case(native_folder, native_manifest)
            validation = run_case(output / "cases" / spec["name"], spec, current, native_folder,
                                  native, helper, build, report["tracer"], finished)
            report["cases"].append(validation); save()
            print(json.dumps({"case": spec["name"], "status": "ORIGINAL_PAIR_PASS",
                              "syscalls": validation["trace_counts"]["syscalls"]}, sort_keys=True), flush=True)
        report["files"] = retained_inventory(output, specifications, native)
        report["counts"] = {"paired_real_filesystem_cases": len(report["cases"]),
                            "actual_original_processes": len(report["cases"]),
                            "actual_tracer_processes": len(report["cases"]), "actual_tracer_version_queries": 1,
                            "retired_original_fixtures": len(report["cases"]),
                            "original_syscalls": sum(row["trace_counts"]["syscalls"] for row in report["cases"]),
                            "original_openat": sum(row["trace_counts"]["openat"] for row in report["cases"]),
                            "original_unlink": sum(row["trace_counts"]["unlink"] for row in report["cases"]),
                            "original_owned_close": sum(row["trace_counts"]["close"] for row in report["cases"]),
                            "original_ownership_transfers": sum(row["result"]["applied_disposition"] == 2 for row in report["cases"]),
                            "shortened_path_displays": sum(row["trace_counts"]["shortened_path_displays"] for row in report["cases"]),
                            "native_fresh_invalid_cases_not_replayed_as_original": 2}
        exact(source_pins(runtime, native), report["sources"], "comparison sources changed during actual execution")
        report.update(status="PASS", scope=SCOPE); save()
        checked = read_evidence(runtime, reference_build, native_corpus, native_manifest, output, rustc, linker, tracer)
        native.write_new(output / "evidence.json", encoded(checked))
    except BaseException as failure:
        report.update(status="FAIL", error=type(failure).__name__ + ": " + str(failure),
                      scope={**SCOPE, "original_blocking_file_compared": False})
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--native-corpus", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--tracer", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    values = [item.absolute() for item in (args.runtime, args.reference_build, args.native_corpus,
                                         args.native_manifest, args.output)]
    if args.read_only:
        result = read_evidence(*values, args.rustc, args.linker, args.tracer)
    else:
        report = run(*values, args.rustc, args.linker, args.tracer)
        result = {"status": report["status"], "error": report["error"], "report": str(values[-1] / "result.json"),
                  "counts": report.get("counts"), "whole_runtime_replaced": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
