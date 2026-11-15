#!/usr/bin/env python3
"""Compare the HIA blocking mkdir leaf with fresh, actually traced Rust calls.

The original executable calls the linked Rust standard library. Python prepares
owned fixtures and reads complete traces; it never substitutes an expected
errno or a synthetic original statx cache observation for an execution.
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
DRIVER = "scripts/hia_native_shell_capture_mkdir_qualification.py"
REFERENCE = "scripts/hia_native_shell_capture_mkdir_reference.py"
HELPERS = "scripts/hia_native_shell_process_reference.py"
NATIVE = "tests/hia_native/shell_capture_mkdir_io.py"
SOURCES = (DRIVER, REFERENCE, HELPERS, NATIVE)
SCHEMA = "hepta.runtime.shell-capture-mkdir-original-comparison.v1"
TIMEOUT = 30
BEGIN, END = b"HSHMKRUST-BEGIN\n", b"HSHMKRUST-END\n"
TRACE_ARGUMENTS = ("-ff", "-xx", "-v", "-X", "verbose",
                   "-e", "trace=execve,mkdir,statx,newfstatat,write")
CASE_FILES = ("spec.json", "input.bin", "stdout.bin", "stderr.bin", "before.json",
              "after.json", "execution.json", "retirement.json")
SCOPE = {
    "original_blocking_mkdir_compared": True,
    "original_tests": 0,
    "original_statx_cache_word_observed": False,
    "all_syscall_path_strings_unabridged": False,
    "complete_caller_input_retained": True,
    "native_phase_cases_added_by_reference": 0,
    "tokio_async_cancellation_qualified": False,
    "global_statx_atomic_cache_qualified": False,
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
    native = load("mkdir_comparison_native", runtime / NATIVE)
    reference = load("mkdir_comparison_reference", runtime / REFERENCE)
    helper = load("mkdir_comparison_process_helpers", runtime / HELPERS)
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


def words(text, opening, closing):
    """Split strace's C-style argument/structure rendering without evaluation."""
    need(text.startswith(opening) and text.endswith(closing), "trace container framing")
    text = text[len(opening):-len(closing)]
    parts, stack, quoted, escaped, start = [], [], False, False, 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            need(stack and stack.pop() == char, "trace container nesting")
        elif char == "," and not stack:
            parts.append(text[start:index].strip()); start = index + 1
    need(not quoted and not stack and not escaped, "incomplete trace argument")
    if text or start:
        parts.append(text[start:].strip())
    need(all(parts), "empty trace argument")
    return parts


def c_bytes(text):
    need(re.fullmatch(r'"(?:\\x[0-9a-f]{2})*"', text) is not None,
         "trace string is abbreviated or not fully hexadecimal")
    return bytes.fromhex(text[1:-1].replace("\\x", ""))


def integer(text):
    number, separator, comment = text.partition(" /* ")
    if separator:
        need(comment.endswith(" */") and "/*" not in comment and "\n" not in comment,
             "trace numeric annotation framing")
        text = number
    need(re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)", text) is not None, "trace numeric constant")
    sign = -1 if text.startswith("-") else 1
    value = text[1:] if sign < 0 else text
    base = 16 if value.startswith("0x") else 8 if len(value) > 1 and value.startswith("0") else 10
    return sign * int(value, base)


def directory_fd(text):
    value = integer(text)
    if 1 << 31 <= value <= (1 << 32) - 1:
        value -= 1 << 32
    return value


def record(line):
    match = re.fullmatch(r"([a-z][a-z0-9_]*)\((.*)\)\s+=\s+(.*)", line)
    need(match is not None, "noncanonical or incomplete traced syscall")
    name, arguments, result = match.groups()
    arguments = words("(" + arguments + ")", "(", ")")
    if result == "0":
        returned, error = 0, 0
    elif re.fullmatch(r"[1-9][0-9]*", result):
        returned, error = int(result), 0
    else:
        failed = re.fullmatch(r"-1 ([A-Z][A-Z0-9_]+) \([^\r\n]*\)", result)
        need(failed is not None, "trace return is incomplete or unexpected")
        import errno
        error = getattr(errno, failed[1], None)
        need(type(error) is int and 1 <= error <= 4095, "unknown actual errno")
        returned = -error
    return name, arguments, returned, error


def fields(text):
    need("..." not in text, "abbreviated successful metadata")
    result = {}
    for item in words(text, "{", "}"):
        key, separator, value = item.partition("=")
        need(separator and re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", key)
             and key not in result, "metadata field syntax or duplicate")
        result[key] = value
    return result


def metadata(text, action):
    value = fields(text)
    if action == 2:
        required = ("stx_mode", "stx_ino", "stx_dev_major", "stx_dev_minor")
        need(all(key in value for key in required), "incomplete statx metadata identity")
        return {"mode": integer(value["stx_mode"]), "inode": integer(value["stx_ino"]),
                "device": os.makedev(integer(value["stx_dev_major"]), integer(value["stx_dev_minor"]))}
    need(all(key in value for key in ("st_mode", "st_ino", "st_dev")), "incomplete stat64 metadata identity")
    device = value["st_dev"]
    need(device.startswith("makedev("), "stat64 device rendering")
    pair = words(device.removeprefix("makedev"), "(", ")")
    need(len(pair) == 2, "stat64 device arguments")
    return {"mode": integer(value["st_mode"]), "inode": integer(value["st_ino"]),
            "device": os.makedev(*(integer(item) for item in pair))}


def parse_trace(raw, executable, env, original_path, stdout, stderr):
    text = raw.decode("ascii")
    need(text.endswith("\n") and "\r" not in text and "\0" not in text, "trace complete ASCII framing")
    lines = text.splitlines()
    need(lines and lines[-1] == "+++ exited with 0 +++", "tracee did not exit normally")
    events = [record(line) for line in lines[:-1]]
    need(sum(event[0] == "execve" for event in events) == 1, "original executable changed during the traced process")
    name, argv, returned, error = events[0]
    need(name == "execve" and len(argv) == 3 and returned == error == 0, "actual original execve")
    need(c_bytes(argv[0]) == os.fsencode(executable), "actual original executable path")
    need([c_bytes(item) for item in words(argv[1], "[", "]")] == [os.fsencode(executable)],
         "actual original argument vector")
    expected_env = [os.fsencode(key + "=" + value) for key, value in env.items()]
    exact([item.hex() for item in (c_bytes(item) for item in words(argv[2], "[", "]"))],
          [item.hex() for item in expected_env], "actual original environment vector")
    markers = []
    written = {1: bytearray(), 2: bytearray()}
    for index, (name, args, returned, error) in enumerate(events):
        if name == "write":
            need(len(args) == 3 and integer(args[0]) in written, "unexpected original output descriptor")
            data = c_bytes(args[1])
            need(integer(args[2]) == len(data) == returned and error == 0, "incomplete original traced write")
            written[integer(args[0])].extend(data)
        if name == "write" and len(args) == 3 and args[0] == "2":
            data = c_bytes(args[1])
            if data in (BEGIN, END):
                need(integer(args[2]) == returned == len(data) and error == 0, "incomplete std-call marker")
                markers.append((index, data))
    need(bytes(written[1]) == stdout and bytes(written[2]) == stderr,
         "traced original writes differ from complete captured process streams")
    need(len(markers) == 2 and [data for _, data in markers] == [BEGIN, END], "std-call marker order/count")
    first, last = (index for index, _ in markers)
    need(not any(event[0] in ("mkdir", "statx") for event in events[:first]),
         "original filesystem or statx state was touched before the fresh call")
    operations = []
    for name, args, returned, error in events[first + 1:last]:
        need(returned == 0 or returned == -error, "unexpected filesystem return value")
        if name == "mkdir":
            need(len(args) == 2 and integer(args[1]) == 0o777, "actual mkdir arguments")
            action, path_text, meta = 1, args[0], None
        elif name == "statx":
            need(len(args) == 5 and integer(args[2]) == 0 and integer(args[3]) == 4095,
                 "actual statx flags/mask")
            if args[1] == "NULL":
                need(integer(args[0]) == 0 and args[4] == "NULL", "actual NULL availability probe")
                action, path_text, meta = 3, None, None
            else:
                need(directory_fd(args[0]) == -100, "actual statx directory FD")
                action, path_text, meta = 2, args[1], args[4]
        elif name == "newfstatat":
            need(len(args) == 4 and directory_fd(args[0]) == -100 and integer(args[3]) == 0,
                 "actual newfstatat directory FD/flags")
            action, path_text, meta = 4, args[1], args[2]
        else:
            raise ValueError("unregistered effect inside the actual standard-library call: " + name)
        shortened = path_text is not None and path_text.endswith('"...')
        if shortened:
            displayed = c_bytes(path_text[:-3])
            # The observed strace 6.19 path decoder renders 4095 bytes even
            # when -s exceeds the complete 4100-byte request. This one failing
            # kernel call is bound to the complete retained caller input; its
            # undisplayed tail is never labeled as observed syscall bytes.
            need(action == 1 and error == 36 and returned == -36
                 and last - first == 2 and not operations
                 and len(displayed) == 4095 and len(original_path) > 4095
                 and b"\0" not in original_path and displayed == original_path[:4095],
                 "unqualified shortened syscall path display")
            path = original_path
        else:
            path = b"" if path_text is None else c_bytes(path_text)
            displayed = path
        observed = metadata(meta, action) if action in (2, 4) and error == 0 else None
        operations.append({"action": action, "path": path, "errno": error,
                           "raw": returned, "mode": observed["mode"] if observed else 0,
                           "metadata_identity": observed, "displayed_path": displayed,
                           "path_display_shortened": shortened})
    need(not any(event[0] in ("execve", "mkdir", "statx") for event in events[last + 1:]),
         "additional original semantic calls after the marker")
    return operations, {"syscalls": len(operations), "total_traced_syscalls": len(events),
                        "null_statx_probes": sum(row["action"] == 3 for row in operations),
                        "fallback_stat64": sum(row["action"] == 4 for row in operations),
                        "shortened_path_displays": sum(row["path_display_shortened"] for row in operations)}


def path_key(path, work, absolute):
    if not absolute or not path.startswith(b"/"):
        return path
    prefix = os.fsencode(work) + b"/"
    need(path.startswith(prefix), "absolute compared operation escaped its owned work tree")
    return path[len(prefix):]


def logical_tree(native, rows):
    native.validate_tree(rows)
    return [{"path_hex": row["path_hex"], "kind": row["kind"],
             "stat": {key: row["stat"][key] for key in ("mode", "uid", "gid", "nlink")},
             **{key: row[key] for key in ("payload_hex", "payload", "target_hex") if key in row}}
            for row in rows]


def verify_tree(native, before, after, spec, work, operations):
    initial = native.verify_setup(before, spec)
    final = native.validate_tree(after)
    current, created = dict(initial), []
    for operation in operations:
        if operation["errno"]:
            continue
        selected = native.virtual_path(operation["path"], work, current)
        if operation["action"] == 1:
            need(selected not in current and selected in final, "original mkdir creation not present in owned tree")
            row = final[selected]
            need(row["kind"] == "directory" and stat.S_IMODE(row["stat"]["mode"]) == 0o777 & ~spec["umask"],
                 "original created directory mode/umask")
            need((row["stat"]["uid"], row["stat"]["gid"]) ==
                 (initial[b""]["stat"]["uid"], initial[b""]["stat"]["gid"]), "original created directory owner")
            current[selected] = row; created.append(selected.hex())
        elif operation["action"] in (2, 4):
            need(selected in current, "original successful metadata target missing")
            exact(operation["metadata_identity"],
                  {key: current[selected]["stat"][key] for key in ("mode", "inode", "device")},
                  "original metadata does not identify the owned inode")
        else:
            raise ValueError("unexpected successful NULL metadata probe")
    need(set(current) == set(final), "unexplained original fixture entries")
    for path, row in initial.items():
        actual = final[path]
        need(actual["kind"] == row["kind"] and native.identity_equal(
            actual["stat"], row["stat"], stable=row["kind"] == "directory"), "original existing fixture identity changed")
        exact({key: actual.get(key) for key in ("payload_hex", "payload", "target_hex")},
              {key: row.get(key) for key in ("payload_hex", "payload", "target_hex")}, "original existing fixture bytes changed")
    return {"initial_entries": len(initial), "final_entries": len(final),
            "created_directories": len(created), "created_paths_hex": created}


def trace_command(tracer, executable, folder, wire):
    # strace 6.19 interprets -s 0 as zero displayed string bytes. Derive a
    # complete bound from this actual request/argv/environment instead.
    strings = [wire[64:], os.fsencode(executable), BEGIN, END, bytes(24)]
    strings.extend(os.fsencode(key + "=" + value) for key, value in environment(folder.parent.parent).items())
    extent = max(len(value) for value in strings) + 1
    return [str(tracer), *TRACE_ARGUMENTS, "-s", str(extent),
            "-o", str(folder / "syscall.trace"), "--", str(executable)]


def decoded_result(raw):
    need(len(raw) == 24 and raw[:8] == b"HSHMKO01", "complete original response framing")
    kind, value = struct.unpack_from("<2Q", raw, 8)
    need(kind in (0, 1, 2) and ((kind == 1 and 1 <= value <= 4095) or (kind != 1 and value == 0)),
         "original error domain")
    return {"kind": kind, "value": value}


def read_case(folder, spec, native_case, native, helper, build, tracer_identity,
              build_finished, *, retired=True):
    folder = Path(folder).absolute()
    native.plain_directory(folder)
    receipt = native.read_json(folder / "execution.json")
    trace_name = receipt.get("trace_file")
    need(type(trace_name) is str and re.fullmatch(r"syscall\.trace\.[1-9][0-9]*", trace_name), "actual trace filename")
    expected_files = set(CASE_FILES) | {trace_name}
    if not retired:
        expected_files.remove("retirement.json"); expected_files.add("work")
    need(set(os.listdir(folder)) == expected_files, "original case retained member inventory")
    exact(native.read_json(folder / "spec.json"), spec, "registered original case changed")
    need(folder.name == spec["name"] and spec["cache_seed"] == 0
         and spec["original_fresh_cache_comparable"] is True, "original fresh cache case domain")
    work = folder / "work"
    wire = native.input_for(spec, work)
    need(native.ordinary(folder / "input.bin") == wire, "complete actual original input differs")
    before, after = (native.read_json(folder / leaf) for leaf in ("before.json", "after.json"))
    stdout, stderr, trace = (native.ordinary(folder / leaf) for leaf in ("stdout.bin", "stderr.bin", trace_name))
    executable = build["executable"]["launch_path"]
    env = environment(folder.parent.parent)
    expected = {"schema": "hepta.runtime.shell-capture-mkdir-original-execution.v1",
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
         and (receipt["uid"], receipt["gid"]) == (before[0]["stat"]["uid"], before[0]["stat"]["gid"]),
         "actual original fixture account")
    if spec["name"] == "permission_denied":
        need(receipt["uid"] != 0, "original permission case requires unprivileged execution")
    operations, counts = parse_trace(trace, executable, env, native.path_for(spec, work), stdout, stderr)
    need(counts["shortened_path_displays"] == int(spec["name"] == "path_too_long"),
         "registered original path display coverage differs")
    projected = native.replay_policy(native.path_for(spec, work), 0, operations)
    result = decoded_result(stdout)
    exact(result, {key: projected[key] for key in ("kind", "value")}, "original response differs from actual syscall policy")
    native_result = native.decode_result(native_case["result_bytes"])
    exact(result, {key: native_result[key] for key in ("kind", "value")}, "original/native result or errno differs")
    need(native_result["cache"] == projected["cache"], "native cache transition differs from observed original syscall policy")
    observed = native_case["operations"]
    need(len(operations) == len(observed), "original/native syscall count differs")
    native_root = Path(receipt["native_case_directory"]) / "work"
    for index, (original, current) in enumerate(zip(operations, observed)):
        need(original["action"] == current["action"] and original["errno"] == current["errno"]
             and (original["raw"] & ((1 << 64) - 1)) == current["raw"]
             and original["mode"] == current["mode"], "original/native actual syscall result differs: " + str(index))
        need(path_key(original["path"], work, spec["absolute_under_work"]) ==
             path_key(current["path"], native_root, spec["absolute_under_work"]),
             "original/native actual syscall path differs: " + str(index))
    filesystem = verify_tree(native, before, after, spec, work, operations)
    exact(logical_tree(native, before), logical_tree(native, native_case["before"]), "original/native initial logical tree differs")
    exact(logical_tree(native, after), logical_tree(native, native_case["after"]), "original/native final logical tree differs")
    validation = {"schema": "hepta.runtime.shell-capture-mkdir-original-case.v1", "status": "PASS",
                  "name": spec["name"], "result": result, "filesystem": filesystem, "trace_counts": counts,
                  "trace_file": trace_name, "trace": pin(trace), "target_pid": target_pid,
                  "tracer_pid": receipt["tracer_pid"], "complete_input": pin(wire),
                  "complete_response": pin(stdout), "complete_native_response": pin(native_case["result_bytes"]),
                  "absolute_owned_prefix_mapping": spec["absolute_under_work"],
                  "syscall_path_displays": [{"complete_caller_path_hex": row["path"].hex(),
                      "displayed_path_hex": row["displayed_path"].hex(),
                      "complete_path_displayed": not row["path_display_shortened"]} for row in operations],
                  "native_case_directory": receipt["native_case_directory"], **SCOPE}
    if retired:
        native.verify_retirement(folder, after, validation)
    else:
        exact(native.tree_snapshot(work), after, "original tree changed before retirement")
    return validation


def run_case(folder, spec, native_case, native_case_directory, native, helper, build,
             tracer_identity, build_finished):
    folder.mkdir(mode=0o700)
    work = folder / "work"
    native.setup_case(work, spec)
    before = native.tree_snapshot(work)
    wire = native.input_for(spec, work)
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
    receipt = {"schema": "hepta.runtime.shell-capture-mkdir-original-execution.v1", "case": spec["name"],
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
        native.retire_case(folder, after, failed)
        raise
    native.retire_case(folder, after, checked)
    return read_case(folder, spec, native_case, native, helper, build, tracer_identity, build_finished)


def admitted(runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker):
    build = reference.read_evidence(runtime, reference_build, rustc, linker)
    need(build.get("status") == "PASS", "fresh original reference strong reader")
    build_report = helper.decode(helper.read(reference_build, "result.json"))
    finished = max(row["finished_unix_ns"] for row in build_report["processes"])
    original = {"path": str(reference_build), "report": pin(helper.read(reference_build, "result.json")), "evidence": build}
    evidence = native.read_evidence(native_corpus, native_manifest, require_full=True)
    need(evidence.get("status") == "PASS" and evidence["counts"]["cases"] == 33
         and evidence["counts"]["retired_fixtures"] == 33
         and evidence["physical_controls"]["physical_negative_controls"] == 14,
         "complete native mkdir corpus/retirement/control admission")
    baseline = {"path": str(native_corpus), "manifest": {"path": str(native_manifest), **pin(native.ordinary(native_manifest))},
                "report": pin(native.ordinary(native_corpus / "report.json")), "evidence": evidence}
    specifications = [spec for spec in native.case_specs() if spec["original_fresh_cache_comparable"]]
    need(len(specifications) == 30 and all(spec["cache_seed"] == 0 for spec in specifications),
         "complete fresh original case inventory")
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
         "original mkdir comparison incomplete")
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
              "actual_null_statx_probes": sum(row["trace_counts"]["null_statx_probes"] for row in results),
              "shortened_path_displays": sum(row["trace_counts"]["shortened_path_displays"] for row in results),
              "native_seeded_cache_cases_not_replayed_as_original": 3}
    exact(report.get("counts"), counts, "original comparison counts changed")
    return {"schema": "hepta.runtime.shell-capture-mkdir-original-evidence.v1", "status": "PASS",
            "report_sha256": pin(native.ordinary(output / "result.json"))["sha256"],
            "counts": counts, "fresh_original_build_qualified": True,
            "complete_native_corpus_and_controls_verified": True, **SCOPE}


def run(runtime, reference_build, native_corpus, native_manifest, output,
        rustc=None, linker=None, tracer=Path("/usr/bin/strace")):
    output.mkdir(parents=True, exist_ok=False)
    (output / "cases").mkdir(); (output / "temporary").mkdir()
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None, "recorded_directory": str(output),
              "runtime": str(runtime), "scope": {**SCOPE, "original_blocking_mkdir_compared": False}, "cases": []}
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
                            "actual_null_statx_probes": sum(row["trace_counts"]["null_statx_probes"] for row in report["cases"]),
                            "shortened_path_displays": sum(row["trace_counts"]["shortened_path_displays"] for row in report["cases"]),
                            "native_seeded_cache_cases_not_replayed_as_original": 3}
        exact(source_pins(runtime, native), report["sources"], "comparison sources changed during actual execution")
        report.update(status="PASS", scope=SCOPE); save()
        checked = read_evidence(runtime, reference_build, native_corpus, native_manifest, output, rustc, linker, tracer)
        native.write_new(output / "evidence.json", encoded(checked))
    except BaseException as failure:
        report.update(status="FAIL", error=type(failure).__name__ + ": " + str(failure),
                      scope={**SCOPE, "original_blocking_mkdir_compared": False})
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
