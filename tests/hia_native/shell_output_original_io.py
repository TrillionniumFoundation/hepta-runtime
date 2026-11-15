#!/usr/bin/env python3
"""Observe unchanged original Shell foreground I/O under real Linux faults.

The shared command gate is a test input. Only this case's original capture paths
are changed, after the original observer and child hold their file descriptors.
All traced threads/processes and unmodified Rust JSONL are retained. No result
here qualifies native I/O, natural wait errors, cancellation, or production Shell.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import traceback


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "hepta.runtime.shell-output-original-io.v1"
EVENT_SCHEMA = "hepta.runtime.shell-process-fixture-event.v1"
GATE_ENV = "HIA_FIXTURE_CAPTURE_READY"
GATE_PREFIX = 'while [ ! -e "$HIA_FIXTURE_CAPTURE_READY" ]; do /bin/sleep 0.005; done\n'
STREAMS = ("stdout", "stderr")
TRACE_RESOLUTION_NS = 1000


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       indent=2, allow_nan=False) + "\n").encode()


def write_json(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def identity(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "expected ordinary file: " + str(path))
    data = path.read_bytes()
    return {"path": str(path.absolute()), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def io_specs():
    """Exact shared stable-file fault inputs, independent of either implementation."""
    rows = [
        {"name": "normal", "exit_code": 0, "faults": []},
        {"name": "stdout_missing", "exit_code": 0,
         "faults": [{"stream": "stdout", "op": "unlink"}]},
        {"name": "stderr_missing", "exit_code": 0,
         "faults": [{"stream": "stderr", "op": "unlink"}]},
        {"name": "stdout_missing_stderr_directory", "exit_code": 0,
         "faults": [{"stream": "stdout", "op": "unlink"},
                    {"stream": "stderr", "op": "replace_dir"}]},
        {"name": "nonzero_stdout_missing", "exit_code": 7,
         "faults": [{"stream": "stdout", "op": "unlink"}]},
        {"name": "replace_both_paths", "exit_code": 0,
         "faults": [{"stream": "stdout", "op": "replace_file",
                     "replacement_hex": b"replacement-out\n".hex()},
                    {"stream": "stderr", "op": "replace_file",
                     "replacement_hex": b"replacement-err\n".hex()}]},
    ]
    for row in rows:
        row.update(stdout_hex=b"alpha\n".hex(), stderr_hex=b"beta\n".hex())
    return rows


def expected_reads(spec):
    result = {stream: {"errno": 0, "bytes_hex": spec[stream + "_hex"]}
              for stream in STREAMS}
    for fault in spec["faults"]:
        result[fault["stream"]] = {
            "unlink": {"errno": 2, "bytes_hex": None},
            "replace_dir": {"errno": 21, "bytes_hex": None},
            "replace_file": {"errno": 0, "bytes_hex": fault.get("replacement_hex")},
        }[fault["op"]]
    return result


def command_for(spec):
    def octal(data):
        return "".join("\\%03o" % byte for byte in data)
    return (GATE_PREFIX + "printf '" + octal(bytes.fromhex(spec["stdout_hex"]))
            + "'; printf '" + octal(bytes.fromhex(spec["stderr_hex"]))
            + "' >&2; exit " + str(spec["exit_code"]))


def process_identity(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        status = Path(f"/proc/{pid}/status").read_text()
    except FileNotFoundError:
        return None
    require(type(pid) is int and pid > 0 and ") " in raw, "invalid process identity")
    fields = raw.rsplit(") ", 1)[1].split()
    parsed = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
              for line in status.splitlines() if ":" in line}
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
            "sid": int(fields[3]), "starttime_ticks": int(fields[19]),
            "tgid": int(parsed["Tgid"]), "tracer_pid": int(parsed["TracerPid"]),
            "raw_stat": raw, "raw_status": status}


def file_state(path):
    try:
        value = Path(path).lstat()
    except FileNotFoundError:
        return None
    require(not stat.S_ISLNK(value.st_mode), "capture pathname became a symlink")
    return {"dev": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
            "uid": value.st_uid, "nlink": value.st_nlink, "size": value.st_size}


def fd_state(pid, fd):
    path = Path(f"/proc/{pid}/fd/{fd}")
    value = path.stat()
    info = Path(f"/proc/{pid}/fdinfo/{fd}").read_text()
    rows = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
    return {"pid": pid, "fd": fd, "dev": value.st_dev, "inode": value.st_ino,
            "mode": value.st_mode, "size": value.st_size,
            "flags": int(rows["flags"].strip(), 8), "fdinfo": info,
            "target_hex": os.fsencode(os.readlink(path)).hex()}


def capture_snapshot(event, temporary):
    oracle, child = event["oracle_pid"], event["pid"]
    directory = temporary / f"octofs-jobs-{oracle}"
    require(directory.resolve(strict=True) == directory, "capture directory is not canonical")
    result = {}
    for stream, fd in (("stdout", 1), ("stderr", 2)):
        expected = directory / f"{oracle}-1.{stream}.log"
        require(event[stream + "_source_path"] == str(expected), "unexpected original capture path")
        state = file_state(expected)
        require(state and stat.S_ISREG(state["mode"]) and state["nlink"] == 1
                and state["uid"] == os.getuid() and state["size"] == 0,
                "original capture is not a fresh owned empty file")
        writer = fd_state(child, fd)
        require((writer["dev"], writer["inode"]) == (state["dev"], state["inode"])
                and writer["flags"] & os.O_ACCMODE == os.O_WRONLY,
                "child writer does not hold this original capture")
        readers = []
        for entry in sorted(Path(f"/proc/{oracle}/fd").iterdir(), key=lambda p: int(p.name)):
            try:
                row = fd_state(oracle, int(entry.name))
            except FileNotFoundError:
                continue
            if (row["dev"], row["inode"]) == (state["dev"], state["inode"]):
                if row["flags"] & os.O_ACCMODE == os.O_RDONLY:
                    readers.append(row)
        require(len(readers) == 1, "capture observer must hold exactly one read descriptor")
        result[stream] = {"path": str(expected), "before": state,
                          "writer": writer, "observer": readers[0]}
    return result


def apply_faults(spec, snapshot):
    """Only descriptor-relative changes to this verified case's exact two leaves."""
    changes = []
    for fault in spec["faults"]:
        original = snapshot[fault["stream"]]
        path = Path(original["path"])
        before = file_state(path)
        require(before == original["before"], "capture changed before controlled mutation")
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        started = time.time_ns()
        try:
            os.unlink(path.name, dir_fd=directory)
            if fault["op"] == "replace_dir":
                os.mkdir(path.name, 0o700, dir_fd=directory)
            elif fault["op"] == "replace_file":
                descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                try:
                    data = bytes.fromhex(fault["replacement_hex"])
                    cursor = 0
                    while cursor < len(data):
                        count = os.write(descriptor, data[cursor:])
                        require(count > 0, "replacement write made no progress")
                        cursor += count
                finally:
                    os.close(descriptor)
            else:
                require(fault["op"] == "unlink", "unregistered fault")
        finally:
            os.close(directory)
        after = file_state(path)
        if after:
            require(after["inode"] != before["inode"], "replacement reused a held inode")
        writer = fd_state(original["writer"]["pid"], original["writer"]["fd"])
        observer = fd_state(original["observer"]["pid"], original["observer"]["fd"])
        for row in (writer, observer):
            require((row["dev"], row["inode"]) == (before["dev"], before["inode"]),
                    "mutation changed a held original descriptor")
        changes.append({"fault": fault, "path": str(path), "started_unix_ns": started,
                        "finished_unix_ns": time.time_ns(), "before": before,
                        "after": after, "writer_after": writer, "observer_after": observer})
    return changes


def decimal_ns(value):
    whole, _, fraction = value.partition(".")
    return int(whole) * 1_000_000_000 + int((fraction + "000000000")[:9])


def quoted_bytes(arguments):
    values = re.findall(r'"((?:\\x[0-9a-fA-F]{2})*)"', arguments)
    return [bytes.fromhex(value.replace("\\x", "")) for value in values]


def first_fd(arguments):
    matched = re.match(r"(\d+)(?:<|,|\))", arguments)
    return int(matched.group(1)) if matched else None


def trace_records(directory):
    """Parse syscall facts; retain every raw line, including unrelated syscalls."""
    directory = Path(directory)
    files, rows, raw_lines = {}, [], {}
    expression = re.compile(r"^(\d+\.\d+) ([a-zA-Z0-9_]+)\((.*)\) += (.*?)(?: <(\d+\.\d+)>)?$")
    for path in sorted(directory.iterdir()):
        require(re.fullmatch(r"trace\.[1-9][0-9]*", path.name) is not None,
                "unexpected member of isolated trace directory")
        tid = int(path.name.split(".")[1])
        require(not path.is_symlink() and path.is_file(), "nonordinary trace member")
        raw = path.read_bytes()
        require(raw.endswith(b"\n"), "incomplete final trace line")
        lines = raw.decode("utf-8", "strict").splitlines()
        require(lines and re.search(r"\+\+\+ (?:exited with \d+|killed by [A-Z0-9]+.*?) \+\+\+$", lines[-1]),
                "trace lacks a terminal process observation")
        files[path.name] = identity(path)
        raw_lines[tid] = lines
        pending = None
        for number, line in enumerate(lines, 1):
            original_line = line
            detached_stdin = re.fullmatch(r"(\d+\.\d+) read\((0<[^>]+>)(?: |, +)<unfinished \.\.\.>\) = \?", line)
            if detached_stdin:
                # The unchanged fixture deliberately leaves its detached stdin
                # reader blocked while main exits. This is an observed aborted
                # fd 0 read, never a completed capture-file read or missing tail.
                require("+++ exited with 0 +++" in lines[-1], "blocked stdin did not end in normal process exit")
                start = decimal_ns(detached_stdin.group(1))
                rows.append({"tid": tid, "line": number, "end_line": number,
                             "start_ns": start, "end_ns": decimal_ns(lines[-1].split()[0]),
                             "call": "read", "arguments": detached_stdin.group(2),
                             "returned": "?", "result": None, "errno": None,
                             "completed": False, "ended_by_process_exit": True,
                             "raw_sha256": hashlib.sha256(line.encode()).hexdigest()})
                continue
            if "<unfinished ...>" in line:
                require(pending is None, "overlapping unfinished syscalls")
                prefix = line.split("<unfinished ...>", 1)[0]
                pending = (prefix, number, line)
                continue
            resumed = re.match(r"^\d+\.\d+ <\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)$", line)
            if resumed:
                require(pending is not None and (" " + resumed.group(1) + "(") in pending[0],
                        "resumed syscall has no matching entry")
                line = pending[0] + resumed.group(2)
                entry_number = pending[1]
                original_line = pending[2] + "\n" + original_line
                pending = None
            else:
                entry_number = number
            matched = expression.match(line)
            if not matched:
                require(re.match(r"^\d+\.\d+ (?:--- |\+\+\+ )", line) is not None,
                        "unrecognized complete strace line: " + path.name + ":" + str(number))
                continue
            timestamp, call, arguments, returned, duration = matched.groups()
            result = re.match(r"(-?\d+)(?:[ <]|$)", returned)
            errno = re.match(r"-1 ([A-Z][A-Z0-9]+) ", returned)
            start = decimal_ns(timestamp)
            rows.append({"tid": tid, "line": entry_number, "end_line": number,
                         "start_ns": start, "end_ns": start + decimal_ns(duration or "0"),
                         "call": call, "arguments": arguments, "returned": returned,
                         "result": int(result.group(1)) if result else None,
                         "errno": errno.group(1) if errno else None,
                         "raw_sha256": hashlib.sha256(original_line.encode()).hexdigest()})
        require(pending is None, "trace ended inside a syscall")
    require(files, "missing complete syscall trace")
    return files, sorted(rows, key=lambda row: (row["start_ns"], row["tid"], row["line"])), raw_lines


def trace_ref(row):
    return {key: row[key] for key in ("tid", "line", "end_line", "start_ns", "end_ns",
                                     "call", "result", "errno", "raw_sha256")}


def trace_scope(rows, oracle, traces):
    descendants, threads = {oracle}, {oracle}
    while True:
        before = (len(descendants), len(threads))
        for row in rows:
            if row["call"] not in ("clone", "clone3", "fork", "vfork") or not row["result"] or row["result"] < 0:
                continue
            if row["tid"] in descendants:
                descendants.add(row["result"])
            if row["tid"] in threads and "CLONE_THREAD" in row["arguments"]:
                threads.add(row["result"])
        if before == (len(descendants), len(threads)):
            break
    require(descendants == set(traces), "full trace inventory differs from actual fork/thread closure")
    return threads, descendants


def pathname(row):
    strings = quoted_bytes(row["arguments"])
    return strings[0] if strings else None


def before(left, right, message):
    # strace -ttt/-T record microsecond values. The bound represents only that
    # explicit rounding resolution, not an allowance for reordered operations.
    require(left["start_ns"] <= right["start_ns"]
            and left["end_ns"] <= right["start_ns"] + TRACE_RESOLUTION_NS,
            message)


def analyze_original_io(directory, prepared, receipt, events, snapshots, mutations):
    spec = prepared["definition"]
    files, all_rows, traces = trace_records(Path(directory) / "traces")
    oracle = receipt["oracle_identity"]["pid"]
    child = receipt["child_identity"]["pid"]
    threads, descendants = trace_scope(all_rows, oracle, traces)
    rows = [row for row in all_rows if row["tid"] in threads]
    waits = [row for row in rows if row["call"] == "wait4"
             and row["result"] == child
             and re.match(str(child) + r",", row["arguments"])]
    require(len(waits) == 1, "original child lacks one actual positive wait4")
    waited = waits[0]
    require(f"WEXITSTATUS(s) == {spec['exit_code']}" in waited["arguments"]
            and "WIFEXITED(s)" in waited["arguments"], "actual wait result differs from case")
    require(waited["start_ns"] >= receipt["gate_release"]["started_unix_ns"],
            "wait completed before controller released the command gate")
    foreground = events[2]
    wanted = expected_reads(spec)
    histories, last = {}, waited
    for stream in STREAMS:
        source = os.fsencode(snapshots[stream]["path"])
        opens = [row for row in rows if row["call"] in ("open", "openat")
                 and pathname(row) == source and "O_RDONLY" in row["arguments"]
                 and row["start_ns"] >= waited["start_ns"]]
        require(len(opens) == 1, "post-wait original must open each stream exactly once")
        opened = opens[0]
        before(last, opened, "original stdout/stderr read ordering differs")
        require("O_CLOEXEC" in opened["arguments"], "original read lost close-on-exec")
        history = {"open": trace_ref(opened), "metadata": [], "reads": [], "close": None}
        if wanted[stream]["errno"] == 2:
            require(opened["result"] == -1 and opened["errno"] == "ENOENT", "missing capture did not fail open with ENOENT")
            history.update(errno=2, bytes_hex=None)
            last = opened
        else:
            fd = opened["result"]
            require(type(fd) is int and fd >= 0
                    and fd != snapshots[stream]["observer"]["fd"],
                    "post-wait read reused the observer instead of opening the path")
            closes = [row for row in rows if row["call"] == "close" and first_fd(row["arguments"]) == fd
                      and row["start_ns"] > opened["start_ns"]]
            require(closes, "original read descriptor was not closed")
            closed = closes[0]
            require(closed["result"] == 0, "unexpected close failure outside these cases")
            middle = [row for row in rows if opened["start_ns"] < row["start_ns"] < closed["start_ns"]
                      and first_fd(row["arguments"]) == fd]
            metadata = [row for row in middle if row["call"] in ("statx", "fstat", "fstat64")]
            require(len(metadata) == 1 and metadata[0]["result"] == 0, "missing actual file metadata observation")
            inode = snapshots[stream]["before"]["inode"]
            for mutation in mutations:
                if mutation["fault"]["stream"] == stream and mutation["after"] is not None:
                    inode = mutation["after"]["inode"]
            require(re.search(r"(?:stx_ino|st_ino)=" + str(inode) + r"(?:,|})", metadata[0]["arguments"]),
                    "post-wait metadata is not the actual selected pathname inode")
            reads = [row for row in middle if row["call"] == "read"]
            require(reads, "original opened capture without an actual read")
            data = bytearray()
            for row in reads:
                require(type(row["result"]) is int, "ambiguous original read return")
                if row["result"] >= 0:
                    strings = quoted_bytes(row["arguments"])
                    require(len(strings) == 1 and len(strings[0]) == row["result"],
                            "trace omitted or truncated actual returned read bytes")
                    data.extend(strings[0])
            if wanted[stream]["errno"]:
                require(wanted[stream]["errno"] == 21 and len(reads) == 1
                        and reads[0]["result"] == -1 and reads[0]["errno"] == "EISDIR",
                        "directory capture did not perform read and fail with EISDIR")
                history.update(errno=21, bytes_hex=None)
            else:
                require(reads[-1]["result"] == 0 and all(row["result"] >= 0 for row in reads)
                        and data.hex() == wanted[stream]["bytes_hex"],
                        "complete original read bytes or final EOF differ")
                history.update(errno=0, bytes_hex=data.hex())
            history.update(metadata=[trace_ref(row) for row in metadata],
                           reads=[trace_ref(row) for row in reads], close=trace_ref(closed), fd=fd, inode=inode)
            last = closed
        histories[stream] = history
    discards = {}
    for stream in STREAMS:
        source = os.fsencode(snapshots[stream]["path"])
        unlinks = [row for row in rows if row["call"] == "unlink" and pathname(row) == source]
        require(len(unlinks) == 1, "original must attempt both discard unlinks exactly once")
        removed = unlinks[0]
        before(last, removed, "read/close/discard ordering differs from original")
        expected_errno = {"unlink": "ENOENT", "replace_dir": "EISDIR"}.get(
            next((fault["op"] for fault in spec["faults"] if fault["stream"] == stream), ""))
        require((removed["result"], removed["errno"]) == ((-1, expected_errno) if expected_errno else (0, None)),
                "discard outcome differs from the injected real pathname state")
        discards[stream] = trace_ref(removed)
        last = removed
    require(last["start_ns"] <= foreground["unix_ns"], "foreground result preceded actual discard attempts")
    observations = {}
    for stream in STREAMS:
        source = os.fsencode(snapshots[stream]["path"])
        quoted_path = "".join("\\x%02x" % byte for byte in source)
        writes = [row for row in all_rows if row["tid"] == child and row["call"] == "write"
                  and ("<" + quoted_path + ">") in row["arguments"]]
        written = bytearray()
        for row in writes:
            strings = quoted_bytes(row["arguments"])
            require(len(strings) == 1 and row["result"] == len(strings[0]), "child write bytes are incomplete")
            require(row["start_ns"] >= receipt["gate_release"]["started_unix_ns"]
                    and row["end_ns"] <= waited["start_ns"] + TRACE_RESOLUTION_NS,
                    "child capture write was outside the released-command lifetime")
            written.extend(strings[0])
        require(written.hex() == spec[stream + "_hex"], "real child did not write exact shared input bytes")
        fd = snapshots[stream]["observer"]["fd"]
        observed = [row for row in rows if row["call"] == "read" and first_fd(row["arguments"]) == fd
                    and row["start_ns"] >= foreground["unix_ns"]]
        original = bytearray()
        require(observed and observed[-1]["result"] == 0, "observer did not read its old descriptor through EOF")
        for row in observed:
            strings = quoted_bytes(row["arguments"])
            require(len(strings) == 1 and row["result"] == len(strings[0]), "observer raw read was incomplete")
            original.extend(strings[0])
        require(original == written, "observer old-inode bytes differ from real original child writes")
        observations[stream] = {"writes": [trace_ref(row) for row in writes],
                                "observer_reads": [trace_ref(row) for row in observed],
                                "old_inode_bytes_hex": original.hex()}
    return {"status": "PASS", "trace_files": files, "oracle_threads": sorted(threads),
            "all_traced_descendants": sorted(descendants), "wait": trace_ref(waited),
            "wait_exit_code": spec["exit_code"], "streams": histories, "discard": discards,
            "child_and_observer": observations,
            "timestamp_resolution_ns": TRACE_RESOLUTION_NS,
            "both_reads_and_both_discards_observed": True,
            "observer_reads_are_separate_from_post_wait_path_reads": True,
            "natural_wait_error_executed": False}


def fixture_environment(directory):
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "USER": "hepta-fixture", "HOME": str(directory / "work"),
            "TMPDIR": str(directory / "tmp"), GATE_ENV: str(directory / "capture.ready")}


def prepare(spec, directory):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    require(directory.resolve(strict=True) == directory, "case directory has a symlink ancestor")
    for name in ("work", "tmp", "retained", "traces"):
        (directory / name).mkdir(mode=0o700)
    value = {"schema": SCHEMA + ".input", "definition": spec, "directory": str(directory),
             "command_hex": command_for(spec).encode().hex(),
             "cwd_hex": os.fsencode(directory / "work").hex(),
             "timeout_ms": 10000, "deadline_seconds": 10,
             "environment": fixture_environment(directory),
             "ready_path": str(directory / "capture.ready"),
             "capture_dir": str(directory / "retained")}
    write_json(directory / "input.json", value)
    return value


def cleanup_owned(process, identities):
    observations = []
    if process.poll() is None and process.stdin is not None:
        try:
            count = os.write(process.stdin.fileno(), b'{"op":"shutdown"}\n')
            observations.append({"trusted_shutdown_bytes": count})
            process.wait(timeout=0.3)
        except (OSError, subprocess.TimeoutExpired) as error:
            observations.append({"shutdown_observation": type(error).__name__})
    # These registered commands only fork bounded gate sleeps. Signal no broad
    # process group or PID whose actual start identity was not observed.
    for role in ("child", "oracle", "wrapper"):
        previous = identities.get(role)
        if not previous:
            continue
        current = process_identity(previous["pid"])
        row = {"role": role, "observed": previous, "before_signal": current, "signaled": False}
        if current and current["starttime_ticks"] == previous["starttime_ticks"]:
            try:
                fd = os.pidfd_open(current["pid"])
                try:
                    again = process_identity(current["pid"])
                    if again and again["starttime_ticks"] == previous["starttime_ticks"]:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                        row["signaled"] = True
                finally:
                    os.close(fd)
            except ProcessLookupError:
                row["exited_before_signal"] = True
        observations.append(row)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        observations.append({"wrapper_wait_timeout": True})
    return observations


def run_case(prepared, oracle, strace):
    directory = Path(prepared["directory"])
    request = {"op": "execute", "command_hex": prepared["command_hex"],
               "cwd_hex": prepared["cwd_hex"], "timeout_ms": prepared["timeout_ms"],
               "capture_dir": prepared["capture_dir"]}
    payload = (json.dumps(request, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    argv = [str(strace), "-ff", "-ttt", "-T", "-yy", "-xx", "-s", "1048576", "-v",
            "-o", str(directory / "traces/trace"), str(oracle), "--fixture"]
    started_unix, started = time.time_ns(), time.monotonic_ns()
    stdout, stderr, delivered = bytearray(), bytearray(), bytearray()
    pending = bytearray(payload)
    events, mutations, snapshots, identities = [], [], {}, {}
    cleanup, gate_release, failure = [], None, None
    timed_out, cursor = False, 0
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=directory,
                                   env=prepared["environment"], start_new_session=True)
        identities["wrapper"] = process_identity(process.pid)
        require(identities["wrapper"] is not None, "strace wrapper identity was not observed")
        for handle, name in ((process.stdin, "stdin"), (process.stdout, "stdout"), (process.stderr, "stderr")):
            require(handle is not None, "missing fixture pipe")
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)
        deadline = started + prepared["deadline_seconds"] * 1_000_000_000
        while True:
            if time.monotonic_ns() >= deadline:
                timed_out = True
                raise TimeoutError("original I/O fixture exceeded its actual deadline")
            for key, _ in selector.select(0.01):
                if key.data == "stdin":
                    count = os.write(key.fileobj.fileno(), pending)
                    delivered.extend(pending[:count])
                    del pending[:count]
                    if not pending:
                        selector.unregister(key.fileobj)
                    continue
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(chunk)
                if key.data != "stdout":
                    continue
                while (end := stdout.find(b"\n", cursor)) >= 0:
                    event = decode(bytes(stdout[cursor:end]))
                    cursor = end + 1
                    require(event.get("schema") == EVENT_SCHEMA and type(event.get("seq")) is int
                            and event["seq"] == len(events) + 1, "invalid original event schema/sequence")
                    if not events:
                        require(event.get("event") == "started", "original did not begin with admitted input")
                        oracle_pid = event.get("oracle_pid")
                        require(type(oracle_pid) is int and oracle_pid > 0 and oracle_pid != process.pid,
                                "strace wrapper PID was confused with the original oracle")
                        own = process_identity(oracle_pid)
                        require(own and own["ppid"] == process.pid and own["tgid"] == oracle_pid
                                and own["tracer_pid"] == process.pid, "original is not the owned traced child")
                        actual = os.stat(f"/proc/{oracle_pid}/exe")
                        expected = oracle.stat()
                        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
                                "observed original process executed a different image")
                        own["exe_path"] = os.readlink(f"/proc/{oracle_pid}/exe")
                        own["exe_dev"], own["exe_inode"] = actual.st_dev, actual.st_ino
                        identities["oracle"] = own
                    require(event.get("oracle_pid") == identities["oracle"]["pid"], "original event PID changed")
                    events.append(event)
                    if event.get("event") == "capture_ready":
                        require(len(events) == 2 and not snapshots, "unexpected duplicate or late capture readiness")
                        child = process_identity(event["pid"])
                        require(child and child["ppid"] == identities["oracle"]["pid"]
                                and child["pgid"] == child["pid"] and child["sid"] == child["pid"]
                                and child["tracer_pid"] == process.pid, "capture child custody was not observed")
                        identities["child"] = child
                        snapshots = capture_snapshot(event, directory / "tmp")
                        mutations = apply_faults(prepared["definition"], snapshots)
                        gate_release = {"started_unix_ns": time.time_ns()}
                        with Path(prepared["ready_path"]).open("xb") as stream:
                            stream.write(b"ready\n")
                        gate_release["finished_unix_ns"] = time.time_ns()
            if process.poll() is not None and not any(key.data in STREAMS for key in selector.get_map().values()):
                break
        require(not pending and cursor == len(stdout), "partial original request or JSONL output")
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        if process is not None:
            cleanup = cleanup_owned(process, identities)
            for handle, target in ((process.stdout, stdout), (process.stderr, stderr)):
                if handle is None:
                    continue
                while True:
                    try:
                        data = os.read(handle.fileno(), 65536)
                    except (BlockingIOError, OSError):
                        break
                    if not data:
                        break
                    target.extend(data)
    finally:
        selector.close()
        if process:
            for handle in (process.stdin, process.stdout, process.stderr):
                if handle:
                    handle.close()
    final_identities = {role: process_identity(value["pid"]) for role, value in identities.items() if value}
    for name, value in (("stdin.jsonl", delivered), ("stdout.jsonl", stdout), ("stderr", stderr)):
        (directory / name).write_bytes(value)
    write_json(directory / "events.json", events)
    write_json(directory / "capture-snapshots.json", snapshots)
    write_json(directory / "mutations.json", mutations)
    receipt = {"schema": SCHEMA + ".process", "argv": argv, "cwd": str(directory),
               "environment": prepared["environment"], "started_unix_ns": started_unix,
               "finished_unix_ns": time.time_ns(), "duration_ns": time.monotonic_ns() - started,
               "deadline_seconds": prepared["deadline_seconds"], "exit_code": process.returncode if process else None,
               "timed_out": timed_out, "exception": failure, "cleanup": cleanup,
               "wrapper_identity": identities.get("wrapper"), "oracle_identity": identities.get("oracle"),
               "child_identity": identities.get("child"), "final_identities": final_identities,
               "gate_release": gate_release, "original_executable": identity(oracle), "strace_executable": identity(strace),
               "streams": {name: identity(directory / filename) for name, filename in
                           (("stdin", "stdin.jsonl"), ("stdout", "stdout.jsonl"), ("stderr", "stderr"))}}
    write_json(directory / "process.json", receipt)
    return receipt


def read_case(directory):
    """Pure read-only reconstruction of raw JSONL, complete traces and owned faults."""
    directory = Path(directory).absolute()
    def read_json(name):
        path = directory / name
        require(not path.is_symlink() and path.is_file(), "missing ordinary case evidence: " + name)
        return decode(path.read_bytes())
    prepared = read_json("input.json")
    receipt = read_json("process.json")
    snapshots = read_json("capture-snapshots.json")
    mutations = read_json("mutations.json")
    spec = prepared["definition"]
    registered = {row["name"]: row for row in io_specs()}
    require(spec == registered.get(spec.get("name")), "case differs from registered deterministic input")
    require(prepared["directory"] == str(directory) and prepared["environment"] == fixture_environment(directory)
            and prepared["command_hex"] == command_for(spec).encode().hex()
            and prepared["cwd_hex"] == os.fsencode(directory / "work").hex()
            and prepared["timeout_ms"] == 10000 and prepared["deadline_seconds"] == 10
            and prepared["capture_dir"] == str(directory / "retained")
            and prepared["ready_path"] == str(directory / "capture.ready"), "case input binding differs")
    require(receipt["schema"] == SCHEMA + ".process" and type(receipt["exit_code"]) is int
            and receipt["exit_code"] == 0 and receipt["timed_out"] is False
            and receipt["exception"] is None and receipt["cleanup"] == [], "original trace process did not finish naturally")
    require(receipt["cwd"] == str(directory) and receipt["environment"] == prepared["environment"]
            and receipt["deadline_seconds"] == 10
            and type(receipt["duration_ns"]) is int and 0 < receipt["duration_ns"] < 10_000_000_000,
            "original process receipt command/deadline differs")
    expected_argv = [receipt["strace_executable"]["path"], "-ff", "-ttt", "-T", "-yy", "-xx", "-s", "1048576", "-v",
                     "-o", str(directory / "traces/trace"), receipt["original_executable"]["path"], "--fixture"]
    require(receipt["argv"] == expected_argv, "trace invocation changed or excludes syscalls")
    for stream, name in (("stdin", "stdin.jsonl"), ("stdout", "stdout.jsonl"), ("stderr", "stderr")):
        require(receipt["streams"][stream] == identity(directory / name), "actual process stream pin differs")
    require(not (directory / "stderr").read_bytes(), "strace/original process wrote unexpected diagnostics")
    request = {"op": "execute", "command_hex": prepared["command_hex"], "cwd_hex": prepared["cwd_hex"],
               "timeout_ms": 10000, "capture_dir": prepared["capture_dir"]}
    require((directory / "stdin.jsonl").read_bytes() ==
            (json.dumps(request, separators=(",", ":"), ensure_ascii=True) + "\n").encode(),
            "actual original request differs or includes a hidden shutdown")
    raw = (directory / "stdout.jsonl").read_bytes()
    require(raw.endswith(b"\n"), "original JSONL is truncated")
    events = [decode(line) for line in raw.splitlines()]
    require(events == read_json("events.json") and [row.get("event") for row in events] ==
            ["started", "capture_ready", "foreground", "final"], "original lifecycle event ordering differs")
    oracle = receipt["oracle_identity"]
    wrapper = receipt["wrapper_identity"]
    child = receipt["child_identity"]
    require(oracle["pid"] != wrapper["pid"] and oracle["ppid"] == wrapper["pid"]
            and oracle["tgid"] == oracle["pid"] and oracle["tracer_pid"] == wrapper["pid"]
            and child["ppid"] == oracle["pid"] and child["pgid"] == child["pid"]
            and child["sid"] == child["pid"] and child["tracer_pid"] == wrapper["pid"],
            "wrapper/oracle/child identities are not distinct actual owned processes")
    for role, previous in (("wrapper", wrapper), ("oracle", oracle), ("child", child)):
        observed = receipt["final_identities"][role]
        require(observed is None or observed["starttime_ticks"] != previous["starttime_ticks"],
                "a traced owned process remained alive at completion")
    prior_time = -1
    for number, event in enumerate(events, 1):
        require(event.get("schema") == EVENT_SCHEMA and type(event.get("seq")) is int
                and event["seq"] == number and event.get("oracle_pid") == oracle["pid"]
                and type(event.get("elapsed_ns")) is int and event["elapsed_ns"] >= prior_time
                and type(event.get("unix_ns")) is int, "original event identity/time/sequence differs")
        prior_time = event["elapsed_ns"]
    require(all(events[0][key] == request[key] for key in ("command_hex", "cwd_hex", "timeout_ms", "capture_dir")),
            "original did not execute this exact request")
    require(events[0]["owner_entry"] == "unchanged execute_with_timeout", "original entry changed")
    ready = events[1]
    require(ready["pid"] == child["pid"] and ready["tracker_pids"] == [child["pid"]]
            and set(snapshots) == set(STREAMS), "capture readiness lost the original tracked child")
    require([row["fault"] for row in mutations] == spec["faults"], "actual controlled mutation recipe differs")
    require(receipt["gate_release"] is not None and receipt["gate_release"]["started_unix_ns"] >= ready["unix_ns"],
            "command gate was released before original capture readiness")
    for stream in STREAMS:
        snapshot = snapshots[stream]
        path = directory / "tmp" / f"octofs-jobs-{oracle['pid']}" / f"{oracle['pid']}-1.{stream}.log"
        require(snapshot["path"] == str(path) == ready[stream + "_source_path"], "capture source is outside exact owned namespace")
        before_state = snapshot["before"]
        require(stat.S_ISREG(before_state["mode"]) and before_state["nlink"] == 1 and before_state["size"] == 0,
                "captured file was not initially empty and ordinary")
        require(snapshot["writer"]["pid"] == child["pid"] and snapshot["writer"]["fd"] == (1 if stream == "stdout" else 2)
                and snapshot["observer"]["pid"] == oracle["pid"], "held capture descriptor owner differs")
        for descriptor in (snapshot["writer"], snapshot["observer"]):
            require((descriptor["dev"], descriptor["inode"]) == (before_state["dev"], before_state["inode"]),
                    "writer/observer did not retain the original same inode")
        for mutation in [row for row in mutations if row["fault"]["stream"] == stream]:
            require(mutation["path"] == str(path) and mutation["before"] == before_state
                    and ready["unix_ns"] <= mutation["started_unix_ns"] <= mutation["finished_unix_ns"]
                    <= receipt["gate_release"]["started_unix_ns"], "controlled mutation escaped readiness gate or owned source")
            if mutation["fault"]["op"] == "unlink":
                require(mutation["after"] is None, "unlink fault did not remove the original path")
            else:
                require(mutation["after"] is not None and mutation["after"]["inode"] != before_state["inode"],
                        "replacement fault did not select a new inode")
                required_type = stat.S_ISDIR if mutation["fault"]["op"] == "replace_dir" else stat.S_ISREG
                require(required_type(mutation["after"]["mode"]), "replacement pathname type differs")
            for key in ("writer_after", "observer_after"):
                require((mutation[key]["dev"], mutation[key]["inode"]) == (before_state["dev"], before_state["inode"]),
                        "fault changed held original descriptor identity")
    final, foreground = events[-1], events[2]
    require(final["callback_count"] == 0 and final["child_reaped_observed"] is True
            and final["pid"] == child["pid"] and final["tracker_pids"] == []
            and final["implicit_shutdown_performed"] is False and final["original_owner_bodies_changed"] is False
            and foreground["tracker_pids"] == [] and foreground["hints"] == [], "original lifecycle/owner effects differ")
    captures = {}
    for stream in STREAMS:
        path = directory / "retained" / (stream + ".bin")
        data = path.read_bytes()
        require(data.hex() == spec[stream + "_hex"] and final["raw_capture"][stream + "_path"] == str(path)
                and final["raw_capture"][stream + "_bytes"] == len(data), "retained original writer bytes differ")
        expect_exists = any(fault["stream"] == stream and fault["op"] == "replace_dir" for fault in spec["faults"])
        require(final["raw_capture"]["source_paths_exist"][stream] is expect_exists, "original discard pathname outcome differs")
        captures[stream] = identity(path)
    wanted = expected_reads(spec)
    error_stream = next((stream for stream in STREAMS if wanted[stream]["errno"]), None)
    if error_stream:
        errno = wanted[error_stream]["errno"]
        message = f"Failed to read command {error_stream}: " + ({2: "No such file or directory", 21: "Is a directory"}[errno]) + f" (os error {errno})"
        require(foreground["ok"] is False and foreground["text"] is None and foreground["error"] == message
                and foreground["os_error_from_message"] == errno and foreground["error_chain"] == [message],
                "original read error precedence or complete result bytes differ")
    else:
        out = bytes.fromhex(wanted["stdout"]["bytes_hex"]).decode().rstrip("\n")
        err = bytes.fromhex(wanted["stderr"]["bytes_hex"]).decode().rstrip("\n")
        message = out + "\n\nstderr:\n" + err
        require(foreground["ok"] is True and foreground["text"] == message and foreground["error"] is None
                and foreground["error_chain"] == [], "complete original literal outcome differs")
    proof = analyze_original_io(directory, prepared, receipt, events, snapshots, mutations)
    proof.update(schema=SCHEMA + ".case-evidence", name=spec["name"], captures=captures,
                 foreground_outcome=foreground, native_execution_compared=False,
                 fresh_original_rust_build_qualified=False, production_shell_execution_qualified=False,
                 whole_runtime_replaced=False)
    retained = directory / "evidence.json"
    if retained.exists():
        require(decode(retained.read_bytes()) == proof, "retained evidence differs from full raw reconstruction")
    return proof


def load_reference(runtime):
    source = Path(runtime) / "scripts/hia_native_shell_process_reference.py"
    spec = importlib.util.spec_from_file_location("shell_output_unchanged_rust_reference", source)
    require(spec is not None and spec.loader is not None, "cannot load original source-bound evidence reader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def version_process(strace, output):
    argv = [str(strace), "-V"]
    started, monotonic = time.time_ns(), time.monotonic_ns()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=output,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate()
    for name, data in (("strace-version.stdout", stdout), ("strace-version.stderr", stderr)):
        (output / name).write_bytes(data)
    value = {"argv": argv, "pid": process.pid, "started_unix_ns": started,
             "finished_unix_ns": time.time_ns(), "duration_ns": time.monotonic_ns() - monotonic,
             "deadline_seconds": 10, "exit_code": process.returncode, "timed_out": timed_out,
             "stdout": identity(output / "strace-version.stdout"),
             "stderr": identity(output / "strace-version.stderr")}
    write_json(output / "strace-version.process.json", value)
    require(process.returncode == 0 and not timed_out and b"strace -- version" in stdout,
            "actual strace version process did not succeed")
    return value


def read_evidence(output, runtime, original_build, *, require_full=True):
    """No subprocess, FFI, live /proc or writes: rebuild every case from raw files."""
    output, runtime, original_build = map(lambda value: Path(value).absolute(), (output, runtime, original_build))
    report = decode((output / "report.json").read_bytes())
    require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
            and report.get("error") is None, "original I/O qualification is incomplete")
    source = identity(Path(__file__).resolve())
    require(report["inputs"]["runner"] == source, "original I/O driver source changed")
    require(report["inputs"]["reference_driver"] == identity(runtime / "scripts/hia_native_shell_process_reference.py")
            and report["inputs"]["original_build"] == identity(original_build / "result.json"),
            "original source-bound build input changed")
    strong = load_reference(runtime).read_evidence(runtime, original_build)
    require(strong["fresh_original_rust_build_qualified"] is True,
            "unchanged original Rust build is not freshly source-qualified")
    oracle = original_build / "target/release/hepta-shell-process-original-oracle"
    require(report["inputs"]["original_executable"] == identity(oracle), "actual original ELF changed")
    strace = Path(report["inputs"]["strace"]["path"])
    require(report["inputs"]["strace"] == identity(strace), "actual trace tool changed")
    require(report["inputs"]["python"] == identity(Path(report["inputs"]["python"]["path"])), "actual controller Python changed")
    version = decode((output / "strace-version.process.json").read_bytes())
    require(version["argv"] == [str(strace), "-V"] and type(version["pid"]) is int and version["pid"] > 0
            and type(version["exit_code"]) is int and version["exit_code"] == 0 and version["timed_out"] is False
            and version["deadline_seconds"] == 10 and 0 < version["duration_ns"] < 10_000_000_000,
            "actual trace tool version receipt differs")
    for stream in STREAMS:
        require(version[stream] == identity(output / ("strace-version." + stream)), "trace tool version stream changed")
    require(b"strace -- version" in (output / "strace-version.stdout").read_bytes(), "missing actual strace version")
    names = report["selected_cases"]
    all_names = [row["name"] for row in io_specs()]
    require(type(names) is list and len(names) == len(set(names)) and names
            and names == [name for name in all_names if name in names], "case set order or identity differs")
    if require_full:
        require(names == all_names and report["full_case_set"] is True, "not all six real original I/O cases ran")
    cases = []
    for name in names:
        evidence = read_case(output / name)
        receipt = decode((output / name / "process.json").read_bytes())
        require(receipt["original_executable"] == report["inputs"]["original_executable"]
                and receipt["strace_executable"] == report["inputs"]["strace"],
                "case process used another original ELF or trace tool")
        cases.append({"name": name, "evidence": identity(output / name / "evidence.json"),
                      "process": identity(output / name / "process.json"),
                      "foreground_outcome": evidence["foreground_outcome"],
                      "trace_files": evidence["trace_files"]})
    require(report["cases"] == cases and report["case_count"] == len(cases), "reported cases differ from exact raw reconstruction")
    return {"schema": SCHEMA + ".readback", "status": "PASS", "case_count": len(cases),
            "full_case_set": names == all_names, "original_tests": strong["original_tests"],
            "fresh_original_rust_build_qualified": True,
            "all_original_io_cases_reconstructed": True,
            "complete_foreground_outcome_and_hints_retained": True,
            "wait_reads_and_discards_from_actual_syscalls": True,
            "native_io_compared": False, "native_wait_executed": False,
            "natural_wait_error_executed": False, "production_shell_execution_qualified": False,
            "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
            "report": identity(output / "report.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--oracle-build", type=Path, required=True)
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", dest="names")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    if args.verify:
        require(not args.names, "verification does not accept a coverage subset")
        result = read_evidence(args.output, args.runtime, args.oracle_build)
        print(json.dumps(result, sort_keys=True))
        return 0
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None,
              "started_at": datetime.now(timezone.utc).isoformat(), "inputs": {}, "cases": [],
              "native_io_compared": False, "native_wait_executed": False,
              "natural_wait_error_executed": False, "production_shell_execution_qualified": False,
              "whole_runtime_replaced": False, "old_stack_removal_qualified": False}
    write_json(output / "initial.json", report)
    start = time.monotonic_ns()
    try:
        require(output.resolve(strict=True) == output, "output has a symlink ancestor")
        runtime = args.runtime.resolve(strict=True)
        require(not output.is_relative_to(runtime), "qualification output must be outside source tree")
        build = args.oracle_build.resolve(strict=True)
        oracle = build / "target/release/hepta-shell-process-original-oracle"
        strace = args.strace.resolve(strict=True)
        report["inputs"] = {"runner": identity(Path(__file__).resolve()),
                            "reference_driver": identity(runtime / "scripts/hia_native_shell_process_reference.py"),
                            "original_build": identity(build / "result.json"),
                            "original_executable": identity(oracle), "strace": identity(strace),
                            "python": identity(Path(sys.executable).resolve())}
        strong = load_reference(runtime).read_evidence(runtime, build)
        require(strong["fresh_original_rust_build_qualified"] is True, "original build failed source qualification")
        report["original_build_evidence"] = strong
        report["host"] = {"uname": list(os.uname()), "libc": os.confstr("CS_GNU_LIBC_VERSION"), "python": sys.version}
        version_process(strace, output)
        specifications = io_specs()
        if args.names:
            require(len(args.names) == len(set(args.names))
                    and set(args.names) <= {row["name"] for row in specifications}, "unknown or repeated selected case")
            specifications = [row for row in specifications if row["name"] in args.names]
        report["selected_cases"] = [row["name"] for row in specifications]
        report["full_case_set"] = len(specifications) == len(io_specs())
        for spec in specifications:
            directory = output / spec["name"]
            prepared = prepare(spec, directory)
            run_case(prepared, oracle, strace)
            evidence = read_case(directory)
            write_json(directory / "evidence.json", evidence)
            report["cases"].append({"name": spec["name"], "evidence": identity(directory / "evidence.json"),
                                    "process": identity(directory / "process.json"),
                                    "foreground_outcome": evidence["foreground_outcome"], "trace_files": evidence["trace_files"]})
            print(json.dumps({"name": spec["name"], "status": "PASS", "trace_files": len(evidence["trace_files"])}), flush=True)
        require(report["inputs"]["runner"] == identity(Path(__file__).resolve())
                and report["inputs"]["original_executable"] == identity(oracle), "inputs changed during execution")
        report["case_count"] = len(report["cases"])
        report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAIL"
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    report["duration_ns"] = time.monotonic_ns() - start
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_json(output / "report.json", report)
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(output, runtime, build, require_full=not bool(args.names))
            write_json(output / "evidence.json", evidence)
        except BaseException as error:
            write_json(output / "before-readback.report.json", report)
            report["status"] = "FAIL"
            report["error"] = {"stage": "final_readback", "type": type(error).__name__,
                               "message": str(error), "traceback": traceback.format_exc()}
            (output / "report.json").write_bytes(encoded(report))
    print(json.dumps({"status": report["status"], "case_count": report.get("case_count", 0),
                      "report": str(output / "report.json"), "error": report["error"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
