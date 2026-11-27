#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain and admit the original detached-strace native execution topology.

This is an external observer. It never constructs a HIA product, changes a
native deadline, or turns execution evidence into whole-stack qualification.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import time


SCHEMA = "hepta.runtime.native-execution-observation.v1"
ENVIRONMENT = {"PATH": "", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
TRACE_OPTIONS = ["/usr/bin/strace", "-D", "-f", "--seccomp-bpf", "-e", "trace=execve,execveat"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def ordinary_stream(path):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            "native execution evidence cannot contain symlinks")
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "native execution evidence must be an ordinary single-link file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        # fdopen can raise from a Python audit hook before taking ownership.
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            require(identity(os.fstat(descriptor)) == identity(before),
                    "native execution evidence changed while opening")
            yield stream
            require(identity(os.fstat(descriptor)) == identity(before)
                    == identity(path.stat(follow_symlinks=False)),
                    "native execution evidence changed while reading")
    finally:
        os.close(descriptor)


def pin(path):
    value, extent = sha256(), 0
    with ordinary_stream(path) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
            extent += len(block)
    return {"bytes": extent, "sha256": value.hexdigest()}


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate native execution receipt key")
            result[key] = value
        return result

    def invalid(value):
        raise RuntimeError("non-JSON native execution receipt number: " + value)

    with ordinary_stream(path) as stream:
        return json.load(stream, object_pairs_hook=unique, parse_constant=invalid)


def command(argv, directory):
    return [*TRACE_OPTIONS, "-o", str(directory / "execution.trace"), "--", *argv]


def trace_summary(path, entry, *, expected_pid=None, required_pids=()):
    """Parse the complete original stream, including paired split syscall lines."""
    pending, terminated, executed = {}, {}, set()
    roots, calls = [], 0
    value, extent = sha256(), 0
    entry_literal = json.dumps(str(entry), ensure_ascii=True)
    with ordinary_stream(path) as stream:
        for raw in stream:
            value.update(raw)
            extent += len(raw)
            require(raw.endswith(b"\n"), "truncated native execution trace line")
            line = raw.decode("ascii").rstrip("\n")
            match = re.fullmatch(r"(?:\[pid\s+)?([0-9]+)(?:\])?\s+(.+)", line)
            require(match is not None, "unrecognized native execution trace line")
            pid, body = int(match[1]), match[2]
            resumed = re.fullmatch(r"<\.\.\. (execve|execveat) resumed>(.*)", body)
            if resumed:
                require(pid in pending and pending[pid][0] == resumed[1],
                        "native execution trace has an unmatched resumed call")
                _, prefix = pending.pop(pid)
                body = prefix + resumed[2]
            if body.startswith(("execve(", "execveat(")):
                require(pid not in pending and pid not in terminated,
                        "native execution trace reuses an incomplete or terminal process")
                kind = body.split("(", 1)[0]
                if body.endswith("<unfinished ...>"):
                    pending[pid] = (kind, body[:-len("<unfinished ...>")])
                    continue
                require(re.search(r"\)\s+=\s+(?:0|-1 [A-Z0-9_]+ \([^\n]*\))$", body),
                        "native execution trace has an incomplete syscall result")
                executed.add(pid)
                if kind == "execve":
                    require(body.startswith("execve(" + entry_literal + ", ")
                            and re.search(r"\)\s+=\s+0$", body),
                            "native execution trace contains a foreign path executable")
                    roots.append(pid)
                else:
                    require(re.match(r'^execveat\([0-9]+, "", ', body)
                            and re.search(r", AT_EMPTY_PATH\s*\)\s+=", body),
                            "native descendants must execute through empty-path descriptors")
                    calls += 1
            elif body.startswith("+++"):
                terminal = re.fullmatch(r"\+\+\+ (exited with ([0-9]+)|killed by [A-Z0-9]+(?: \(core dumped\))?) \+\+\+", body)
                require(terminal is not None and pid not in pending and pid not in terminated,
                        "native execution trace has an invalid or incomplete terminal process")
                terminated[pid] = int(terminal[2]) if terminal[2] is not None else None
            else:
                require(body.startswith("--- SIG") and body.endswith(" ---"),
                        "unexpected event in native execution-only trace")
    require(not pending and len(roots) == 1 and terminated.get(roots[0]) == 0
            and executed <= terminated.keys(),
            "native execution trace lacks one complete successful entry and terminal descendants")
    require(expected_pid is None or roots[0] == expected_pid,
            "native execution trace entry PID differs from the waited child")
    require(set(required_pids) <= executed,
            "native execution trace does not contain the retained native owner")
    return {"bytes": extent, "sha256": value.hexdigest(), "entry_pid": roots[0],
            "execve": 1, "execveat": calls, "executed_processes": len(executed),
            "terminal_processes": len(terminated)}


def admit_execution(directory, *, source, stage, expected_argv, expected_entry,
                    expected_result=None, owner_receipt=None):
    directory = Path(directory).absolute()
    receipt = read_json(directory / "observation.json")
    argv = receipt.get("argv")
    require(type(expected_argv) is list and bool(expected_argv)
            and all(type(item) is str for item in expected_argv) and Path(expected_argv[0]).is_absolute()
            and type(expected_entry) is dict and set(expected_entry) == {"bytes", "sha256"},
            "native execution admission requires independently selected argv and entry identity")
    require(argv == expected_argv, "native execution receipt argv differs from its trusted invocation")
    require(receipt.get("schema") == SCHEMA and receipt.get("status") == "OBSERVED_NATIVE_EXECUTION_PASS"
            and receipt.get("source_commit") == source and receipt.get("stage") == stage
            and receipt.get("trace_argv") == command(argv, directory)
            and receipt.get("environment") == ENVIRONMENT
            and type(receipt.get("returncode")) is int and receipt["returncode"] == 0
            and type(receipt.get("pid")) is int and receipt["pid"] > 0
            and receipt.get("observed_entry_process_terminal") is True
            and receipt.get("observer_timeout") is False
            and receipt.get("observer_termination_requests") == []
            and receipt.get("observer") == pin(__file__)
            and receipt.get("whole_stack_native") is False,
            "native execution receipt is incomplete or belongs to another source/topology")
    require(receipt.get("entry") == expected_entry == pin(expected_argv[0]),
            "native entry differs from its independently admitted tool identity")
    for name in ("stdout", "stderr"):
        require(receipt.get(name) == pin(directory / name), "native execution stream changed: " + name)
    require(receipt["stderr"]["bytes"] == 0, "native execution wrote stderr or tracer diagnostics")
    required_pids = []
    if owner_receipt is not None:
        with ordinary_stream(owner_receipt) as stream:
            owner = stream.read(1024 * 1024 + 1)
        require(256 <= len(owner) <= 1024 * 1024 and owner[:8] == b"HIACOR01",
                "native execution owner receipt is missing or oversized")
        words = struct.unpack_from("<32Q", owner)
        require(words[1] == 0 and words[3] == receipt["pid"] and words[2] > 0
                and len({words[2], words[3], words[8]}) == 3
                and len(owner) == 256 + words[16] * 40 + words[18] * 48
                and words[6:8] == (180, 3000000000) and words[8] >= 2
                and words[9] == 0 and words[11:14] == (1, 1, 1)
                and words[10] == words[14] == words[15] == words[17] == 0
                and words[21] == 0 and words[22] == 1 and words[24] == 0
                and words[16] <= 16384 and words[18] <= 4096
                and words[25:32] == (4096, 16384, 65536, 1, 0, 0, 0)
                and words[5] == words[4] + 180000000000
                and words[4] <= words[19] <= words[5]
                and words[20] == words[19] + 3000000000
                and words[19] <= words[23] <= words[20],
                "native owner does not bind the observed successful entry process")
        required_pids.extend((words[2], words[8]))
    parsed = trace_summary(directory / "execution.trace", expected_argv[0],
                           expected_pid=receipt["pid"], required_pids=required_pids)
    require(receipt.get("trace") == parsed
            and receipt.get("trace_raw") == {key: parsed[key] for key in ("bytes", "sha256")}
            and parsed["execveat"] > 0,
            "native execution trace changed or contains no native descendants")
    if expected_result is not None:
        expected_result = Path(expected_result).absolute()
        require(receipt.get("result_path") == str(expected_result)
                and receipt.get("result") == pin(expected_result) == receipt["stdout"],
                "native execution is not bound to the retained result bytes")
    return {"observation": pin(directory / "observation.json"), "trace": parsed,
            "entry": receipt["entry"], "stdout": receipt["stdout"], "source_commit": source,
            "stage": stage, "argv": expected_argv, "whole_stack_native": False}


def observe(argv, *, directory, source, stage, timeout, result=None):
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    require(re.fullmatch(r"[0-9a-f]{40}", source), "execution requires an exact source commit")
    require(argv and Path(argv[0]).is_absolute(), "execution requires an absolute native entry")
    require(result is None or not Path(result).exists(), "native result must be produced by this execution")
    with ordinary_stream(argv[0]) as stream:
        header = stream.read(64)
    require(header[:5] == b"\x7fELF\x02" and 64 <= Path(argv[0]).stat().st_size <= 64 * 1024 * 1024,
            "native entry must be a bounded ELF64 executable")
    row = {"schema": SCHEMA, "status": "HOLD", "source_commit": source, "stage": stage,
           "argv": argv, "trace_argv": command(argv, directory), "environment": dict(ENVIRONMENT),
           "entry": pin(argv[0]), "whole_stack_native": False,
           "observer": pin(__file__),
           "observer_timeout": False, "observer_termination_requests": [],
           "observer_timeout_seconds": timeout, "observed_entry_process_terminal": False}
    if result is not None:
        row["result_path"] = str(Path(result).absolute())
    def save():
        (directory / "observation.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    child, started = None, time.monotonic_ns()
    save()
    try:
        with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
            child = subprocess.Popen(row["trace_argv"], stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, env=ENVIRONMENT, start_new_session=True)
            row["pid"] = child.pid
            save()
            try:
                child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["observer_timeout"] = True
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    row["observer_termination_requests"].append(sig.name)
                    try:
                        os.killpg(child.pid, sig)
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=3)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                raise
        row.update(returncode=child.returncode, observed_entry_process_terminal=child.returncode is not None)
        require(child.returncode == 0, "native entry returned failure")
        require(pin(directory / "stderr")["bytes"] == 0, "native entry or tracer wrote stderr")
        require(pin(argv[0]) == row["entry"], "native entry changed during execution")
        row["trace"] = trace_summary(directory / "execution.trace", argv[0], expected_pid=child.pid)
        if result is not None:
            row["result"] = pin(result)
            require(row["result"] == pin(directory / "stdout"), "native stdout differs from its retained result")
        row["status"] = "OBSERVED_NATIVE_EXECUTION_PASS"
    except BaseException as exc:
        row["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        row.update(elapsed_ns=time.monotonic_ns() - started,
                   returncode=None if child is None else child.poll(),
                   observed_entry_process_terminal=child is not None and child.returncode is not None)
        for name in ("stdout", "stderr", "execution.trace"):
            if (directory / name).exists():
                try:
                    row["trace_raw" if name == "execution.trace" else name] = pin(directory / name)
                except Exception as exc:
                    row.setdefault("evidence_errors", {})[name] = str(exc)
                    row["status"] = "HOLD"
        save()
    require(row["status"] == "OBSERVED_NATIVE_EXECUTION_PASS", "native execution evidence remains incomplete")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--stage", choices=("prebuild", "cold", "post", "release"), required=True)
    parser.add_argument("--result", type=Path)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    require(args.argv and args.argv[0] == "--", "native invocation must follow --")
    row = observe(args.argv[1:], directory=args.output, source=args.source_commit,
                  stage=args.stage, timeout=1830 if args.stage == "release" else 360,
                  result=args.result)
    print(json.dumps({"status": row["status"], "returncode": row["returncode"],
                      "observation": str(args.output / "observation.json")}))


if __name__ == "__main__":
    main()
