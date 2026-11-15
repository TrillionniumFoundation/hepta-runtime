"""Read real shell-process evidence without executing a process or HIA image.

Only current repository code supplies parsers and registered cases. Evidence
snapshots are hashed as bytes, never imported. Retained case paths may move;
native/original build identities and current source paths are checked strongly.
"""
from __future__ import annotations

import argparse
import ctypes  # Import before the optional read-only audit rejects new FFI loads.
from datetime import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/hia_native/shell_process_cases.py"
RUNNER = ROOT / "scripts/hia_native_shell_process_qualification.py"
BUILDER = ROOT / "scripts/hia_native_shell_process_build.py"
REFERENCE = ROOT / "scripts/hia_native_shell_process_reference.py"
PINNED_COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
BORROWED_ABI = "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
MASK = (1 << 64) - 1
SCOPE = {
    "matching_source_full_cold_qualified": False,
    "production_activated": False,
    "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False,
}


class EvidenceError(ValueError):
    pass


class ReadOnlyViolation(RuntimeError):
    pass


def require(test, message: str) -> None:
    if not test:
        raise EvidenceError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def integer(value, minimum=0, maximum=None) -> bool:
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def strict_json(raw: bytes, *, floats: bool = False):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def number(value):
        require(floats, "unexpected non-integer JSON number")
        parsed = float(value)
        require(math.isfinite(parsed), "non-finite JSON number")
        return parsed
    def constant(value):
        raise EvidenceError("non-finite JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)


def raw_file(path: Path) -> bytes:
    require(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode),
            "evidence member is not an ordinary file: " + str(path))
    require(path.resolve(strict=True) == path.absolute(),
            "evidence path contains a symlink: " + str(path))
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "evidence member changed while read")
    return raw


def shape_pin(value, *, path: bool = True, nonempty: bool = False) -> bool:
    keys = {"size", "sha256"} | ({"path"} if path else set())
    return (type(value) is dict and set(value) == keys
            and integer(value.get("size"), 1 if nonempty else 0)
            and type(value.get("sha256")) is str
            and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None
            and (not path or type(value.get("path")) is str and canonical(value["path"])))


def canonical(value: str) -> bool:
    return (type(value) is str and value.startswith("/")
            and str(Path(value)) == value
            and all(part not in (".", "..") for part in Path(value).parts))


def file_pin(path: Path, declared: Path | str | None = None) -> dict:
    raw = raw_file(path)
    return {"path": str(path if declared is None else declared),
            "size": len(raw), "sha256": sha(raw)}


def check_pin(path: Path, expected, declared: Path | str | None = None) -> bytes:
    require(shape_pin(expected), "malformed file identity")
    require(file_pin(path, declared) == expected, "file identity differs: " + str(path))
    return raw_file(path)


def load_current(path: Path, name: str):
    require(path in (CASES, RUNNER, BUILDER, REFERENCE), "unregistered source module")
    before = raw_file(path)
    spec = importlib.util.spec_from_file_location("shell_process_evidence_" + name, path)
    require(spec is not None and spec.loader is not None, "cannot load current helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(raw_file(path) == before, "current helper changed during admission")
    return module


def native_binding(manifest: Path) -> tuple[dict, Path, dict]:
    manifest = manifest.absolute()
    raw = raw_file(manifest)
    metadata = strict_json(raw)
    require(type(metadata) is dict and metadata.get("schema") == "hepta.runtime.shell-process.v1",
            "wrong native build schema")
    require(metadata.get("compiler_commit") == PINNED_COMPILER
            and metadata.get("target") == "linux-x86_64"
            and metadata.get("elf") == "shell-process.elf"
            and type(metadata.get("compiler_sha256")) is str
            and re.fullmatch("[0-9a-f]{64}", metadata["compiler_sha256"]) is not None,
            "native compiler/target identity differs")
    builder = load_current(BUILDER, "builder")
    portable = builder.read_evidence(manifest)
    require(portable.get("status") == "PASS", "native retained build evidence failed")
    evidence = strict_json(raw_file(manifest.parent / metadata["build_evidence"]))
    for relative in builder.INPUTS + builder.PRODUCERS:
        source = ROOT / relative
        expected = evidence["source_files"][relative]
        require(shape_pin(expected, path=False, nonempty=True),
                "malformed sealed native source identity")
        require({"size": len(raw_file(source)), "sha256": sha(raw_file(source))} == expected,
                "current compiled input or build producer differs: " + relative)
    for name in ("as", "objcopy"):
        receipt = strict_json(raw_file(manifest.parent / ("tools/" + name + ".json")))
        require(shape_pin(receipt.get("tool_before"), path=False, nonempty=True)
                and receipt["tool_before"] == receipt.get("tool_after"),
                "assembler tool identity is not a complete file pin")
    for name in ("owner", "packer"):
        relative = metadata[name + "_manifest"]
        require(type(relative) is str and not relative.startswith("/")
                and all(x not in ("", ".", "..") for x in relative.split("/")),
                "unsafe native component member")
        component = strict_json(raw_file(manifest.parent.parent / relative))
        require(component.get("abi") == BORROWED_ABI
                and component.get("target") == "linux-x86_64"
                and component.get("compiler_commit") == PINNED_COMPILER
                and component.get("compiler_sha256") == metadata["compiler_sha256"],
                "component ABI/compiler differs")
    executable = manifest.parent / "shell-process.elf"
    require(sha(raw_file(executable)) == metadata["elf_sha256"], "current native ELF differs")
    return metadata, executable, portable


def prepared_value(definition: dict, directory: str, module) -> dict:
    require(canonical(directory), "recorded case directory is not canonical")
    base = Path(directory)
    work = base / "work"
    cwd = os.fsencode(work)
    suffix = {"missing": b"/missing", "plain": b"/plain",
              "nul": b"/invalid\0tail", "raw": b"/raw-\xff-\xfe"}
    if definition.get("cwd"):
        require(definition["cwd"] in suffix, "unknown registered cwd variant")
        cwd += suffix[definition["cwd"]]
    command = ((module.GATE_PREFIX if definition["gate"] else "") + definition["body"]).encode()
    ready = base / "capture.ready"
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "USER": "hepta-fixture", "HOME": str(work), "TMPDIR": str(base / "tmp"),
        module.GATE_ENV: str(ready),
    }
    environment.update(definition["env"])
    for key in definition["remove_env"]:
        environment.pop(key, None)
    return {
        "schema": module.SCHEMA, "name": definition["name"], "definition": definition,
        "command_hex": command.hex(), "cwd_hex": cwd.hex(), "environment": environment,
        "ready_path": str(ready), "directory": directory,
        "timeout_ms": module.PRODUCTION_TIMEOUT_MS,
    }


def proc_identity(value, parent: int, child: int | None = None) -> dict:
    require(type(value) is dict and set(value) == {
        "pid", "state", "ppid", "pgid", "sid", "starttime_ticks", "raw_stat"
    }, "recorded proc identity schema differs")
    pid, raw = value["pid"], value["raw_stat"]
    require(integer(pid, 1) and (child is None or pid == child)
            and type(raw) is str and raw.startswith(str(pid) + " (") and ") " in raw,
            "recorded proc PID is not bound to its original bytes")
    fields = raw[raw.rfind(") ") + 2:].split()
    require(len(fields) >= 20, "recorded proc stat is incomplete")
    decoded = {
        "pid": pid, "state": fields[0], "ppid": int(fields[1]), "pgid": int(fields[2]),
        "sid": int(fields[3]), "starttime_ticks": int(fields[19]), "raw_stat": raw,
    }
    require(decoded == value and value["ppid"] == parent
            and integer(value["starttime_ticks"], 0), "original child PPID/starttime binding differs")
    return value


def process_receipt(receipt: dict, prepared: dict, side: str, executable: dict,
                    actual: Path, declared: Path) -> dict:
    schema = ("hepta.runtime.shell-process-real-native.v1" if side == "native"
              else "hepta.runtime.shell-process-original-controller.v1")
    require(type(receipt) is dict and receipt.get("schema") == schema,
            "process receipt schema differs")
    argv = ([executable["path"], "--process-fixture", str(declared / "capture")]
            if side == "native" else [executable["path"], "--fixture"])
    require(receipt.get("argv") == argv and receipt.get("cwd") == prepared["directory"]
            and receipt.get("environment") == prepared["environment"]
            and receipt.get("executable") == executable,
            "actual process executable, argv, cwd or controlled environment differs")
    require(integer(receipt.get("pid"), 1) and receipt.get("exit_code") == 0
            and receipt.get("timed_out") is False and receipt.get("exception") is None
            and receipt.get("cleanup") == [], "process did not complete without failure containment")
    require(integer(receipt.get("duration_ns"), 1)
            and receipt.get("deadline_seconds") == prepared["definition"]["deadline_seconds"]
            and receipt["duration_ns"] <= (receipt["deadline_seconds"] + 1) * 1_000_000_000,
            "actual process duration/deadline differs")
    require(type(receipt.get("started_at")) is str
            and datetime.fromisoformat(receipt["started_at"]).tzinfo is not None,
            "process start timestamp is missing")
    files = ({"stdin": "stdin.bin", "stdout": "fixture.stdout", "stderr": "fixture.stderr"}
             if side == "native" else {"stdin": "stdin.jsonl", "stdout": "stdout.jsonl", "stderr": "stderr"})
    require(type(receipt.get("streams")) is dict and set(receipt["streams"]) == set(files),
            "process stream inventory differs")
    streams = {name: check_pin(actual / path, receipt["streams"][name], declared / path)
               for name, path in files.items()}
    require(streams["stderr"] == b"", "process wrote unqualified diagnostics")
    identities = receipt.get("observed_child_identities")
    require(type(identities) is list and len({x["pid"] for x in identities}) == len(identities),
            "duplicate or malformed child observations")
    for identity in identities:
        proc_identity(identity, receipt["pid"])
    return streams


def controls(receipt: dict, prepared: dict, module, *, original: bool) -> bytes:
    case = prepared["definition"]
    if original:
        request = {
            "op": "execute", "command": bytes.fromhex(prepared["command_hex"]).decode(),
            "cwd_hex": prepared["cwd_hex"], "timeout_ms": prepared["timeout_ms"],
            "capture_dir": str(Path(prepared["directory"]) / "original/retained"),
        }
        initial = (json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    else:
        initial = module.frame(1, bytes.fromhex(prepared["command_hex"]), bytes.fromhex(prepared["cwd_hex"]))
    recorded = receipt.get("controls")
    require(type(recorded) is list, "control receipt is not a list")
    control = case.get("control")
    require(len(recorded) == int(control is not None), "missing, duplicate or unsolicited control")
    if not control:
        return initial
    operation = "cancel" if control.startswith("cancel") else "shutdown"
    if original:
        payload = (json.dumps({"op": operation}, separators=(",", ":")) + "\n").encode()
        wanted = {"operation": operation, "input_hex": payload.hex()}
    else:
        operation = 3 if operation == "cancel" else 4
        payload = module.frame(operation)
        wanted = {"operation": operation, "frame_hex": payload.hex()}
    row = recorded[0]
    require(type(row) is dict and set(row) == set(wanted) | {"elapsed_ns"}
            and all(row[k] == v for k, v in wanted.items())
            and integer(row["elapsed_ns"], 0, receipt["duration_ns"]),
            "actual control bytes or timing differ")
    return initial + payload


def native_frames(raw: bytes, recorded, receipt: dict, runner, module) -> list:
    cursor, parsed = runner.decode_frames(bytearray(raw), 0, module)
    require(cursor == len(raw) and type(recorded) is list and len(recorded) == len(parsed),
            "incomplete or extra native output")
    last_time = -1
    for expected, observed in zip(parsed, recorded):
        require(type(observed) is dict and set(observed) == set(expected) | {"observed_elapsed_ns"},
                "recorded native frame shape differs")
        require({k: v for k, v in observed.items() if k != "observed_elapsed_ns"} == expected,
                "frames.json differs from complete actual native stdout")
        stamp = observed["observed_elapsed_ns"]
        require(integer(stamp, 0, receipt["duration_ns"]) and stamp >= last_time,
                "native frame observation timing is inconsistent")
        last_time = stamp
    return recorded


def check_trace(trace: dict, receipt: dict, prepared: dict, frames: list) -> dict:
    """Validate separate process orders and actual kernel return evidence."""
    rows, footer = trace["records"], trace["footer"]
    require(footer is not None and trace["trailing_bytes"] == 0, "native audit is not complete")
    parent = receipt["pid"]
    case = prepared["definition"]
    forks = [r for r in rows if r["role"] == 1 and r["self_pid"] == parent
             and r["action"] == 5 and r["phase"] == 1]
    expect_fork = not case.get("spawn_invalid_input", False)
    require(len(forks) == int(expect_fork), "actual fork inventory differs")
    child = forks[0]["result"] if forks else 0
    require(not child or integer(child, 1) and child != parent, "actual child PID is invalid")
    for row in rows:
        require(row["role"] in (0, 1, 2) and row["phase"] in (0, 1)
                and row["action"] in range(1, 20) and row["child_token"] == 1
                and integer(row["sequence"], 1), "audit role/action/token/sequence differs")
        require(row["self_pid"] == (child if row["role"] == 2 else parent)
                and row["child_pid"] == (0 if row["role"] == 0 else child),
                "audit PID is not bound to the owned process")
        require(row["ownership_flags"] & ~31 == 0, "unknown ownership flag")
        if row["role"] == 0:
            require(row["action"] in (1, 2, 3, 4, 5), "post-fork effect has pre-fork role")
        elif row["role"] == 1:
            require(row["action"] in (5, 6, 13, 14, 15, 16, 17, 18, 19),
                    "parent attempted a child-only effect")
        else:
            require(row["action"] in (5, 6, 7, 8, 9, 10, 11, 12)
                    and row["ownership_flags"] == 0, "child effect/custody differs")
        action = row["action"]
        args = (row["arg0"], row["arg1"], row["arg2"])
        if action in (3, 4, 5, 9, 10, 13, 15, 19):
            require(args == (0, 0, 0), "unused fixed effect argument is nonzero")
        elif action == 1:
            require(args == (1, 0, 0), "capture admission token differs")
        elif action == 2:
            require(args[0] >= 4096 and args[1] >= 8 and args[2] == 0,
                    "environment snapshot span differs")
        elif action == 6:
            require(args == (row["role"], 0, 0), "post-fork close role differs")
        elif action == 7:
            require(args[0] in (0, 1, 2) and args[1:] == (0, 0), "stdio destination differs")
        elif action == 8:
            require(args[0] >= 4096 and args[1] == len(bytes.fromhex(prepared["cwd_hex"]))
                    and args[2] == 0, "child cwd effect differs")
        elif action == 11:
            require(args[0] >= 4096 and args[1] > 0 and args[2] == 512,
                    "exec plan span differs")
        elif action == 12:
            require(args[0] <= 4095 and args[1:] == (0, 0), "NOEX errno payload differs")
        elif action in (14, 16):
            require(args[0] == 1 and args[1] in (0, 1) and args[2] == 0,
                    "tracker/wait owned token differs")
        elif action == 17:
            require(args[0] == 1 and args[2] == 0, "wakeup owned token differs")
        elif action == 18:
            require(args[0] == 1 and args[1] in (1, 2) and args[2] == 9,
                    "fixed signal ownership/number differs")
        if row["phase"] == 0:
            require((row["result"], row["errno"], row["aux"], row["raw_aux"]) == (0, 0, 0, 0),
                    "issued effect contains forged completion data")

    process_rows = [[r for r in rows if r["self_pid"] == parent]]
    if child:
        process_rows.append([r for r in rows if r["self_pid"] == child])
    parent_completed, child_terminal = [], None
    for index, stream in enumerate(process_rows):
        last_sequence, pending = 0, None
        for row in stream:
            if index == 1 and last_sequence == 0:
                require(row["action"] == 5 and row["phase"] == 1
                        and row["sequence"] == forks[0]["sequence"]
                        and (row["result"], row["errno"], row["aux"], row["raw_aux"]) == (0, 0, 1, 0),
                        "child lacks its exact fork completion")
                last_sequence = row["sequence"]
                continue
            if row["phase"] == 0:
                require(pending is None and row["sequence"] == last_sequence + 1,
                        "effect issuance is duplicated, missing or out of order")
                pending = row
                last_sequence = row["sequence"]
            else:
                require(pending is not None
                        and all(row[key] == pending[key] for key in (
                            "sequence", "action", "arg0", "arg1", "arg2")),
                        "effect completion has no matching issued operation")
                pending = None
                if index == 0:
                    parent_completed.append(row)
        if index == 0:
            require(pending is None, "parent retired with an uncompleted effect")
        else:
            require(pending is not None and pending["action"] in (11, 12),
                    "child neither execed nor sent its NOEX terminal effect")
            child_terminal = pending

    starts = [r["action"] for r in process_rows[0] if r["phase"] == 0]
    require(starts[:5] == [1, 2, 3, 4, 5] if child else starts == [1],
            "original spawn admission/setup order differs")
    if child:
        child_rows = process_rows[1]
        child_issued = [r for r in child_rows if r["phase"] == 0]
        prefix = [r["action"] for r in child_issued]
        require(prefix[:5] == [6, 7, 7, 7, 8]
                and [r["arg0"] for r in child_issued[1:4]] == [0, 1, 2],
                "child stdio/chdir effect order differs")
        if case.get("cwd") not in ("missing", "plain"):
            require(prefix[5:7] == [9, 10], "child signal/setsid effect order differs")
        for row in child_rows:
            if row["phase"] != 1 or row["action"] == 5:
                continue
            action, result, error, aux, raw = (
                row[k] for k in ("action", "result", "errno", "aux", "raw_aux")
            )
            if error:
                require(action in (7, 8, 9, 10, 11) and error <= 4095
                        and (result, aux, raw) == (0, 0, (-error) & MASK),
                        "child syscall errno differs from its raw kernel return")
            elif action == 10:
                require((result, aux, raw) == (child, 0, child), "setsid returned a different session")
            elif action == 7:
                require((result, aux, raw) == (0, 0, row["arg0"]), "dup2 raw result differs")
            else:
                require(action in (6, 8, 9) and (result, aux, raw) == (0, 0, 0),
                        "unexpected child syscall success completion")
    flags, actual_reaps, clock_values = 0, [], []
    for row in process_rows[0]:
        if row["phase"] == 0:
            require(row["ownership_flags"] == flags, "issued ownership flags differ")
            if row["action"] == 18:
                require(flags & 1, "signal targeted a retired PID")
            continue
        action, result, error, aux, raw = (row[k] for k in ("action", "result", "errno", "aux", "raw_aux"))
        if action == 5:
            require((result, error, aux, raw) == (child, 0, 1, child), "actual parent fork return differs")
            flags |= 1
        elif action == 13:
            require(result in (0, 1) and aux == 0 and error <= 4095
                    and raw == (0 if result == 0 else 8)
                    and (result != 0 or error == 0), "exec EOF/NOEX raw handshake differs")
            flags |= (result + 1) << 3
        elif action == 14:
            require((result, error, aux, raw) == (0, 0, 0, 0), "tracker completion differs")
            flags = flags | 2 if row["arg1"] else flags & ~2
        elif action == 16:
            require(error == 0 and result in (0, 1) and aux <= 0xffffffff,
                    "unexpected wait error/result in successful registered case")
            if result == 0:
                require(aux == 0 and raw == 0, "pending wait reports a child exit")
            else:
                require(raw in (0, child), "wait returned a different PID")
                if raw == child:
                    require(flags & 1, "actual reap occurred after custody was retired")
                    actual_reaps.append(row)
                flags &= ~1
        elif action == 19:
            require((result, error, aux, raw) == (0, 0, 0, 0), "setup close completion differs")
            flags |= 4
        elif action == 15:
            require(result > 0 and (error, aux, raw) == (0, 0, 0), "monotonic clock result differs")
            clock_values.append(result)
        elif action == 2:
            required = 8 + sum(10 + len(os.fsencode(k)) + len(os.fsencode(v))
                               for k, v in prepared["environment"].items())
            require((result, error, aux, raw) == (required, 0, 0, 0),
                    "complete controlled environment snapshot size differs")
        elif action == 3:
            require((result, error, aux) == (0, 0, 0) and 3 <= raw < 1 << 31,
                    "private null FD was not normalized above stdio")
        elif action == 17:
            require((result, error, aux) == (0, 0, 0) and raw <= 3, "wakeup kernel result differs")
        else:
            require((result, error, aux, raw) == (0, 0, 0, 0),
                    "fixed parent operation completion differs")
        require(row["ownership_flags"] == flags, "completed ownership flags differ")
    require(len(actual_reaps) == int(bool(child)), "missing, duplicate or cached-only reap proof")
    require(clock_values == sorted(clock_values), "monotonic clock moved backwards")
    if 3 in case["expected_kinds"]:
        require(clock_values and clock_values[-1] - clock_values[0] >= 10_000_000_000,
                "promotion lacks the actual production foreground interval")
    if child:
        handshake = [r for r in parent_completed if r["action"] == 13]
        require(len(handshake) == 1, "exec handshake count differs")
        if "spawn_errno" in case:
            require(handshake[0]["result"] == 1 and handshake[0]["errno"] == case["spawn_errno"]
                    and child_terminal["action"] == 12
                    and child_terminal["arg0"] == case["spawn_errno"],
                    "spawn error differs from exact child NOEX and parent handshake")
        else:
            require(handshake[0]["result"] == 0 and child_terminal["action"] == 11,
                    "ordinary execution did not reach the same execed child")
        for event in [r["event"] for r in frames if "event" in r and r["event"]["kind"] in (2, 4)]:
            require(event["wait_status"] == actual_reaps[0]["aux"],
                    "final event status differs from actual kernel wait")
    for identity in receipt["observed_child_identities"]:
        proc_identity(identity, parent, child)
    audit = footer["words"]
    require(audit[12] == 0, "explicit registered input unexpectedly closed stdin")
    return {"actual_reaps": len(actual_reaps), "child_pid": child,
            "effect_records": len(rows), "separate_process_orders_checked": True}

def original_events(raw: bytes, recorded, receipt: dict, prepared: dict) -> list[dict]:
    require(raw.endswith(b"\n") and raw, "original JSONL is incomplete")
    lines = raw[:-1].split(b"\n")
    require(all(line and line == line.strip() for line in lines), "empty/ambiguous original JSONL line")
    events = [strict_json(line) for line in lines]
    require(events == recorded, "events.json differs from the complete original stdout JSONL")
    allowed = {"started", "capture_ready", "foreground", "promoted", "completion",
               "cancelled", "shutdown", "final"}
    last_elapsed = -1
    for sequence, event in enumerate(events, 1):
        require(type(event) is dict
                and event.get("schema") == "hepta.runtime.shell-process-fixture-event.v1"
                and event.get("event") in allowed and event.get("oracle_pid") == receipt["pid"]
                and type(event.get("seq")) is int and event["seq"] == sequence,
                "original event schema, PID or sequence differs")
        elapsed = event.get("elapsed_ns")
        require(integer(elapsed, 0, receipt["duration_ns"]) and elapsed >= last_elapsed
                and integer(event.get("unix_ns"), 1), "original event time evidence differs")
        for key in ("callback_count", "exit_code", "exit_code_from_owner_result",
                    "os_error_from_message", "pid", "timeout_ms"):
            if event.get(key) is not None:
                require(type(event[key]) is int, "original typed integer field differs: " + key)
        last_elapsed = elapsed
    require(events and events[0]["event"] == "started"
            and sum(x["event"] == "started" for x in events) == 1
            and events[-1]["event"] == "final"
            and sum(x["event"] == "final" for x in events) == 1,
            "original stream lacks unique initial/final events")
    initial = events[0]
    require(initial.get("command_hex") == prepared["command_hex"]
            and initial.get("cwd_hex") == prepared["cwd_hex"]
            and initial.get("timeout_ms") == prepared["timeout_ms"]
            and initial.get("capture_dir") == str(Path(prepared["directory"]) / "original/retained")
            and initial.get("owner_entry") == "unchanged execute_with_timeout",
            "original announced a different request")
    capture = [x for x in events if x["event"] == "capture_ready"]
    require(len(capture) <= 1, "original capture ownership changed")
    if capture:
        ready = capture[0]
        pid = ready.get("pid")
        require(integer(pid, 1) and pid != receipt["pid"]
                and ready.get("stdin_link_hex") == b"/dev/null".hex()
                and ready.get("tracker_pids") == [pid], "original child admission differs")
        raw_stat = ready.get("initial_proc_stat")
        require(type(raw_stat) is str and raw_stat.startswith(str(pid) + " (")
                and ") " in raw_stat, "original initial proc stat is missing")
        fields = raw_stat[raw_stat.rfind(") ") + 2:].split()
        require(len(fields) >= 20 and int(fields[1]) == receipt["pid"]
                and int(fields[2]) == pid and int(fields[3]) == pid,
                "original child session, group or parent differs")
        observed = receipt["observed_child_identities"]
        require(len(observed) == 1 and observed[0]["pid"] == pid
                and observed[0]["starttime_ticks"] == int(fields[19]),
                "original capture is not bound to the observed child starttime")
        proc_identity(observed[0], receipt["pid"], pid)
        for stream in ("stdout", "stderr"):
            expected_capture = str(Path(prepared["directory"]) / "original/retained" / (stream + ".bin"))
            expected_source = str(Path(prepared["directory"]) / "tmp" /
                                  ("octofs-jobs-" + str(receipt["pid"])) /
                                  (str(receipt["pid"]) + "-1." + stream + ".log"))
            require(ready.get(stream + "_capture_path") == expected_capture
                    and ready.get(stream + "_source_path") == expected_source,
                    "original log path is outside its exact owned fixture")
    else:
        require(receipt["observed_child_identities"] == [], "original had unannounced child custody")
    # The gate is released only after the controller receives capture_ready.
    # Result and control causality is checked without inventing a total order
    # between the background callback thread and the main-loop acknowledgements.
    case = prepared["definition"]
    if case["gate"] and capture:
        ready_sequence = capture[0]["seq"]
        require(all(ready_sequence < row["seq"] for row in events
                    if row["event"] in ("foreground", "completion")),
                "gated owner completed before capture_ready released its input")
    control = case.get("control")
    if control is not None:
        kind = "cancelled" if control.startswith("cancel") else "shutdown"
        acknowledgements = [row for row in events if row["event"] == kind]
        if control.endswith("after_ready"):
            require(len(capture) == 1 and all(capture[0]["seq"] < row["seq"] for row in acknowledgements),
                    "ready-triggered control preceded capture_ready")
        elif control.endswith("after_promotion"):
            promotion = [row for row in events if row["event"] == "promoted"]
            require(len(promotion) == 1 and all(promotion[0]["seq"] < row["seq"] for row in acknowledgements),
                    "background control preceded the observed promotion acknowledgement")
        if control == "shutdown_after_ready":
            foreground = [row for row in events if row["event"] == "foreground"]
            require(len(acknowledgements) == len(foreground) == 1
                    and acknowledgements[0]["seq"] < foreground[0]["seq"],
                    "foreground result preceded its synchronous shutdown acknowledgement")
    return events


def session_projection(raw: bytes, pid: int) -> bytes:
    lines = raw.splitlines()
    require(len(lines) == 2 and lines[0] == str(pid).encode(), "session capture names a different shell")
    observed = strict_json(lines[1])
    require(type(observed) is dict and set(observed) == {"pid", "ppid", "pgid", "sid"}
            and all(integer(v, 1) for v in observed.values())
            and observed["pid"] != pid
            and all(observed[k] == pid for k in ("ppid", "pgid", "sid")),
            "session projection changed a non-PID relationship")
    return b"SHELL_PID\n" + json.dumps({
        "pid": "PROBE_PID", "ppid": "SHELL_PID", "pgid": "SHELL_PID", "sid": "SHELL_PID"
    }, sort_keys=True).encode() + b"\n"


def original_projection(prepared: dict, native: dict, events: list, receipt: dict,
                        actual: Path, declared: Path, captures: dict) -> tuple[dict, dict]:
    case = prepared["definition"]
    groups = {kind: [e for e in events if e["event"] == kind]
              for kind in ("foreground", "promoted", "completion", "cancelled", "shutdown", "capture_ready")}
    foreground, promoted, completed, cancelled, shut, ready = (
        groups[k] for k in ("foreground", "promoted", "completion", "cancelled", "shutdown", "capture_ready")
    )
    final = events[-1]
    original_pid = ready[0]["pid"] if ready else None
    spawn_failure = "spawn_errno" in case or case.get("spawn_invalid_input", False)
    require(final.get("implicit_shutdown_performed") is False
            and final.get("original_owner_bodies_changed") is False
            and final.get("raw_wait_status_observable") is False
            and final.get("raw_wait_status") is None,
            "original fixture performed an unqualified cleanup or claimed raw wait access")
    if spawn_failure:
        require(not ready and len(foreground) == 1 and foreground[0].get("ok") is False
                and not promoted and not completed and not cancelled and not shut,
                "original spawn failure lifecycle differs")
        error = foreground[0].get("error")
        require(type(error) is str and error.startswith("Failed to spawn command:")
                and foreground[0].get("exit_code_from_owner_result") is None,
                "original spawn error did not come from the owner result")
        if "spawn_errno" in case:
            errno = case["spawn_errno"]
            require(foreground[0].get("os_error_from_message") == errno
                    and re.search(r"\(os error " + str(errno) + r"\)$", error) is not None,
                    "original spawn errno message projection differs")
        else:
            require(foreground[0].get("os_error_from_message") is None and "nul" in error.lower(),
                    "original NUL error differs")
        require(final.get("outcome") == "error" and final.get("callback_count") == 0
                and final.get("pid") is None and final.get("child_reaped_observed") is None,
                "spawn failure fabricated a live/reaped original child")
    elif case.get("control") == "cancel_after_ready":
        require(len(ready) == 1 and not foreground and not promoted and not completed
                and len(cancelled) == 1 and cancelled[0].get("phase") == "foreground"
                and cancelled[0].get("caller_aborted") is True
                and cancelled[0].get("caller_join_observed") is True
                and cancelled[0].get("background_waiter_aborted") is False,
                "foreground cancellation became a result or background callback")
        require(final.get("outcome") == "cancelled" and final.get("callback_count") == 0
                and final.get("tracker_pids") == [original_pid],
                "original cancellation tracker/callback contract differs")
    elif 3 in case["expected_kinds"]:
        require(len(ready) == 1 and not foreground and len(promoted) == len(completed) == 1
                and promoted[0].get("pid") == completed[0].get("pid") == original_pid
                and promoted[0].get("job_id") == completed[0].get("job_id")
                and promoted[0].get("resource_uri") == completed[0].get("resource_uri"),
                "promotion changed the original child, job, resource or waiter")
        job_id = str(receipt["pid"]) + "-1"
        require(promoted[0]["job_id"] == job_id
                and promoted[0]["resource_uri"] == "octofs://jobs/" + job_id
                and completed[0].get("exit_code") == case["exit_code"]
                and completed[0].get("callback_count") == final.get("callback_count") == 1
                and final.get("outcome") == "background"
                and promoted[0]["elapsed_ns"] >= 10_000_000_000,
                "original production promotion interval or completion changed")
        job = promoted[0].get("job")
        require(type(job) is dict and job.get("id") == job_id and job.get("pid") == original_pid
                and job.get("command") == bytes.fromhex(prepared["command_hex"]).decode()
                and job.get("working_dir_hex") == prepared["cwd_hex"]
                and job.get("status") == "running" and job.get("exit_code") is None,
                "promoted job did not retain the original request")
    else:
        require(len(ready) == 1 and len(foreground) == 1 and not promoted and not completed
                and final.get("callback_count") == 0, "original foreground lifecycle differs")
        if case["exit_code"] == 0:
            require(foreground[0].get("ok") is True and foreground[0].get("error") is None
                    and foreground[0].get("exit_code_from_owner_result") == 0
                    and final.get("outcome") == "foreground", "original foreground success differs")
        else:
            error = foreground[0].get("error")
            match = re.match(r"Command failed with exit code (-?\d+)\n\n", error or "")
            require(foreground[0].get("ok") is False and match is not None
                    and int(match.group(1)) == case["exit_code"]
                    and foreground[0].get("exit_code_from_owner_result") == case["exit_code"],
                    "original foreground exit-code projection differs")
    if case.get("control") == "cancel_after_promotion":
        require(len(cancelled) == 1 and cancelled[0].get("phase") == "background"
                and cancelled[0].get("background_waiter_aborted") is False
                and cancelled[0].get("caller_aborted") is False
                and cancelled[0]["seq"] > promoted[0]["seq"],
                "caller cancellation disturbed its moved background waiter")
    elif case.get("control") != "cancel_after_ready":
        require(not cancelled, "unsolicited original cancellation")
    expected_shutdown = int(case.get("control") in ("shutdown_after_ready", "shutdown_after_promotion"))
    require(len(shut) == expected_shutdown
            and all(e.get("reason") == "explicit" and e.get("tracker_after") == []
                    and e.get("tracker_before") == [original_pid]
                    and e.get("owner_function") == "kill_all_shell_children" for e in shut),
            "original shutdown did not drain exactly its tracked child")
    if not spawn_failure:
        require(final.get("child_reaped_observed") is True and final.get("pid") == original_pid,
                "original child reap was not observed")
    if case.get("control") != "cancel_after_ready":
        require(final.get("tracker_pids") == [], "original retained an unexpected tracked child")
    raw = final.get("raw_capture")
    require(type(raw) is dict and type(raw.get("observed")) is bool, "original raw capture receipt missing")
    capture_comparison = {"observed": raw["observed"], "normalization": None, "streams": {}}
    original_captures = {}
    if raw["observed"]:
        require(not spawn_failure and raw.get("complete_read_from_original_file_descriptors") is True
                and raw.get("original_paths_mutated_by_observer") is False,
                "original observer changed or incompletely read its log files")
        retained = bool(promoted or case.get("control") == "cancel_after_ready")
        require(type(raw.get("source_paths_exist")) is dict
                and all(type(v) is bool for v in raw["source_paths_exist"].values())
                and raw["source_paths_exist"] == {"stdout": retained, "stderr": retained},
                "original discard/retention order differs")
        for stream in ("stdout", "stderr"):
            filename = "original/retained/" + stream + ".bin"
            source = str(declared / "tmp" / ("octofs-jobs-" + str(receipt["pid"])) /
                         (str(receipt["pid"]) + "-1." + stream + ".log"))
            require(raw.get(stream + "_path") == str(declared / filename)
                    and raw.get(stream + "_source_path") == source,
                    "original retained stream path is not the exact owned file")
            data = raw_file(actual / filename)
            original_captures[stream] = data
            require(type(raw.get(stream + "_bytes")) is int and raw[stream + "_bytes"] == len(data),
                    "original complete stream size differs")
            if stream == "stdout" and case.get("observe_session"):
                equal = session_projection(data, original_pid) == session_projection(captures[stream], native["child_pid"])
                capture_comparison["normalization"] = "session probe PID fields only; all original bytes retained"
            else:
                equal = data == captures[stream]
            require(equal, "complete original/native " + stream + " bytes differ")
            capture_comparison["streams"][stream] = {
                "original": file_pin(actual / filename, declared / filename),
                "native": file_pin(actual / "native/capture" / (stream + ".log"),
                                   declared / "native/capture" / (stream + ".log")),
                "equal_under_declared_projection": True,
            }
    else:
        require(spawn_failure and all(not value for value in captures.values()),
                "successful execution lacks original raw capture evidence")
        require(all(raw.get(k) is None for k in (
            "source_paths_exist", "stdout_bytes", "stderr_bytes", "stdout_path", "stderr_path"
        )), "unobserved original capture fabricated stream values")
        capture_comparison["reason"] = "original spawn failure discarded logs before observer; no byte equality claimed"
    result = {
        "schema": "hepta.runtime.shell-process-original-comparison.v1", "status": "PASS",
        "name": case["name"], "original_pid": original_pid, "native_pid": native["child_pid"],
        "capture_comparison": capture_comparison, "process_lifecycle_projection_equal": True,
        "foreground_result_formatter_compared": False, "background_resource_renderer_compared": False,
        "original_raw_wait_status_observable": False,
        "original_error_errno_is_message_projection": bool(spawn_failure),
        "production_shell_execution_qualified": False, "whole_runtime_replaced": False,
    }
    return result, original_captures

FIXTURE_ROOTS = (b"work", b"tmp", b"capture.ready")
RETIREMENT = "fixture-retirement"


def member(root: Path, value: str) -> Path:
    require(type(value) is str and value and not value.startswith("/")
            and all(x not in ("", ".", "..") for x in value.split("/")),
            "unsafe retirement evidence member")
    return root / value


def stat_identity(info) -> dict:
    return {
        "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
        "links": info.st_nlink, "uid": info.st_uid, "gid": info.st_gid,
        "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }


def missing(path: bytes) -> bool:
    try:
        os.lstat(path)
        return False
    except FileNotFoundError:
        return True


def scan_fixtures(directory: Path) -> tuple[list[dict], list[str]]:
    """Scan only the three explicit roots; symlinks are never followed."""
    base = os.fsencode(directory)
    result, absent = [], []

    def visit(relative: bytes):
        path = base + b"/" + relative
        info = os.lstat(path)
        identity = stat_identity(info)
        row = {"path_hex": relative.hex(), "identity": identity,
               "permissions": stat.S_IMODE(info.st_mode)}
        if stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
            result.append(row)
            with os.scandir(path) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                require(name not in (b"", b".", b"..") and b"/" not in name,
                        "invalid scanned fixture name")
                visit(relative + b"/" + name)
        elif stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, "fixture snapshot refuses shared hard links")
            row["kind"] = "regular"
            data = raw_file(Path(os.fsdecode(path)))
            row["content"] = {"size": len(data), "sha256": sha(data)}
            row["_bytes"] = data
            result.append(row)
        elif stat.S_ISLNK(info.st_mode):
            require(info.st_nlink == 1, "fixture symlink has unexpected hard links")
            row["kind"] = "symlink"
            target = os.readlink(path)
            require(type(target) is bytes, "symlink target lost raw Unix bytes")
            row["target_hex"] = target.hex()
            result.append(row)
        else:
            raise EvidenceError("unsupported fixture inode type")
        require(stat_identity(os.lstat(path)) == identity,
                "fixture inode changed while being snapshotted")

    for root in FIXTURE_ROOTS:
        if missing(base + b"/" + root):
            absent.append(root.hex())
        else:
            visit(root)
    result.sort(key=lambda row: bytes.fromhex(row["path_hex"]))
    return result, absent


def fixture_shape(entries: list[dict], absent: list[str]) -> dict[bytes, dict]:
    require(type(entries) is list and type(absent) is list
            and absent == sorted(absent, key=bytes.fromhex), "fixture inventory ordering differs")
    rows = {}
    previous = None
    for row in entries:
        require(type(row) is dict and type(row.get("path_hex")) is str
                and re.fullmatch("(?:[0-9a-f]{2})+", row["path_hex"]) is not None,
                "fixture raw path is malformed")
        path = bytes.fromhex(row["path_hex"])
        require(path.split(b"/")[0] in FIXTURE_ROOTS and b"\0" not in path
                and all(x not in (b"", b".", b"..") for x in path.split(b"/"))
                and (previous is None or path > previous), "fixture path is duplicated or outside owned roots")
        previous = path
        identity = row.get("identity")
        require(type(identity) is dict and set(identity) == {
            "device", "inode", "mode", "links", "uid", "gid", "size", "mtime_ns", "ctime_ns"
        } and all(type(v) is int for v in identity.values())
                and all(identity[k] >= 0 for k in ("device", "inode", "mode", "links", "uid", "gid", "size")),
                "fixture lstat identity is incomplete")
        mode = identity["mode"]
        kind = ("directory" if stat.S_ISDIR(mode) else "regular" if stat.S_ISREG(mode)
                else "symlink" if stat.S_ISLNK(mode) else None)
        require(row.get("kind") == kind and kind is not None
                and row.get("permissions") == stat.S_IMODE(mode),
                "fixture type/mode differs from actual lstat")
        if kind == "regular":
            require(identity["links"] == 1 and shape_pin(row.get("content"), path=False)
                    and identity["size"] == row["content"]["size"],
                    "fixture regular content identity differs")
            require(type(row.get("_bytes")) is bytes
                    and {"size": len(row["_bytes"]), "sha256": sha(row["_bytes"])} == row["content"],
                    "fixture complete payload differs")
        elif kind == "symlink":
            require(identity["links"] == 1 and type(row.get("target_hex")) is str,
                    "fixture symlink target is absent")
            require(len(bytes.fromhex(row["target_hex"])) == identity["size"],
                    "fixture symlink target extent differs")
        rows[path] = row
    require(set(absent) <= {p.hex() for p in FIXTURE_ROOTS}
            and len(set(absent)) == len(absent), "unknown or duplicate absent fixture root")
    require({p for p in FIXTURE_ROOTS if p not in rows} == {bytes.fromhex(x) for x in absent},
            "fixture root absence is not fully observed")
    for path in rows:
        if b"/" in path:
            require(rows.get(path.rsplit(b"/", 1)[0], {}).get("kind") == "directory",
                    "fixture member lacks its recorded parent directory")
    return rows


def expected_fixtures(prepared: dict, native_receipt: dict, original_receipt,
                      events: list | None, original_captures: dict, module,
                      entries: list, absent: list) -> dict:
    rows = fixture_shape(entries, absent)
    case = prepared["definition"]
    require(rows.get(b"work", {}).get("kind") == "directory"
            and rows.get(b"tmp", {}).get("kind") == "directory", "fixture work/tmp root is missing")
    work = {b"work": ("directory", None, None)}
    wrapper = b'#!/bin/sh\nexec /bin/sh "$@"\n'
    setup = case.get("setup")
    if setup == "cwd_sh":
        work[b"work/sh"] = ("regular", wrapper, 0o755)
    elif setup == "cwd_marker_sh":
        work[b"work/sh"] = ("regular",
            ("#!/bin/sh\n" + module.GATE_PREFIX + 'printf cwd-search:; exec /bin/sh "$@"\n').encode(), 0o755)
    elif setup == "relative_sh":
        work[b"work/bin"] = ("directory", None, None)
        work[b"work/bin/sh"] = ("regular", wrapper, 0o755)
    elif setup == "denied_sh":
        work[b"work/denied"] = ("directory", None, None)
        work[b"work/denied/sh"] = ("regular", wrapper, 0o644)
    elif setup == "plain_file":
        work[b"work/plain"] = ("regular", b"not a directory\n", 0o644)
    elif setup == "loop_sh":
        work[b"work/loop"] = ("directory", None, None)
        work[b"work/loop/sh"] = ("symlink", b"sh", None)
    elif setup == "text_sh":
        work[b"work/text"] = ("directory", None, None)
        work[b"work/text/sh"] = ("regular",
            (module.GATE_PREFIX + 'printf "fallback:%s" "$1"; exit 9\n').encode(), 0o755)
    elif setup == "raw_cwd":
        work[b"work/raw-\xff-\xfe"] = ("directory", None, None)
    else:
        require(setup is None, "unknown registered fixture setup")
    require({p for p in rows if p == b"work" or p.startswith(b"work/")} == set(work),
            "full work fixture inventory differs from current registered source")
    for path, (kind, data, mode) in work.items():
        row = rows[path]
        require(row["kind"] == kind and (mode is None or row["permissions"] == mode),
                "generated fixture type/mode differs")
        if kind == "regular":
            require(row["_bytes"] == data, "generated fixture full contents differ")
        elif kind == "symlink":
            require(bytes.fromhex(row["target_hex"]) == data, "generated symlink target differs")
    expected_tmp = {b"tmp"}
    if original_receipt is not None:
        pid = str(original_receipt["pid"]).encode()
        logdir = b"tmp/octofs-jobs-" + pid
        if logdir in rows:
            require(rows[logdir]["kind"] == "directory", "original private log root type differs")
            expected_tmp.add(logdir)
        final_capture = events[-1]["raw_capture"]
        if final_capture["observed"]:
            for stream in ("stdout", "stderr"):
                path = logdir + b"/" + pid + b"-1." + stream.encode() + b".log"
                retained = final_capture["source_paths_exist"][stream]
                if retained:
                    require(rows.get(path, {}).get("kind") == "regular"
                            and rows[path]["_bytes"] == original_captures[stream],
                            "retained original source log differs from its complete FD capture")
                    expected_tmp.add(path)
                else:
                    require(path not in rows, "discarded original source log was retained")
    require({p for p in rows if p == b"tmp" or p.startswith(b"tmp/")} == expected_tmp,
            "unregistered temporary fixture file")
    ready = (bool([x for x in events if x["event"] == "capture_ready"]) and case["gate"]
             if events is not None else native_receipt["gate_created"])
    require(type(ready) is bool and (b"capture.ready" in rows) is ready,
            "capture gate lifetime differs from actual controller observations")
    if ready:
        require(rows[b"capture.ready"]["kind"] == "regular"
                and rows[b"capture.ready"]["_bytes"] == b"ready\n",
                "capture gate bytes differ")
    return {
        "entries": len(rows), "regular_bytes": sum(len(x["_bytes"]) for x in rows.values() if x["kind"] == "regular"),
        "setup": setup, "raw_path_and_complete_setup_checked": True,
    }


def retirement_data(folder: Path, report_sha: str, native_manifest: Path,
                    names: list[str], *, relocated: bool) -> dict | None:
    directory = folder / RETIREMENT
    if not directory.exists():
        return None
    require(directory.is_dir() and not directory.is_symlink(), "retirement location is not an ordinary directory")
    receipt = strict_json(raw_file(directory / "receipt.json"))
    require(type(receipt) is dict and receipt.get("schema") == "hepta.runtime.shell-process-fixture-retirement.v1"
            and receipt.get("status") == "PASS" and receipt.get("report_sha256") == report_sha
            and receipt.get("native_manifest") == file_pin(native_manifest)
            and receipt.get("cases") is not None and list(receipt["cases"]) == sorted(names)
            and receipt.get("roots") == [x.hex() for x in FIXTURE_ROOTS]
            and canonical(receipt.get("retired_at_directory", "")),
            "fixture retirement identity differs")
    require(relocated or receipt["retired_at_directory"] == str(folder),
            "retirement is not at its original strong evidence directory")
    require(receipt.get("reader_source") == file_pin(Path(__file__).resolve())
            and receipt.get("cases_source") == file_pin(CASES)
            and receipt.get("runner_source") == file_pin(RUNNER),
            "retirement producer or registered source changed")
    require(integer(receipt.get("started_ns"), 0)
            and integer(receipt.get("finished_ns"), receipt["started_ns"])
            and receipt.get("duration_ns") == receipt["finished_ns"] - receipt["started_ns"]
            and all(receipt.get(k) is v for k, v in SCOPE.items()), "retirement scope/timing differs")
    declared_root = Path(receipt["retired_at_directory"]) / RETIREMENT
    prepared = strict_json(check_pin(directory / "prepared.json", receipt.get("prepared_receipt"),
                                     declared_root / "prepared.json"))
    require(prepared.get("schema") == "hepta.runtime.shell-process-fixture-retirement-prepared.v1"
            and prepared.get("validated_evidence") == receipt.get("validated_evidence")
            and prepared.get("cases") == {
                name: {"snapshot": receipt["cases"][name]["snapshot"]} for name in names
            }
            and all(prepared.get(key) == receipt[key] for key in (
                "reader_source", "cases_source", "runner_source", "native_manifest"
            )), "retirement prepared receipt chain differs")
    for key, source in (("reader", Path(__file__).resolve()), ("cases", CASES), ("runner", RUNNER)):
        require(raw_file(directory / "source-snapshots" / (key + ".py")) == raw_file(source),
                "retirement sealed producer source differs")
    for name in names:
        row = receipt["cases"][name]
        require(type(row) is dict and row.get("deleted_roots_observed_absent") == [x.hex() for x in FIXTURE_ROOTS],
                "retirement did not observe every explicit root absent")
        for root in FIXTURE_ROOTS:
            require(missing(os.fsencode(folder / name) + b"/" + root),
                    "retired fixture root has reappeared")
        declared = Path(receipt["retired_at_directory"]) / RETIREMENT / "cases" / (name + ".json")
        snapshot = strict_json(check_pin(directory / "cases" / (name + ".json"), row["snapshot"], declared))
        require(snapshot.get("schema") == "hepta.runtime.shell-process-fixture-snapshot.v1"
                and snapshot.get("case") == name, "retirement case snapshot schema differs")
        for entry in snapshot["entries"]:
            if entry.get("kind") == "regular":
                payload = member(directory, entry["payload"])
                require(payload.lstat().st_nlink == 1, "retirement payload is a shared hard link")
                data = raw_file(payload)
                require({"size": len(data), "sha256": sha(data)} == entry["content"],
                        "retirement complete payload changed")
                entry["_bytes"] = data
        fixture_shape(snapshot["entries"], snapshot["absent_roots"])
        row["_snapshot"] = snapshot
    return receipt

def _read_evidence(folder: Path, native_manifest: Path, original_manifest: Path | None,
                   require_full: bool, *, relocated: bool = False, native_only: bool = False) -> dict:
    folder = folder.absolute()
    require(folder.resolve(strict=True) == folder and folder.is_dir(), "evidence root is not an ordinary canonical directory")
    native_manifest = native_manifest.absolute()
    before_sources = {str(p): sha(raw_file(p)) for p in (CASES, RUNNER, BUILDER, Path(__file__).resolve())}
    report_raw = raw_file(folder / "report.json")
    report = strict_json(report_raw)
    require(type(report) is dict and report.get("schema") == "hepta.runtime.shell-process-real-os-review.v1",
            "real-OS report schema differs")
    inputs = strict_json(raw_file(folder / "inputs.json"))
    require(type(inputs) is dict and report.get("inputs") == inputs
            and report.get("inputs_unchanged") is True
            and report.get("fresh_native_processes_executed") is True,
            "actual run input identity changed")
    with_original = "original_executable" in inputs
    require(not native_only or not with_original, "native-only reader received an original comparison")
    expected_inputs = {"native_executable", "native_build_manifest", "cases_source", "runner_source"}
    if with_original:
        expected_inputs |= {"original_executable", "original_build_manifest"}
    require(set(inputs) == expected_inputs, "actual run input inventory differs")
    require(report.get("status") == ("ORIGINAL_COMPARISON_PASS" if with_original else "NATIVE_ONLY_PASS")
            and report.get("fresh_original_process_comparisons_performed") is with_original
            and report.get("fresh_original_rust_build_qualified") is False,
            "report did not pass its explicitly declared process scope")
    for key in ("matching_source_full_cold_qualified", "production_shell_execution_qualified",
                "whole_runtime_replaced", "old_stack_removal_qualified"):
        require(report.get(key) is False, "process report overclaims qualification")
    require(report.get("production_activated", False) is False, "process report overclaims activation")
    for name, identity in inputs.items():
        require(shape_pin(identity), "malformed admitted run input pin")
        check_pin(folder / "input-snapshots" / name, identity, identity["path"])
    require(set(p.name for p in (folder / "input-snapshots").iterdir()) == expected_inputs,
            "input snapshot inventory differs")
    check_pin(CASES, inputs["cases_source"])
    check_pin(RUNNER, inputs["runner_source"])
    require(inputs["native_build_manifest"]["path"] == str(native_manifest),
            "run was not bound to the supplied final native manifest path")
    check_pin(native_manifest, inputs["native_build_manifest"])
    native_metadata, executable, build_validation = native_binding(native_manifest)
    check_pin(executable, inputs["native_executable"])
    original_build = None
    original_path = None
    if with_original:
        recorded_manifest = Path(inputs["original_build_manifest"]["path"])
        if original_manifest is None:
            require(recorded_manifest.is_relative_to(ROOT.parent),
                    "development-only original manifest is outside this qualification workspace")
        if original_manifest is not None:
            require(original_manifest.absolute() == recorded_manifest,
                    "run used a different original build manifest path")
        original_raw = check_pin(recorded_manifest, inputs["original_build_manifest"])
        original_build = strict_json(original_raw, floats=True)
        require(type(original_build) is dict
                and original_build.get("schema") == "hepta.runtime.shell-process-original-qualification.v1"
                and original_build.get("status") == "PASS"
                and original_build.get("error") is None,
                "original build declaration did not pass")
        binding = original_build.get("executable")
        require(type(binding) is dict and set(binding) == {"path", "bytes", "sha256"}
                and inputs["original_executable"] == {
                    "path": binding["path"], "size": binding["bytes"], "sha256": binding["sha256"]
                }, "original executable differs from its actual build declaration")
        original_path = Path(binding["path"])
        require(original_path.is_relative_to(recorded_manifest.parent), "original ELF escaped its admitted build")
        check_pin(original_path, inputs["original_executable"])
        for flag in ("production_shell_execution_qualified", "whole_runtime_replaced", "old_stack_removal_qualified"):
            require(original_build.get(flag) is False, "original build overclaims production closure")
    else:
        require(original_manifest is None, "native-only evidence cannot claim an original build")

    module, runner = load_current(CASES, "cases"), load_current(RUNNER, "runner")
    definitions = module.specs()
    known = {row["name"]: row for row in definitions}
    require(len(known) == len(definitions) and all(re.fullmatch("[a-z0-9_]+", k) for k in known),
            "current registered case inventory is ambiguous")
    selected = report.get("selected_cases")
    if selected is None:
        require(report.get("full_case_set") is True, "whole case flag differs from selected input")
        wanted_names = list(known)
    else:
        require(type(selected) is list and selected and all(type(x) is str for x in selected)
                and len(set(selected)) == len(selected) and set(selected) <= set(known)
                and report.get("full_case_set") is False, "unknown or duplicate selected case")
        require(not require_full, "partial --case evidence cannot qualify the complete registered suite")
        wanted_names = [name for name in known if name in selected]
    require(not require_full or report.get("full_case_set") is True, "full case set is required")
    rows = report.get("cases")
    require(type(rows) is list and all(type(x) is dict for x in rows)
            and [x.get("name") for x in rows] == wanted_names
            and type(report.get("case_count")) is int and report["case_count"] == len(wanted_names),
            "case inventory is missing, duplicated or reordered")
    require(all(x.get("status") == "PASS" for x in rows), "failed real-OS case cannot be replayed as PASS")
    expected_dirs = set(wanted_names) | {"input-snapshots"}
    if (folder / RETIREMENT).exists():
        expected_dirs.add(RETIREMENT)
    actual_dirs = set()
    for path in folder.iterdir():
        require(not path.is_symlink(), "unexpected symlink at evidence root")
        if path.is_dir():
            actual_dirs.add(path.name)
        else:
            require(path.name in {"report.json", "inputs.json"} and path.is_file(),
                    "unregistered evidence root member")
    require(actual_dirs == expected_dirs, "unregistered or missing case directory")
    retired = retirement_data(folder, sha(report_raw), native_manifest, wanted_names, relocated=relocated)
    producer_root = None
    statistics = []
    for row in rows:
        name = row["name"]
        actual = folder / name
        prepared = strict_json(raw_file(actual / "input.json"))
        require(type(prepared) is dict and canonical(prepared.get("directory", "")),
                "missing complete prepared case input")
        declared = Path(prepared["directory"])
        if producer_root is None:
            producer_root = declared.parent
        require(declared == producer_root / name, "case run directories do not share the same declared producer root")
        require(relocated or actual == declared, "actual evidence directory differs from the original process path")
        expected = prepared_value(known[name], str(declared), module)
        require(prepared == expected, "registered command/cwd/environment/setup input differs")
        initial = module.frame(1, bytes.fromhex(prepared["command_hex"]), bytes.fromhex(prepared["cwd_hex"]))
        require(raw_file(actual / "native-start.bin") == initial, "original complete native frame differs")
        nactual, ndeclared = actual / "native", declared / "native"
        nreceipt = strict_json(raw_file(nactual / "process.json"))
        nstreams = process_receipt(nreceipt, prepared, "native", inputs["native_executable"], nactual, ndeclared)
        require(nstreams["stdin"] == controls(nreceipt, prepared, module, original=False),
                "complete native initial/control stdin differs")
        require(type(nreceipt.get("gate_created")) is bool
                and (known[name]["gate"] or nreceipt["gate_created"] is False),
                "native capture gate receipt differs")
        nframes = native_frames(nstreams["stdout"], strict_json(raw_file(nactual / "frames.json")),
                                nreceipt, runner, module)
        captures = {stream: raw_file(nactual / "capture" / (stream + ".log")) for stream in ("stdout", "stderr")}
        trace = module.decode_trace(raw_file(nactual / "capture/effects.bin"), complete=True)
        identities = {i["pid"]: i for i in nreceipt["observed_child_identities"]}
        validation = runner.validate_native(
            known[name], nreceipt, nframes, trace, captures, identities, check_live_children=False
        )
        validation["capture_files"] = {stream: file_pin(nactual / "capture" / (stream + ".log"),
                                                       ndeclared / "capture" / (stream + ".log"))
                                       for stream in ("stdout", "stderr")}
        validation["trace_file"] = file_pin(nactual / "capture/effects.bin", ndeclared / "capture/effects.bin")
        require(validation == strict_json(raw_file(nactual / "validation.json")),
                "native validation was not reconstructed from complete raw bytes")
        traced = check_trace(trace, nreceipt, prepared, nframes)
        if known[name].get("control", "").endswith("after_promotion"):
            promotion = [x for x in nframes if x.get("event", {}).get("kind") == 3]
            require(len(promotion) == 1 and promotion[0]["observed_elapsed_ns"] <= nreceipt["controls"][0]["elapsed_ns"],
                    "control was not delivered after the observed native promotion")
        if known[name].get("control", "").endswith("after_ready"):
            require(captures["stdout"].startswith(b"ready"), "ready-triggered native control lacks actual ready output")
        native_row = {
            "name": name, "status": "PASS", "process": file_pin(nactual / "process.json", ndeclared / "process.json"),
            "validation": file_pin(nactual / "validation.json", ndeclared / "validation.json"),
            "duration_ns": nreceipt["duration_ns"], "error": None,
        }
        original_captures, events, oreceipt = {}, None, None
        if with_original:
            oactual, odeclared = actual / "original", declared / "original"
            oreceipt = strict_json(raw_file(oactual / "process.json"))
            ostreams = process_receipt(oreceipt, prepared, "original", inputs["original_executable"], oactual, odeclared)
            require(ostreams["stdin"] == controls(oreceipt, prepared, module, original=True),
                    "complete original initial/control JSONL stdin differs")
            events = original_events(ostreams["stdout"], strict_json(raw_file(oactual / "events.json")),
                                     oreceipt, prepared)
            oval = {"status": "PASS", "error": None, "event_names": [x["event"] for x in events]}
            require(oval == strict_json(raw_file(oactual / "validation.json")),
                    "original validation differs from actual complete process stream")
            comparison, original_captures = original_projection(
                prepared, validation, events, oreceipt, actual, declared, captures
            )
            require(comparison == strict_json(raw_file(actual / "comparison.json")),
                    "retained comparison was not reconstructed from actual raw streams and lifecycle events")
            original_row = {
                "name": name, "status": "PASS",
                "process": file_pin(oactual / "process.json", odeclared / "process.json"),
                "validation": file_pin(oactual / "validation.json", odeclared / "validation.json"),
                "duration_ns": oreceipt["duration_ns"], "error": None,
            }
            expected_row = {
                "name": name, "status": "PASS", "native": native_row, "original": original_row,
                "comparison": file_pin(actual / "comparison.json", declared / "comparison.json"),
                "duration_ns": nreceipt["duration_ns"] + oreceipt["duration_ns"], "error": None,
            }
        else:
            expected_row = native_row
        require(row == expected_row, "report case summary differs from actual processes and reconstruction")
        if retired is None:
            entries, absent = scan_fixtures(actual)
        else:
            snapshot = retired["cases"][name]["_snapshot"]
            require(snapshot.get("recorded_case_directory") == str(declared)
                    and snapshot.get("definition") == known[name], "retired fixture source/setup identity differs")
            entries, absent = snapshot["entries"], snapshot["absent_roots"]
        fixture = expected_fixtures(prepared, nreceipt, oreceipt, events, original_captures,
                                    module, entries, absent)
        statistics.append({
            "name": name, "native_effect_records": traced["effect_records"],
            "actual_direct_child_reaps": traced["actual_reaps"],
            "native_frames": len(nframes), "original_jsonl_events": len(events) if events else 0,
            "captured_stdout_bytes": len(captures["stdout"]), "captured_stderr_bytes": len(captures["stderr"]),
            "fixture_entries": fixture["entries"], "fixture_regular_bytes": fixture["regular_bytes"],
        })
    qualified_original = None
    if original_manifest is not None:
        reference = load_current(REFERENCE, "reference")
        reference_source = sha(raw_file(REFERENCE))
        qualified_original = reference.read_evidence(ROOT, original_manifest.absolute().parent)
        require(qualified_original.get("fresh_original_rust_build_qualified") is True
                and qualified_original.get("report_sha256") == inputs["original_build_manifest"]["sha256"],
                "original strong build reader did not qualify this exact final build")
        require(sha(raw_file(REFERENCE)) == reference_source, "original evidence reader changed")
    require(all(sha(raw_file(Path(path))) == digest for path, digest in before_sources.items()),
            "current parser or registered source changed during read")
    require(raw_file(folder / "report.json") == report_raw, "report changed during evidence read")
    result = {
        "schema": "hepta.runtime.shell-process-real-os-evidence.v1", "status": "PASS",
        "verification": ("current-build-paths-and-relocated-retained-bytes" if relocated
                         else "strong-current-path-evidence"),
        "strong_process_directory_binding": not relocated,
        "report_sha256": sha(report_raw), "case_count": len(rows),
        "full_case_set": selected is None, "original_comparison_cases": len(rows) if with_original else 0,
        "fresh_original_rust_build_qualified": qualified_original is not None,
        "original_build_report_sha256": inputs.get("original_build_manifest", {}).get("sha256"),
        "native_manifest_sha256": inputs["native_build_manifest"]["sha256"],
        "native_elf_sha256": inputs["native_executable"]["sha256"],
        "fixtures_retired": retired is not None, "cases": statistics,
        "foreground_result_formatter_compared": False, "background_resource_renderer_compared": False,
        "original_raw_wait_status_observable": False,
        "original_error_errno_is_message_projection": with_original, **SCOPE,
    }
    if retired is not None:
        original_pin = retired.get("original_manifest")
        require(original_pin is None or with_original and original_pin == inputs["original_build_manifest"],
                "retirement original build binding differs")
        prior = dict(result, fixtures_retired=False,
                     verification="strong-current-path-evidence", strong_process_directory_binding=True,
                     fresh_original_rust_build_qualified=original_pin is not None)
        require(retired.get("validated_evidence") == prior,
                "pre-retirement validation differs from reconstructed complete snapshots")
    return result


def read_evidence(folder: Path, native_manifest: Path, original_manifest: Path | None = None,
                  require_full: bool = True) -> dict:
    return _read_evidence(folder, native_manifest, original_manifest, require_full)


def read_native_evidence(folder: Path, native_manifest: Path, require_full: bool = True) -> dict:
    return _read_evidence(folder, native_manifest, None, require_full, native_only=True)


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()


def retire_fixtures(folder: Path, native_manifest: Path, original_manifest: Path | None = None) -> Path:
    """Snapshot and retire only verified work/tmp/gate fixture roots.

    This explicit mutation entrypoint is separate from the read-only reader.
    Existing valid retirement is checked and returned without rewriting it.
    """
    import time
    folder, native_manifest = folder.absolute(), native_manifest.absolute()
    baseline = read_evidence(folder, native_manifest, original_manifest)
    destination = folder / RETIREMENT
    result_path = destination / "receipt.json"
    if baseline["fixtures_retired"]:
        return result_path
    started = time.monotonic_ns()
    destination.mkdir(mode=0o700, exist_ok=False)
    (destination / "cases").mkdir(mode=0o700)
    (destination / "payloads").mkdir(mode=0o700)
    (destination / "source-snapshots").mkdir(mode=0o700)
    for key, source in (("reader", Path(__file__).resolve()), ("cases", CASES), ("runner", RUNNER)):
        _write_new(destination / "source-snapshots" / (key + ".py"), raw_file(source))
    report = strict_json(raw_file(folder / "report.json"))
    prepared_snapshots = {}
    case_records = {}
    for case_row in report["cases"]:
        name = case_row["name"]
        actual = folder / name
        prepared = strict_json(raw_file(actual / "input.json"))
        entries, absent = scan_fixtures(actual)
        prepared_snapshots[name] = (entries, absent)
        payload_dir = destination / "payloads" / name
        payload_dir.mkdir(mode=0o700)
        sealed = []
        for index, entry in enumerate(entries):
            row = {key: value for key, value in entry.items() if key != "_bytes"}
            if entry["kind"] == "regular":
                relative = "payloads/" + name + "/" + str(index) + ".bin"
                _write_new(destination / relative, entry["_bytes"])
                row["payload"] = relative
            sealed.append(row)
        snapshot = {
            "schema": "hepta.runtime.shell-process-fixture-snapshot.v1", "case": name,
            "recorded_case_directory": prepared["directory"], "definition": prepared["definition"],
            "entries": sealed, "absent_roots": absent,
        }
        path = destination / "cases" / (name + ".json")
        _write_new(path, _json_bytes(snapshot))
        case_records[name] = {"snapshot": file_pin(path)}
    prepared_record = {
        "schema": "hepta.runtime.shell-process-fixture-retirement-prepared.v1",
        "validated_evidence": baseline, "cases": case_records,
        "reader_source": file_pin(Path(__file__).resolve()), "cases_source": file_pin(CASES),
        "runner_source": file_pin(RUNNER), "native_manifest": file_pin(native_manifest),
    }
    _write_new(destination / "prepared.json", _json_bytes(prepared_record))
    # Recheck every inode and every byte before the first deletion.
    for name, expected in prepared_snapshots.items():
        require(scan_fixtures(folder / name) == expected, "fixture changed before retirement")
    for name, (entries, absent) in prepared_snapshots.items():
        base = os.fsencode(folder / name)
        for entry in reversed(entries):
            relative = bytes.fromhex(entry["path_hex"])
            path = base + b"/" + relative
            current = stat_identity(os.lstat(path))
            earlier = entry["identity"]
            if entry["kind"] == "directory":
                # Child removal changes directory metadata. Preserve the complete
                # pre-deletion tree above and recheck immutable inode ownership now.
                require(all(current[k] == earlier[k] for k in ("device", "inode", "mode", "uid", "gid")),
                        "fixture directory identity changed before rmdir")
                os.rmdir(path)
            else:
                require(current == earlier, "fixture leaf identity changed before unlink")
                if entry["kind"] == "regular":
                    require(raw_file(Path(os.fsdecode(path))) == entry["_bytes"], "fixture bytes changed before unlink")
                else:
                    require(os.readlink(path).hex() == entry["target_hex"], "fixture symlink changed before unlink")
                os.unlink(path)
        require(all(missing(base + b"/" + root) for root in FIXTURE_ROOTS),
                "explicit fixture root survived retirement")
        case_records[name]["deleted_roots_observed_absent"] = [x.hex() for x in FIXTURE_ROOTS]
    finished = time.monotonic_ns()
    result = {
        "schema": "hepta.runtime.shell-process-fixture-retirement.v1", "status": "PASS",
        "retired_at_directory": str(folder), "report_sha256": baseline["report_sha256"],
        "native_manifest": file_pin(native_manifest),
        "original_manifest": file_pin(original_manifest.absolute()) if original_manifest is not None else None,
        "reader_source": prepared_record["reader_source"], "cases_source": prepared_record["cases_source"],
        "runner_source": prepared_record["runner_source"],
        "validated_evidence": baseline, "prepared_receipt": file_pin(destination / "prepared.json"),
        "roots": [x.hex() for x in FIXTURE_ROOTS], "cases": case_records,
        "started_ns": started, "finished_ns": finished, "duration_ns": finished - started, **SCOPE,
    }
    _write_new(result_path, _json_bytes(result))
    read_evidence(folder, native_manifest, original_manifest)
    return result_path


def readonly_audit(event, args):
    process_actions = {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
                       "os.exec", "os.kill", "os.killpg", "ctypes.dlopen", "ctypes.dlsym",
                       "mmap.__new__"}
    writes = {"os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown",
              "os.utime", "os.link", "os.symlink", "shutil.copyfile", "shutil.rmtree"}
    if event in process_actions or event in writes:
        raise ReadOnlyViolation("reader attempted a forbidden action: " + event)
    if event in ("open", "os.listdir", "os.scandir") and args:
        path = args[0]
        if isinstance(path, (str, bytes, os.PathLike)):
            raw = os.fsencode(path)
            if raw == b"/proc" or raw.startswith(b"/proc/"):
                raise ReadOnlyViolation("reader attempted to inspect live /proc")
        if event == "open":
            mode, flags = args[1], args[2]
            if (type(mode) is str and any(x in mode for x in "wax+")
                    or type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                raise ReadOnlyViolation("reader attempted to write a file")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", "--cases", dest="evidence", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--original-manifest", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--relocated-evidence", action="store_true",
                        help="Explicit byte replay for copied evidence; never claims original directory binding.")
    parser.add_argument("--audit-read-only", action="store_true")
    args = parser.parse_args()
    if args.audit_read_only:
        sys.addaudithook(readonly_audit)
    try:
        result = _read_evidence(
            args.evidence, args.native_manifest, args.original_manifest, not args.allow_partial,
            relocated=args.relocated_evidence, native_only=args.native_only,
        )
        result["read_only_audit_enforced"] = args.audit_read_only
        print(json.dumps(result, sort_keys=True))
        return 0
    except ReadOnlyViolation as error:
        print(json.dumps({"status": "READ_ONLY_VIOLATION", "message": str(error), **SCOPE}, sort_keys=True))
        return 2
    except (EvidenceError, ValueError, AssertionError, TypeError, KeyError, OSError) as error:
        print(json.dumps({"status": "REJECTED", "error_type": type(error).__name__,
                          "message": str(error), "read_only_audit_enforced": args.audit_read_only, **SCOPE},
                         sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
