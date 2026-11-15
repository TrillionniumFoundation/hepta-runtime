#!/usr/bin/env python3
"""Execute and retain real Linux process-owner observations.

Native-only runs are explicitly NATIVE_ONLY_PASS.  This runner does not substitute
for the original Rust comparison, compiler cold gate, or production dispatcher
qualification.  Every attempt owns a new output directory and keeps failed runs.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
import struct
import subprocess
import sys
import time
import traceback


ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "tests/hia_native/shell_process_cases.py"


def json_write(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")


def pin(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def cases_module(path: Path):
    spec = importlib.util.spec_from_file_location("shell_process_real_os_cases", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load pinned cases")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process_identity(pid: int) -> dict | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    split = raw.rfind(") ")
    if split < 0:
        raise ValueError("malformed proc stat")
    fields = raw[split + 2:].split()
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]), "starttime_ticks": int(fields[19]), "raw_stat": raw}


def decode_frames(raw: bytearray, cursor: int, module) -> tuple[int, list[dict]]:
    result = []
    while len(raw) - cursor >= 16:
        returned, extent = struct.unpack_from("<QQ", raw, cursor)
        if extent > 96:
            raise ValueError(f"fixture published impossible event extent {extent}")
        if len(raw) - cursor < 16 + extent:
            break
        body = bytes(raw[cursor + 16:cursor + 16 + extent])
        record = {"offset": cursor, "return": returned, "extent": extent, "body_hex": body.hex()}
        if returned == 96 and extent == 96:
            record["event"] = module.decode_event(body)
        elif returned == 0 and extent == 0:
            record["retired"] = True
        else:
            raise ValueError(f"native owner refused or fixture emitted an invalid frame: {record}")
        result.append(record)
        cursor += 16 + extent
    return cursor, result


def read_owned_trace(path: Path, module) -> dict:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return {"records": [], "footer": None, "trailing_bytes": 0}
    return module.decode_trace(data, complete=False)


def remember_children(trace: dict, parent_pid: int, children: dict[int, dict]) -> None:
    for record in trace["records"]:
        if record["self_pid"] == parent_pid and record["action"] == 5 and record["phase"] == 1 and record["errno"] == 0 and record["result"] > 0:
            child_pid = record["result"]
            if child_pid in children:
                continue
            identity = process_identity(child_pid)
            if identity is not None and identity["ppid"] == parent_pid:
                children[child_pid] = identity


def emergency_cleanup(process: subprocess.Popen, children: dict[int, dict], shutdown_frame: bytes) -> list[dict]:
    """Only kill processes whose identity was actually observed under this child."""
    observations = []
    if process.poll() is None and process.stdin is not None:
        try:
            written = os.write(process.stdin.fileno(), shutdown_frame)
            observations.append({"trusted_controller_shutdown_bytes": written, "requested_bytes": len(shutdown_frame)})
            process.wait(timeout=0.3)
        except (BrokenPipeError, BlockingIOError, OSError, subprocess.TimeoutExpired) as exc:
            observations.append({"controller_shutdown_observation": type(exc).__name__})
    # A fixture may fail before its capture_ready/FORK audit is readable. Bind
    # only kernel-observed direct children of this still-unreaped owned parent.
    if process.poll() is None:
        parent = process_identity(process.pid)
        try:
            raw_children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text()
        except FileNotFoundError:
            raw_children = ""
        if parent is not None and process_identity(process.pid) is not None:
            for item in raw_children.split():
                pid = int(item)
                identity = process_identity(pid)
                parent_after = process_identity(process.pid)
                if identity and identity["ppid"] == process.pid and parent_after and parent_after["starttime_ticks"] == parent["starttime_ticks"]:
                    children.setdefault(pid, identity)
    for pid, earlier in children.items():
        current = process_identity(pid)
        row = {"pid": pid, "observed": earlier, "before_cleanup": current, "signaled": False}
        if current and current["starttime_ticks"] == earlier["starttime_ticks"]:
            try:
                if current["pgid"] == pid and current["sid"] == pid:
                    os.killpg(pid, signal.SIGKILL)
                    row["signal_target"] = "owned_session_group"
                else:
                    os.kill(pid, signal.SIGKILL)
                    row["signal_target"] = "owned_direct_child"
                row["signaled"] = True
            except ProcessLookupError:
                row["disappeared_before_signal"] = True
        observations.append(row)
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        observations.append({"fixture_wait_timeout": True})
    return observations


def validate_native(case: dict, receipt: dict, frames: list[dict], trace: dict, captures: dict, children: dict[int, dict], *, check_live_children: bool = True) -> dict:
    if receipt["exit_code"] != 0 or receipt["timed_out"] or receipt["exception"] is not None:
        raise AssertionError("native fixture did not finish cleanly")
    if receipt["streams"]["stderr"]["size"]:
        raise AssertionError("native fixture wrote diagnostics to stderr")
    if not frames or not frames[-1].get("retired") or sum(bool(row.get("retired")) for row in frames) != 1:
        raise AssertionError("owner did not retire exactly once, last")
    events = [row["event"] for row in frames if "event" in row]
    if [row["kind"] for row in events] != case["expected_kinds"]:
        raise AssertionError(f"event ordering mismatch: {[row['kind'] for row in events]}")
    if [row["sequence"] for row in events] != list(range(1, len(events) + 1)):
        raise AssertionError("event sequence is not contiguous")
    parent = receipt["pid"]
    records = trace["records"]
    if any(row["phase"] not in (0, 1) or row["action"] not in range(1, 20) for row in records):
        raise AssertionError("invalid kernel audit action/phase")
    forks = [row for row in records if row["self_pid"] == parent and row["action"] == 5 and row["phase"] == 1 and row["errno"] == 0 and row["result"] > 0]
    expected_forks = 0 if case.get("spawn_invalid_input") else 1
    if len(forks) != expected_forks:
        raise AssertionError(f"expected {expected_forks} fork, saw {len(forks)}")
    child_pid = forks[0]["result"] if forks else 0
    footer = trace["footer"]
    if footer is None:
        raise AssertionError("native audit was not sealed")
    audit = footer["words"]
    if len(audit) != 15 or any(audit[index] != 0 for index in (2, 3, 6, 7, 8, 13, 14)):
        raise AssertionError(f"native kernel audit reports an error or retained custody: {audit}")
    parent_records = [row for row in records if row["self_pid"] == parent]
    child_records = [row for row in records if row["self_pid"] != parent]
    if (audit[0], audit[1]) != (len(parent_records), len(child_records)):
        raise AssertionError("actual audit records differ from adapter write attempts")
    if (audit[4], audit[5]) != (128 if parent_records else 0, 128 if child_records else 0):
        raise AssertionError("last audit writes were incomplete")
    if any(row["self_pid"] != child_pid for row in child_records) or audit[11] != child_pid:
        raise AssertionError("audit record came from an unowned process")
    expected_tracker = 1 if case.get("control") == "cancel_after_ready" else 0
    if audit[9] != expected_tracker or audit[10] != (1 if child_pid else 0):
        raise AssertionError(f"tracker/reap footer disagrees with original lifecycle: {audit}")
    if any(row["pid"] != child_pid for row in events):
        raise AssertionError("event changed the actual child PID")
    tokens = {row["child_token"] for row in events}
    if len(tokens) != 1 or (child_pid and not next(iter(tokens))):
        raise AssertionError("child custody token changed or was zero")
    if "spawn_errno" in case:
        event = events[-1]
        if (event["error_kind"], event["errno"]) != (1, case["spawn_errno"]):
            raise AssertionError(f"spawn OS error mismatch: {event}")
    elif case.get("spawn_invalid_input"):
        if (events[-1]["error_kind"], events[-1]["errno"]) != (2, 0):
            raise AssertionError("interior NUL did not retain original InvalidInput semantics")
    else:
        final = next((row for row in reversed(events) if row["kind"] in (2, 4)), None)
        if final is not None:
            if final["error_kind"] != 0 or final["errno"] != 0 or final["exit_code"] != case["exit_code"] or final["tracked"] != 0 or not final["flags"] & 2:
                raise AssertionError(f"normal completion contract mismatch: {final}")
            status = final["wait_status"]
            if case.get("wait_signal"):
                if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != case["wait_signal"]:
                    raise AssertionError("wrong actual wait signal")
            elif not os.WIFEXITED(status) or os.WEXITSTATUS(status) != case["exit_code"]:
                raise AssertionError("wrong actual wait exit status")
        if any(row["kind"] == 3 for row in events):
            promoted = next(row for row in events if row["kind"] == 3)
            if promoted["tracked"] != 1 or not promoted["flags"] & 1:
                raise AssertionError("promotion lost original tracker/custody")
    signals = [row for row in records if row["self_pid"] == parent and row["action"] == 18 and row["phase"] == 0]
    control = case.get("control")
    expected_signal_modes = [1] if control == "cancel_after_ready" else [2] if control in ("shutdown_after_ready", "shutdown_after_promotion") else []
    if [row["arg1"] for row in signals] != expected_signal_modes:
        raise AssertionError("cancellation/shutdown signal target or count changed")
    for stream in ("stdout", "stderr"):
        if stream + "_hex" in case and captures[stream] != bytes.fromhex(case[stream + "_hex"]):
            raise AssertionError(f"complete {stream} capture differs")
    session_observation = None
    if case.get("observe_session"):
        lines = captures["stdout"].splitlines()
        if len(lines) != 2 or int(lines[0]) != child_pid:
            raise AssertionError("shell PID observation differs from owner")
        session_observation = json.loads(lines[1])
        if any(session_observation[key] != child_pid for key in ("ppid", "pgid", "sid")):
            raise AssertionError("child did not retain its detached session/group")
    survivors = []
    if check_live_children:
        for pid, identity in children.items():
            current = process_identity(pid)
            if current and current["starttime_ticks"] == identity["starttime_ticks"]:
                survivors.append(current)
    if survivors:
        raise AssertionError(f"owned child survived fixture retirement: {survivors}")
    return {"status": "PASS", "event_kinds": [row["kind"] for row in events], "events": events, "forks": len(forks), "signal_modes": expected_signal_modes, "child_pid": child_pid, "session_observation": session_observation, "owned_children_alive_after_retirement": survivors, "audit_footer": trace["footer"]}


def run_native(prepared: dict, executable: Path, module) -> dict:
    case = prepared["definition"]
    directory = Path(prepared["directory"]) / "native"
    directory.mkdir()
    capture = directory / "capture"
    capture.mkdir()
    ready = Path(prepared["ready_path"])
    if ready.exists():
        raise ValueError("capture gate unexpectedly exists before this run")
    argv = [str(executable), "--process-fixture", str(capture)]
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=prepared["directory"], env=prepared["environment"], start_new_session=True)
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    clock = time.monotonic_ns()
    started_at = datetime.now(timezone.utc).isoformat()
    selector = selectors.DefaultSelector()
    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    os.set_blocking(process.stdin.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    pending = bytearray(module.frame(1, bytes.fromhex(prepared["command_hex"]), bytes.fromhex(prepared["cwd_hex"])))
    delivered = bytearray()
    stdout, stderr = bytearray(), bytearray()
    frames, children, controls = [], {}, []
    cursor = 0
    timed_out, error, cleanup = False, None, []
    gate_created, control_sent, input_registered = False, False, True
    deadline = clock + int(case["deadline_seconds"] * 1_000_000_000)
    try:
        while True:
            now = time.monotonic_ns()
            if now >= deadline:
                timed_out = True
                raise TimeoutError(f"native case exceeded {case['deadline_seconds']} seconds")
            if not gate_created and prepared["definition"]["gate"] and all((capture / (stream + ".log")).is_file() for stream in ("stdout", "stderr")):
                with ready.open("xb") as stream:
                    stream.write(b"ready\n")
                gate_created = True
            trace = read_owned_trace(capture / "effects.bin", module)
            remember_children(trace, process.pid, children)
            control = case.get("control")
            should_send = False
            if control and not control_sent:
                if control.endswith("after_ready"):
                    path = capture / "stdout.log"
                    should_send = path.exists() and path.read_bytes().startswith(b"ready")
                elif control.endswith("after_promotion"):
                    should_send = any(row.get("event", {}).get("kind") == 3 for row in frames)
                if should_send:
                    operation = 3 if control.startswith("cancel") else 4
                    payload = module.frame(operation)
                    pending.extend(payload)
                    controls.append({"operation": operation, "elapsed_ns": now - clock, "frame_hex": payload.hex()})
                    control_sent = True
                    if not input_registered:
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                        input_registered = True
            for key, _ in selector.select(0.01):
                if key.data == "stdin":
                    if pending:
                        count = os.write(process.stdin.fileno(), pending)
                        delivered.extend(pending[:count])
                        del pending[:count]
                    if not pending:
                        selector.unregister(process.stdin)
                        input_registered = False
                else:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    target.extend(chunk)
                    if key.data == "stdout":
                        cursor, additional = decode_frames(stdout, cursor, module)
                        for row in additional:
                            row["observed_elapsed_ns"] = time.monotonic_ns() - clock
                        frames.extend(additional)
            if process.poll() is not None and not any(key.data in ("stdout", "stderr") for key in selector.get_map().values()):
                break
        if pending or cursor != len(stdout):
            raise AssertionError("native fixture ended with undelivered input or an incomplete output frame")
        if control and not control_sent:
            raise AssertionError("requested control was never delivered")
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
        cleanup = emergency_cleanup(process, children, module.frame(4))
        for fileobj, target in ((process.stdout, stdout), (process.stderr, stderr)):
            while True:
                try:
                    data = os.read(fileobj.fileno(), 65536)
                except BlockingIOError:
                    break
                if not data:
                    break
                target.extend(data)
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    finished = time.monotonic_ns()
    (directory / "stdin.bin").write_bytes(delivered)
    (directory / "fixture.stdout").write_bytes(stdout)
    (directory / "fixture.stderr").write_bytes(stderr)
    receipt = {"schema": "hepta.runtime.shell-process-real-native.v1", "argv": argv, "cwd": prepared["directory"], "environment": prepared["environment"], "pid": process.pid, "started_at": started_at, "duration_ns": finished - clock, "deadline_seconds": case["deadline_seconds"], "exit_code": process.poll(), "timed_out": timed_out, "exception": error, "gate_created": gate_created, "controls": controls, "cleanup": cleanup, "observed_child_identities": list(children.values()), "streams": {"stdin": pin(directory / "stdin.bin"), "stdout": pin(directory / "fixture.stdout"), "stderr": pin(directory / "fixture.stderr")}, "executable": pin(executable)}
    json_write(directory / "process.json", receipt)
    json_write(directory / "frames.json", frames)
    try:
        trace = module.decode_trace((capture / "effects.bin").read_bytes(), complete=True)
        captures = {name: (capture / (name + ".log")).read_bytes() for name in ("stdout", "stderr")}
        validation = validate_native(case, receipt, frames, trace, captures, children)
        validation["capture_files"] = {name: pin(capture / (name + ".log")) for name in ("stdout", "stderr")}
        validation["trace_file"] = pin(capture / "effects.bin")
    except BaseException as exc:
        validation = {"status": "FAIL", "type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    json_write(directory / "validation.json", validation)
    return {"name": case["name"], "status": validation["status"], "process": pin(directory / "process.json"), "validation": pin(directory / "validation.json"), "duration_ns": receipt["duration_ns"], "error": validation.get("message")}


def owned_fixture_path(value: str, prepared: dict) -> Path:
    path = Path(value).resolve(strict=True)
    if not path.is_relative_to(Path(prepared["directory"]).resolve(strict=True)) or not path.is_file():
        raise ValueError("oracle returned a path outside this owned fixture")
    return path


def run_original(prepared: dict, executable: Path) -> dict:
    """Only drive original public/private fixture entrypoints; no lifecycle copy."""
    case = prepared["definition"]
    directory = Path(prepared["directory"]) / "original"
    directory.mkdir()
    retained = directory / "retained"
    retained.mkdir()
    ready = Path(prepared["ready_path"])
    if ready.exists():
        ready.unlink()
    request = {"op": "execute", "command": bytes.fromhex(prepared["command_hex"]).decode("utf-8"), "cwd_hex": prepared["cwd_hex"], "timeout_ms": prepared["timeout_ms"], "capture_dir": str(retained)}
    argv = [str(executable), "--fixture"]
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=prepared["directory"], env=prepared["environment"], start_new_session=True)
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    start = time.monotonic_ns()
    started_at = datetime.now(timezone.utc).isoformat()
    selector = selectors.DefaultSelector()
    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    os.set_blocking(process.stdin.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    pending = bytearray((json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n").encode())
    delivered, stdout, stderr = bytearray(), bytearray(), bytearray()
    events, controls, children = [], [], {}
    cursor, input_registered, control_sent, timed_out = 0, True, False, False
    error, cleanup, capture_event = None, [], None
    deadline = start + int(case["deadline_seconds"] * 1_000_000_000)
    try:
        while True:
            now = time.monotonic_ns()
            if now >= deadline:
                timed_out = True
                raise TimeoutError(f"original case exceeded {case['deadline_seconds']} seconds")
            control = case.get("control")
            should_send = False
            if control and not control_sent:
                if control.endswith("after_ready") and capture_event is not None:
                    source = Path(capture_event["stdout_source_path"])
                    should_send = source.exists() and owned_fixture_path(str(source), prepared).read_bytes().startswith(b"ready")
                elif control.endswith("after_promotion"):
                    should_send = any(row["event"] == "promoted" for row in events)
                if should_send:
                    operation = "cancel" if control.startswith("cancel") else "shutdown"
                    payload = (json.dumps({"op": operation}, separators=(",", ":")) + "\n").encode()
                    pending.extend(payload)
                    controls.append({"operation": operation, "elapsed_ns": now - start, "input_hex": payload.hex()})
                    control_sent = True
                    if not input_registered:
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                        input_registered = True
            for key, _ in selector.select(0.01):
                if key.data == "stdin":
                    if pending:
                        count = os.write(process.stdin.fileno(), pending)
                        delivered.extend(pending[:count])
                        del pending[:count]
                    if not pending:
                        selector.unregister(process.stdin)
                        input_registered = False
                else:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    target.extend(chunk)
                    if key.data == "stdout":
                        while True:
                            end = stdout.find(b"\n", cursor)
                            if end < 0:
                                break
                            row = json.loads(bytes(stdout[cursor:end]))
                            cursor = end + 1
                            if row.get("schema") != "hepta.runtime.shell-process-fixture-event.v1" or row.get("event") not in ("started", "capture_ready", "foreground", "promoted", "completion", "cancelled", "shutdown", "final"):
                                raise ValueError(f"unexpected original fixture event: {row}")
                            if row.get("oracle_pid") != process.pid or row.get("seq") != len(events) + 1:
                                raise ValueError("original event identity or sequence changed")
                            if not events and row["event"] != "started":
                                raise ValueError("original fixture did not announce its admitted input")
                            if row["event"] == "started" and (events or row.get("command_hex") != prepared["command_hex"] or row.get("cwd_hex") != prepared["cwd_hex"] or row.get("timeout_ms") != prepared["timeout_ms"] or row.get("capture_dir") != str(retained)):
                                raise ValueError("original fixture input differs from the exact native case")
                            events.append(row)
                            if row["event"] == "capture_ready":
                                if capture_event is not None:
                                    raise ValueError("original published duplicate capture_ready")
                                capture_event = row
                                pid = row["pid"]
                                if type(pid) is not int or pid <= 0 or row["oracle_pid"] != process.pid:
                                    raise ValueError("original capture custody is malformed")
                                identity = process_identity(pid)
                                if identity is None or identity["ppid"] != process.pid:
                                    raise ValueError("capture_ready did not observe an owned live original child")
                                children[pid] = identity
                                for name in ("stdout", "stderr"):
                                    owned_fixture_path(row[name + "_source_path"], prepared)
                                if case["gate"]:
                                    with ready.open("xb") as stream:
                                        stream.write(b"ready\n")
            if process.poll() is not None and not any(key.data in ("stdout", "stderr") for key in selector.get_map().values()):
                break
        if pending or cursor != len(stdout):
            raise ValueError("original exited with incomplete input/output")
        if case.get("control") and not control_sent:
            raise ValueError("original control was never delivered")
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
        cleanup = emergency_cleanup(process, children, b'{"op":"shutdown"}\n')
        for fileobj, target in ((process.stdout, stdout), (process.stderr, stderr)):
            while True:
                try:
                    data = os.read(fileobj.fileno(), 65536)
                except BlockingIOError:
                    break
                if not data:
                    break
                target.extend(data)
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    duration = time.monotonic_ns() - start
    for name, data in (("stdin.jsonl", delivered), ("stdout.jsonl", stdout), ("stderr", stderr)):
        (directory / name).write_bytes(data)
    receipt = {"schema": "hepta.runtime.shell-process-original-controller.v1", "argv": argv, "cwd": prepared["directory"], "environment": prepared["environment"], "pid": process.pid, "started_at": started_at, "duration_ns": duration, "deadline_seconds": case["deadline_seconds"], "exit_code": process.poll(), "timed_out": timed_out, "exception": error, "controls": controls, "cleanup": cleanup, "observed_child_identities": list(children.values()), "streams": {name: pin(directory / filename) for name, filename in (("stdin", "stdin.jsonl"), ("stdout", "stdout.jsonl"), ("stderr", "stderr"))}, "executable": pin(executable)}
    json_write(directory / "process.json", receipt)
    json_write(directory / "events.json", events)
    valid = receipt["exit_code"] == 0 and not timed_out and error is None and not stderr and bool(events) and events[-1]["event"] == "final" and sum(row["event"] == "final" for row in events) == 1
    validation = {"status": "PASS" if valid else "FAIL", "error": error, "event_names": [row["event"] for row in events]}
    json_write(directory / "validation.json", validation)
    return {"name": case["name"], "status": validation["status"], "process": pin(directory / "process.json"), "validation": pin(directory / "validation.json"), "duration_ns": duration, "error": error}


def normalized_session_capture(raw: bytes, shell_pid: int) -> bytes:
    lines = raw.splitlines()
    if len(lines) != 2 or lines[0] != str(shell_pid).encode():
        raise AssertionError("session output does not name its original child")
    values = json.loads(lines[1])
    if set(values) != {"pid", "ppid", "pgid", "sid"} or any(type(value) is not int or value <= 0 for value in values.values()):
        raise AssertionError("invalid session probe shape")
    if any(values[key] != shell_pid for key in ("ppid", "pgid", "sid")) or values["pid"] == shell_pid:
        raise AssertionError("session/group/parent relation is not preserved")
    return b"SHELL_PID\n" + json.dumps({"pid": "PROBE_PID", "ppid": "SHELL_PID", "pgid": "SHELL_PID", "sid": "SHELL_PID"}, sort_keys=True).encode() + b"\n"


def compare_original(prepared: dict) -> dict:
    case = prepared["definition"]
    directory = Path(prepared["directory"])
    native = json.loads((directory / "native/validation.json").read_text())
    original_receipt = json.loads((directory / "original/process.json").read_text())
    original = json.loads((directory / "original/events.json").read_text())
    if native["status"] != "PASS" or original_receipt["exit_code"] != 0 or original_receipt["exception"] is not None:
        raise AssertionError("comparison requires both actual processes to pass")
    finals = [row for row in original if row["event"] == "final"]
    if len(finals) != 1 or original[-1] is not finals[0]:
        raise AssertionError("original did not finish once, last")
    final = finals[0]
    foreground = [row for row in original if row["event"] == "foreground"]
    promoted = [row for row in original if row["event"] == "promoted"]
    completed = [row for row in original if row["event"] == "completion"]
    cancelled = [row for row in original if row["event"] == "cancelled"]
    shut = [row for row in original if row["event"] == "shutdown"]
    capture_ready = [row for row in original if row["event"] == "capture_ready"]
    if len(capture_ready) > 1:
        raise AssertionError("original changed capture ownership")
    original_pid = capture_ready[0]["pid"] if capture_ready else promoted[0]["pid"] if promoted else None
    spawn_failure = "spawn_errno" in case or case.get("spawn_invalid_input", False)
    if spawn_failure:
        if len(foreground) != 1 or foreground[0]["ok"] is not False or promoted or completed:
            raise AssertionError("original spawn failure lifecycle differs")
        if "spawn_errno" in case and foreground[0].get("os_error_from_message") != case["spawn_errno"]:
            raise AssertionError(f"actual original spawn error differs: {foreground[0]}")
        if case.get("spawn_invalid_input") and (foreground[0].get("os_error_from_message") is not None or "nul" not in foreground[0]["error"].lower()):
            raise AssertionError("original did not report its NUL InvalidInput")
    elif case.get("control") == "cancel_after_ready":
        if foreground or promoted or completed or len(cancelled) != 1 or cancelled[0].get("phase") != "foreground" or cancelled[0].get("caller_aborted") is not True:
            raise AssertionError("original cancellation did not drop only its foreground caller")
        if final["outcome"] != "cancelled" or final["callback_count"] != 0 or original_pid not in final["tracker_pids"]:
            raise AssertionError("original cancellation tracking/callback behavior differs")
    elif 3 in case["expected_kinds"]:
        if foreground or len(promoted) != 1 or len(completed) != 1 or promoted[0]["pid"] != original_pid or completed[0]["pid"] != original_pid or completed[0]["job_id"] != promoted[0]["job_id"] or completed[0]["resource_uri"] != promoted[0]["resource_uri"]:
            raise AssertionError("original did not promote/complete the same one child/job")
        if completed[0]["exit_code"] != case["exit_code"] or completed[0]["callback_count"] != 1 or final["callback_count"] != 1:
            raise AssertionError("original background completion status/callback count differs")
    else:
        if len(foreground) != 1 or promoted or completed or final["callback_count"] != 0:
            raise AssertionError("original foreground lifecycle differs")
        if case["exit_code"] == 0:
            if foreground[0]["ok"] is not True:
                raise AssertionError(f"original foreground unexpectedly failed: {foreground[0]}")
        else:
            if foreground[0]["ok"] is not False:
                raise AssertionError("original lost nonzero command exit")
            matched = re.match(r"Command failed with exit code (-?\d+)\n\n", foreground[0]["error"])
            if matched is None or int(matched.group(1)) != case["exit_code"]:
                raise AssertionError("original foreground exit-code message differs")
    if case.get("control") == "cancel_after_promotion":
        if len(cancelled) != 1 or cancelled[0].get("phase") != "background" or cancelled[0].get("background_waiter_aborted") is not False:
            raise AssertionError("original caller cancellation disturbed its moved background waiter")
    elif case.get("control") != "cancel_after_ready" and cancelled:
        raise AssertionError("unsolicited original cancellation")
    expected_shutdown = int(case.get("control") in ("shutdown_after_ready", "shutdown_after_promotion"))
    if len(shut) != expected_shutdown or any(row["reason"] != "explicit" or row["tracker_after"] for row in shut):
        raise AssertionError("original shutdown changed or did not drain tracker")
    if not spawn_failure and final.get("child_reaped_observed") is not True:
        raise AssertionError("original child reap was not actually observed")
    if case.get("control") != "cancel_after_ready" and final["tracker_pids"]:
        raise AssertionError("original retained an unexpected tracked child")
    raw = final["raw_capture"]
    capture_comparison = {"observed": raw["observed"], "normalization": None, "streams": {}}
    if raw["observed"]:
        if raw.get("complete_read_from_original_file_descriptors") is not True or raw.get("original_paths_mutated_by_observer") is not False:
            raise AssertionError("original observer changed the original log lifetime")
        retained_original_paths = bool(promoted or case.get("control") == "cancel_after_ready")
        if raw.get("source_paths_exist") != {"stdout": retained_original_paths, "stderr": retained_original_paths}:
            raise AssertionError("original discard/retention order differs")
        for name in ("stdout", "stderr"):
            original_path = owned_fixture_path(raw[name + "_path"], prepared)
            actual = original_path.read_bytes()
            wanted = (directory / "native/capture" / (name + ".log")).read_bytes()
            if len(actual) != raw[name + "_bytes"]:
                raise AssertionError("original raw capture size receipt differs")
            if name == "stdout" and case.get("observe_session"):
                equal = normalized_session_capture(actual, original_pid) == normalized_session_capture(wanted, native["child_pid"])
                capture_comparison["normalization"] = "session probe PID fields only; all original bytes retained"
            else:
                equal = actual == wanted
            if not equal:
                raise AssertionError(f"complete original/native {name} bytes differ")
            capture_comparison["streams"][name] = {"original": pin(original_path), "native": pin(directory / "native/capture" / (name + ".log")), "equal_under_declared_projection": True}
    elif not spawn_failure:
        raise AssertionError("original did not retain both observable command streams")
    else:
        capture_comparison["reason"] = "original spawn failure discarded logs before observer; no byte equality claimed"
    return {"schema": "hepta.runtime.shell-process-original-comparison.v1", "status": "PASS", "name": case["name"], "original_pid": original_pid, "native_pid": native["child_pid"], "capture_comparison": capture_comparison, "process_lifecycle_projection_equal": True, "foreground_result_formatter_compared": False, "background_resource_renderer_compared": False, "original_raw_wait_status_observable": False, "original_error_errno_is_message_projection": bool(spawn_failure), "production_shell_execution_qualified": False, "whole_runtime_replaced": False}


def run_case(prepared: dict, executable: Path, module, oracle: Path | None) -> dict:
    native = run_native(prepared, executable, module)
    if oracle is None:
        return native
    original = run_original(prepared, oracle)
    try:
        comparison = compare_original(prepared)
    except BaseException as exc:
        comparison = {"status": "FAIL", "name": prepared["name"], "type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    path = Path(prepared["directory"]) / "comparison.json"
    json_write(path, comparison)
    passed = native["status"] == original["status"] == comparison["status"] == "PASS"
    return {"name": prepared["name"], "status": "PASS" if passed else "FAIL", "native": native, "original": original, "comparison": pin(path), "duration_ns": native["duration_ns"] + original["duration_ns"], "error": comparison.get("message")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-executable", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--oracle-executable", type=Path)
    parser.add_argument("--oracle-build-manifest", type=Path)
    parser.add_argument("--cases-source", type=Path, default=CASES_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", dest="names")
    parser.add_argument("--jobs", type=int, default=2, choices=(1, 2))
    args = parser.parse_args()
    executable = args.native_executable.resolve(strict=True)
    manifest = args.native_manifest.resolve(strict=True)
    if bool(args.oracle_executable) != bool(args.oracle_build_manifest):
        raise ValueError("original executable and its build manifest are both required")
    oracle = args.oracle_executable.resolve(strict=True) if args.oracle_executable else None
    oracle_manifest = args.oracle_build_manifest.resolve(strict=True) if args.oracle_build_manifest else None
    if not stat.S_ISREG(executable.stat().st_mode) or not os.access(executable, os.X_OK):
        raise ValueError("native fixture is not an executable regular file")
    args.output.mkdir(parents=True, exist_ok=False)
    module = cases_module(args.cases_source.resolve(strict=True))
    definitions = module.specs()
    if args.names:
        requested = set(args.names)
        known = {row["name"] for row in definitions}
        if not requested <= known or len(requested) != len(args.names):
            raise ValueError("unknown or duplicate selected case")
        definitions = [row for row in definitions if row["name"] in requested]
    initial = {"native_executable": pin(executable), "native_build_manifest": pin(manifest), "cases_source": pin(args.cases_source), "runner_source": pin(Path(__file__))}
    if oracle is not None:
        initial.update({"original_executable": pin(oracle), "original_build_manifest": pin(oracle_manifest)})
    build = json.loads(manifest.read_text())
    if build.get("schema") != "hepta.runtime.shell-process.v1" or build.get("elf_sha256") != initial["native_executable"]["sha256"]:
        raise ValueError("native ELF does not match its actual build manifest")
    if (manifest.parent / build["elf"]).resolve(strict=True) != executable:
        raise ValueError("manifest binds a different executable path")
    json_write(args.output / "inputs.json", initial)
    snapshots = args.output / "input-snapshots"
    snapshots.mkdir()
    for name, identity in initial.items():
        target = snapshots / name
        target.write_bytes(Path(identity["path"]).read_bytes())
        if pin(target)["sha256"] != identity["sha256"]:
            raise ValueError("input changed during snapshot")
    prepared = [module.prepare(row, args.output / row["name"]) for row in definitions]
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        work = {pool.submit(run_case, row, executable, module, oracle): row["name"] for row in prepared}
        for future in as_completed(work):
            name = work[future]
            try:
                result = future.result()
            except BaseException as exc:
                result = {"name": name, "status": "FAIL", "type": type(exc).__name__, "error": str(exc), "traceback": traceback.format_exc()}
                json_write(args.output / name / "runner-failure.json", result)
            results.append(result)
            print(json.dumps({key: result.get(key) for key in ("name", "status", "duration_ns", "error")}), flush=True)
    results.sort(key=lambda row: [item["name"] for item in definitions].index(row["name"]))
    final = {"native_executable": pin(executable), "native_build_manifest": pin(manifest), "cases_source": pin(args.cases_source), "runner_source": pin(Path(__file__))}
    if oracle is not None:
        final.update({"original_executable": pin(oracle), "original_build_manifest": pin(oracle_manifest)})
    immutable = initial == final
    passed = immutable and len(results) == len(definitions) and all(row["status"] == "PASS" for row in results)
    report = {"schema": "hepta.runtime.shell-process-real-os-review.v1", "status": ("ORIGINAL_COMPARISON_PASS" if oracle else "NATIVE_ONLY_PASS") if passed else "FAIL", "inputs_unchanged": immutable, "inputs": initial, "cases": results, "case_count": len(results), "full_case_set": not bool(args.names), "selected_cases": args.names, "fresh_native_processes_executed": True, "fresh_original_process_comparisons_performed": bool(oracle), "fresh_original_rust_build_qualified": False, "matching_source_full_cold_qualified": False, "production_shell_execution_qualified": False, "whole_runtime_replaced": False, "old_stack_removal_qualified": False}
    json_write(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "case_count": len(results), "report": str((args.output / "report.json").resolve())}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
