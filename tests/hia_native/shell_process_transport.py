"""Real OS controls for shell-process transport and descriptor custody.

This is development qualification, not a runtime implementation. Six fixed
controls execute the actual HIA-packed ELF, keep original bytes and observations,
and verify the resulting evidence without rerunning a process.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "tests/hia_native/shell_process_cases.py"
SOURCE = ROOT / "tests/hia_native/shell_process_transport.py"
NAMES = (
    "partial_control", "closed_stderr_success", "closed_stderr_noex",
    "private_fds_cloexec", "promotion_backpressure", "descendant_group_shutdown",
)
SCOPE = {
    "original_rust_compared": False, "production_activated": False,
    "production_shell_execution_qualified": False, "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False,
}


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def non_integer(value):
        raise ValueError("unexpected non-integer JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_float=non_integer,
                      parse_constant=non_integer)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=True, indent=2)
        stream.write("\n")


def raw_file(path: Path) -> bytes:
    if (not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink()
            or path.resolve(strict=True) != path.absolute()):
        raise ValueError("evidence member is not an ordinary file")
    return path.read_bytes()


def pin(path: Path) -> dict:
    raw = raw_file(path)
    return {"size": len(raw), "sha256": digest(raw)}


def source_pins() -> dict:
    return {str(path.relative_to(ROOT)): pin(path) for path in (SOURCE, CASES)}


def cases_module():
    spec = importlib.util.spec_from_file_location("shell_process_transport_cases", CASES)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load shell process cases")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def specifications() -> list[dict]:
    code = (
        "import os,json; d={};\n"
        "for f in os.listdir('/proc/self/fd'):\n"
        " try: d[f]=os.readlink('/proc/self/fd/'+f)\n"
        " except FileNotFoundError: pass\n"
        "print(json.dumps(d,sort_keys=True))"
    )
    python_command = ("exec /usr/bin/python3 -c '" + code.replace("'", "'\\''") + "'").encode()
    descendant_code = (
        "import json,os,time; "
        "print(json.dumps({'ready':True,'pid':os.getpid(),'ppid':os.getppid(),"
        "'pgid':os.getpgid(0),'sid':os.getsid(0)},sort_keys=True),flush=True); "
        "time.sleep(30)"
    )
    # A following shell builtin keeps the shell alive as the direct child.
    descendant_command = ("/usr/bin/python3 -u -c '" + descendant_code.replace("'", "'\\''") + "'\n:").encode()
    return [
        {"name": NAMES[0], "command": b"sleep 0.2; printf 'partial-survived\\n'", "partial": True},
        {"name": NAMES[1], "command": b"printf 'owned-out'; printf 'owned-err' >&2", "close_stderr": True},
        {"name": NAMES[2], "command": b"printf unreachable", "close_stderr": True, "path": "/hia-no-such-directory"},
        {"name": NAMES[3], "command": python_command},
        {"name": NAMES[4], "command": b"sleep 10.25; printf 'after-promotion\\n'", "backpressure": True},
        {"name": NAMES[5], "command": descendant_command, "descendant_shutdown": True},
    ]


def process_identity(pid: int) -> dict | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("incomplete proc stat observation")
    return {
        "pid": pid, "state": fields[0], "ppid": int(fields[1]),
        "pgid": int(fields[2]), "sid": int(fields[3]),
        "starttime_ticks": int(fields[19]), "raw_stat": raw,
    }


def validate_identity(identity: dict | None, pid: int) -> None:
    if identity is None:
        return
    if (type(identity) is not dict or set(identity) != {
        "pid", "state", "ppid", "pgid", "sid", "starttime_ticks", "raw_stat"
    } or identity.get("pid") != pid or type(identity.get("raw_stat")) is not str):
        raise ValueError("proc identity schema differs")
    raw = identity["raw_stat"]
    if not raw.startswith(str(pid) + " (") or ")" not in raw:
        raise ValueError("raw proc PID differs")
    fields = raw[raw.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("incomplete raw proc identity")
    expected = {
        "pid": pid, "state": fields[0], "ppid": int(fields[1]),
        "pgid": int(fields[2]), "sid": int(fields[3]),
        "starttime_ticks": int(fields[19]), "raw_stat": raw,
    }
    if identity != expected:
        raise ValueError("proc identity fields differ from raw stat")


def frames(raw: bytes, module) -> list[dict]:
    result, at = [], 0
    while at < len(raw):
        if len(raw) - at < 16:
            raise ValueError("partial reply header")
        returned, extent = struct.unpack_from("<2Q", raw, at)
        at += 16
        if extent > len(raw) - at or extent not in (0, 96):
            raise ValueError("invalid reply extent")
        body = raw[at:at + extent]
        at += extent
        if (returned, extent) not in ((0, 0), (96, 96)):
            raise ValueError("unexpected owner refusal")
        result.append({"returned": returned, "extent": extent,
                       "event": module.decode_event(body) if extent else None})
    if not result or result[-1] != {"returned": 0, "extent": 0, "event": None}:
        raise ValueError("missing final retirement")
    if any(row["returned"] == 0 for row in result[:-1]):
        raise ValueError("event after retirement")
    return result


def trace_checks(raw: bytes, module, parent_pid: int, *, group_shutdown: bool = False) -> dict:
    trace = module.decode_trace(raw)
    footer = trace["footer"]["words"]
    rows = trace["records"]
    if len(footer) != 15 or footer[14] != 0:
        raise ValueError("audit footer shape differs")
    # parent/child record attempts, error flags, last write results, contract
    # failures, custody, tracker, cached wait, child PID, EOF, transport error.
    if any(footer[i] != 0 for i in (2, 3, 6, 7, 8, 9, 12, 13)):
        raise ValueError("trace failed or custody/tracker was retained")
    forks = [r for r in rows if r["self_pid"] == parent_pid and r["role"] == 1
             and r["action"] == 5 and r["phase"] == 1 and r["errno"] == 0]
    if len(forks) != 1 or forks[0]["result"] <= 0 or forks[0]["aux"] != 1:
        raise ValueError("control requires exactly one observed native child")
    child_pid = forks[0]["result"]
    if footer[10] != 1 or footer[11] != child_pid:
        raise ValueError("child was not reaped before retirement")
    parent_rows = [r for r in rows if r["role"] in (0, 1)]
    child_rows = [r for r in rows if r["role"] == 2]
    if (footer[0], footer[1]) != (len(parent_rows), len(child_rows)):
        raise ValueError("audit record counts differ")
    if footer[4] != 128 or footer[5] != 128:
        raise ValueError("audit write was not complete")
    if any(r["self_pid"] != parent_pid for r in parent_rows):
        raise ValueError("parent trace identity differs")
    if any(r["self_pid"] != child_pid for r in child_rows):
        raise ValueError("child trace identity differs")
    for r in rows:
        if (r["role"] not in (0, 1, 2) or r["child_token"] != 1 or r["phase"] not in (0, 1)
                or r["action"] not in range(1, 20)):
            raise ValueError("trace violates fixed effect contract")
        if r["child_pid"] not in (0, child_pid):
            raise ValueError("trace references a different child")
    def paired(records, first_sequence: int, *, child: bool = False) -> int:
        issued = None
        sequence = first_sequence
        pairs = 0
        for record in records:
            if record["sequence"] != sequence:
                raise ValueError("effect sequence is not consecutive within its actual process")
            if record["phase"] == 0:
                if issued is not None:
                    raise ValueError("a process issued another effect before completing its prior one")
                if any(record[key] != 0 for key in ("result", "errno", "aux", "raw_aux")):
                    raise ValueError("issued effect already contains a forged result")
                issued = record
            else:
                if issued is None or any(record[key] != issued[key] for key in (
                        "sequence", "action", "arg0", "arg1", "arg2", "child_token", "self_pid")):
                    raise ValueError("effect completion differs from its actual issued request")
                issued = None
                sequence += 1
                pairs += 1
        if child:
            if issued is None or issued["action"] not in (11, 12):
                raise ValueError("child trace does not end at exec or the NOEX exit syscall")
        elif issued is not None:
            raise ValueError("parent retired with an unfinished effect")
        return pairs
    parent_pairs = paired(parent_rows, 1)
    first_child = child_rows[0] if child_rows else None
    if (first_child is None or first_child["phase"] != 1 or first_child["action"] != 5
            or first_child["sequence"] != forks[0]["sequence"]
            or first_child["result"] != 0 or first_child["errno"] != 0
            or first_child["aux"] != 1 or first_child["raw_aux"] != 0):
        raise ValueError("child trace does not begin with its inherited fork completion")
    child_pairs = paired(child_rows[1:], first_child["sequence"] + 1, child=True)
    signals = [r for r in rows if r["action"] == 18]
    if not group_shutdown and signals:
        raise ValueError("these controls must not signal a child")
    if group_shutdown:
        if (len(signals) != 2 or [r["phase"] for r in signals] != [0, 1]
                or signals[0]["sequence"] != signals[1]["sequence"]
                or any(r["role"] != 1 or r["self_pid"] != parent_pid
                       or (r["arg0"], r["arg1"], r["arg2"]) != (1, 2, 9)
                       or any(r[k] != 0 for k in ("result", "errno", "aux", "raw_aux"))
                       for r in signals)):
            raise ValueError("descendant shutdown lacks one successful owned group SIGKILL")
    reaps = [r for r in parent_rows if r["action"] == 16 and r["phase"] == 1
             and r["result"] == 1 and r["errno"] == 0 and r["raw_aux"] == child_pid]
    if len(reaps) != 1:
        raise ValueError("missing unique actual wait/reap syscall")
    if group_shutdown:
        if reaps[0]["aux"] != 9:
            raise ValueError("group shutdown did not reap the direct child with SIGKILL status")
        if signals[1]["offset"] >= reaps[0]["offset"]:
            raise ValueError("owned group SIGKILL did not complete before the actual direct-child reap")
    return {"records": len(rows), "footer": footer, "child_pid": child_pid,
            "actual_reap": reaps[0], "group_signal": signals[1] if signals else None,
            "parent_effect_pairs": parent_pairs, "child_effect_pairs": child_pairs,
            "eventual_owner_retirement": True}


def observe_children(case: Path, module, process: subprocess.Popen,
                     identities: dict, observations: list) -> tuple[bytes, dict]:
    try:
        raw = raw_file(case / "capture/effects.bin")
    except FileNotFoundError:
        return b"", {"records": [], "footer": None}
    trace = module.decode_trace(raw, complete=False)
    for r in trace["records"]:
        if (r["self_pid"] != process.pid or r["role"] != 1 or r["action"] != 5
                or r["phase"] != 1 or r["errno"] != 0 or r["result"] <= 0):
            continue
        pid = r["result"]
        if pid in identities:
            continue
        identity = process_identity(pid)
        owned = identity is not None and identity["ppid"] == process.pid
        observations.append({"time_ns": time.monotonic_ns(), "pid": pid,
                             "identity": identity, "owned": owned})
        identities[pid] = identity if owned else None
    return raw, trace


def cleanup_owned(process: subprocess.Popen, identities: dict) -> list[dict]:
    """Failure containment only for observed starttime-bound native children."""
    result = []
    for pid, observed in identities.items():
        current = process_identity(pid)
        if (observed is None or current is None
                or current["starttime_ticks"] != observed["starttime_ticks"]):
            continue
        target = -pid if current["pgid"] == pid and current["sid"] == pid else pid
        entry = {"pid": pid, "identity": current, "target": target,
                 "signal": signal.SIGKILL, "time_ns": time.monotonic_ns()}
        try:
            os.kill(target, signal.SIGKILL)
            entry["errno"] = 0
        except OSError as error:
            entry["errno"] = error.errno
        result.append(entry)
    if process.poll() is None:
        process.kill()
    process.wait(timeout=3)
    return result


def inactive_observation(current: dict | None, owned: dict) -> str | None:
    if current is None:
        return "absent"
    if current["starttime_ticks"] != owned["starttime_ticks"]:
        return "pid-reused"
    if current["state"] == "Z":
        return "zombie-awaiting-system-reap"
    if current["state"] in ("X", "x"):
        return "dead"
    return None


def run_case(definition: dict, output: Path, executable: Path, module) -> dict:
    name = definition["name"]
    case = output / name
    case.mkdir()
    capture = case / "capture"
    capture.mkdir()
    cwd = os.fsencode(case)
    start_frame = module.frame(1, definition["command"], cwd)
    partial = struct.pack("<Q", 40)[:3] if definition.get("partial") else b""
    delivered = bytearray()
    (case / "input.bin").write_bytes(delivered)
    environment = {"PATH": definition.get("path", "/bin:/usr/bin"), "LC_ALL": "C"}
    prefill = bytearray()
    prefill_writes = []
    read_fd = write_fd = None
    if definition.get("backpressure"):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        while True:
            before = time.monotonic_ns()
            try:
                written = os.write(write_fd, b"x" * 4096)
                prefill.extend(b"x" * written)
                prefill_writes.append({"started_ns": before, "finished_ns": time.monotonic_ns(),
                                       "requested": 4096, "result": written, "errno": 0})
            except BlockingIOError as error:
                prefill_writes.append({"started_ns": before, "finished_ns": time.monotonic_ns(),
                                       "requested": 4096, "result": -1, "errno": error.errno})
                break
    (case / "stdout-prefill.bin").write_bytes(prefill)
    write_json(case / "prefill-writes.json", prefill_writes)
    process = None
    parent_identity = None
    raw_output = bytearray()
    raw_stderr = bytearray()
    controls, observations, identities, cleanup = [], [], {}, []
    descendant_identities = {}
    descendant_before = descendant_after = None
    before_drain = None
    exception = None
    timed_out = False
    started_ns = time.monotonic_ns()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    argv = [str(executable), "--process-fixture", str(capture)]
    try:
        kwargs = {}
        if definition.get("close_stderr"):
            kwargs["preexec_fn"] = lambda: os.close(2)
        process = subprocess.Popen(
            argv, cwd=case, env=environment, stdin=subprocess.PIPE,
            stdout=write_fd if write_fd is not None else subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, bufsize=0, **kwargs,
        )
        parent_identity = process_identity(process.pid)
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        for label, part in (("start", start_frame), ("partial_control", partial)):
            if not part:
                continue
            at, sent = time.monotonic_ns(), 0
            while sent < len(part):
                count = os.write(process.stdin.fileno(), part[sent:])
                delivered.extend(part[sent:sent + count])
                sent += count
            controls.append({"kind": label, "started_ns": at, "finished_ns": time.monotonic_ns(),
                             "bytes_hex": part.hex(), "written": sent})
        if definition.get("descendant_shutdown"):
            ready_deadline = time.monotonic() + 4
            while True:
                observe_children(case, module, process, identities, observations)
                try:
                    announcement_bytes = raw_file(capture / "stdout.log")
                except FileNotFoundError:
                    announcement_bytes = b""
                if announcement_bytes.endswith(b"\n"):
                    announcement = strict_json(announcement_bytes)
                    if (type(announcement) is not dict
                            or set(announcement) != {"ready", "pid", "ppid", "pgid", "sid"}
                            or announcement["ready"] is not True
                            or any(type(announcement[key]) is not int or announcement[key] <= 0
                                   for key in ("pid", "ppid", "pgid", "sid"))):
                        raise ValueError("descendant readiness announcement is malformed")
                    direct = identities.get(announcement["ppid"])
                    current_direct = process_identity(announcement["ppid"])
                    worker = process_identity(announcement["pid"])
                    controller = process_identity(process.pid)
                    if (direct is None or current_direct is None or worker is None or controller is None
                            or current_direct["starttime_ticks"] != direct["starttime_ticks"]
                            or current_direct["ppid"] != process.pid
                            or current_direct["pgid"] != direct["pid"] or current_direct["sid"] != direct["pid"]
                            or worker["ppid"] != direct["pid"] or worker["pgid"] != direct["pid"]
                            or worker["sid"] != direct["pid"] or worker["state"] in ("Z", "X", "x")
                            or current_direct["state"] in ("Z", "X", "x")
                            or announcement["pgid"] != worker["pgid"] or announcement["sid"] != worker["sid"]
                            or controller["starttime_ticks"] != parent_identity["starttime_ticks"]):
                        raise ValueError("descendant is not an observed live member of this owned process group")
                    descendant_identities[worker["pid"]] = worker
                    descendant_before = {
                        "schema": "hepta.runtime.shell-process-descendant-before.v1",
                        "observed_ns": time.monotonic_ns(), "announcement_hex": announcement_bytes.hex(),
                        "controller": controller, "direct": current_direct, "descendant": worker,
                    }
                    break
                if process.poll() is not None or time.monotonic() > ready_deadline:
                    timed_out = True
                    raise TimeoutError("descendant did not become ready before group shutdown")
                time.sleep(.005)
            part = module.frame(4)
            at, sent = time.monotonic_ns(), 0
            while sent < len(part):
                count = os.write(process.stdin.fileno(), part[sent:])
                delivered.extend(part[sent:sent + count])
                sent += count
            controls.append({"kind": "group_shutdown", "started_ns": at, "finished_ns": time.monotonic_ns(),
                             "bytes_hex": part.hex(), "written": sent})
        if before_drain is None and definition.get("backpressure"):
            deadline = time.monotonic() + 16
            while True:
                trace_bytes, trace = observe_children(case, module, process, identities, observations)
                completed = [r for r in trace["records"] if r["role"] == 1
                             and r["self_pid"] == process.pid and r["action"] == 16
                             and r["phase"] == 1 and r["result"] == 1 and r["errno"] == 0]
                if completed:
                    if process.poll() is not None:
                        raise AssertionError("controller exited before blocked replies were drained")
                    seen_ns = time.monotonic_ns()
                    before_drain = {
                        "observed_ns": seen_ns, "controller_running": True,
                        "controller_identity": process_identity(process.pid),
                        "actual_reap": completed[-1],
                        "prefilled_bytes": len(prefill),
                        "trace_size": len(trace_bytes), "trace_sha256": digest(trace_bytes),
                        "child_after_reap": process_identity(completed[-1]["child_pid"]),
                    }
                    (case / "trace-before-drain.bin").write_bytes(trace_bytes)
                    break
                if process.poll() is not None:
                    raise AssertionError("controller exited without a pre-drain actual reap")
                if time.monotonic() > deadline:
                    timed_out = True
                    raise TimeoutError("no real reap while output pipe was full")
                time.sleep(.025)
        selector = selectors.DefaultSelector()
        stdout_fd = read_fd if read_fd is not None else process.stdout.fileno()
        selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        read_started_ns = time.monotonic_ns()
        if before_drain is not None:
            before_drain["first_output_read_ns"] = read_started_ns
        deadline = time.monotonic() + 5
        while selector.get_map():
            observe_children(case, module, process, identities, observations)
            if time.monotonic() > deadline:
                timed_out = True
                raise TimeoutError("controller stream completion deadline")
            for key, _ in selector.select(.025):
                chunk = os.read(key.fd, 65536)
                if chunk:
                    (raw_output if key.data == "stdout" else raw_stderr).extend(chunk)
                else:
                    selector.unregister(key.fd)
        process.wait(timeout=2)
        if descendant_before is not None:
            after_rows = []
            nonlive_deadline = time.monotonic() + 2
            while True:
                direct = process_identity(descendant_before["direct"]["pid"])
                worker = process_identity(descendant_before["descendant"]["pid"])
                direct_state = inactive_observation(direct, descendant_before["direct"])
                worker_state = inactive_observation(worker, descendant_before["descendant"])
                after_rows.append({
                    "observed_ns": time.monotonic_ns(), "direct": direct, "descendant": worker,
                    "direct_disposition": direct_state, "descendant_disposition": worker_state,
                })
                if direct_state is not None and worker_state is not None:
                    break
                if time.monotonic() > nonlive_deadline:
                    raise TimeoutError("observed descendant remained live after owned group shutdown")
                time.sleep(.01)
            descendant_after = {
                "schema": "hepta.runtime.shell-process-descendant-after.v1",
                "observations": after_rows, "runtime_reaped_descendant": False,
            }
    except Exception as error:
        exception = {"type": type(error).__name__, "message": str(error)}
        if process is not None:
            try:
                observe_children(case, module, process, identities, observations)
            except Exception as observation_error:
                cleanup.append({"observation_error": type(observation_error).__name__,
                                "message": str(observation_error)})
            try:
                cleanup.extend(cleanup_owned(process, {**identities, **descendant_identities}))
            except Exception as cleanup_error:
                cleanup.append({"exception": type(cleanup_error).__name__,
                                "message": str(cleanup_error)})
    finally:
        finished_ns = time.monotonic_ns()
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
        if process is not None and process.stdin is not None:
            process.stdin.close()
        (case / "input.bin").write_bytes(delivered)
        (case / "raw-stdout.bin").write_bytes(raw_output)
        (case / "raw-stderr.bin").write_bytes(raw_stderr)
        fixture_output = raw_output[len(prefill):] if raw_output[:len(prefill)] == prefill else b""
        (case / "fixture-output.bin").write_bytes(fixture_output)
        write_json(case / "controls.json", controls)
        write_json(case / "proc-observations.json", observations)
        if before_drain is not None:
            write_json(case / "before-drain.json", before_drain)
        if descendant_before is not None:
            write_json(case / "descendant-before.json", descendant_before)
        if descendant_after is not None:
            write_json(case / "descendant-after.json", descendant_after)
        receipt = {
            "schema": "hepta.runtime.shell-process-transport-execution.v1",
            "argv": argv, "cwd": str(case), "env": environment,
            "close_stderr_before_exec": bool(definition.get("close_stderr")),
            "pid": process.pid if process is not None else None,
            "started_at": started_at, "started_ns": started_ns, "finished_ns": finished_ns,
            "duration_ns": finished_ns - started_ns,
            "exit_code": process.returncode if process is not None else None,
            "timed_out": timed_out, "exception": exception,
            "failure_cleanup": cleanup, "prefilled_bytes": len(prefill),
            "controller_identity_at_launch": parent_identity,
            "stdin": pin(case / "input.bin"),
            "stdout": pin(case / "raw-stdout.bin"), "stderr": pin(case / "raw-stderr.bin"),
        }
        write_json(case / "process.json", receipt)
    try:
        validation = validate_case(case, definition, module)
    except Exception as error:
        validation = {"status": "FAIL", "error": type(error).__name__, "message": str(error)}
    write_json(case / "validation.json", validation)
    names = ("input.bin", "stdout-prefill.bin", "prefill-writes.json",
             "raw-stdout.bin", "raw-stderr.bin", "fixture-output.bin",
             "controls.json", "proc-observations.json", "process.json",
             "validation.json", "capture/stdout.log", "capture/stderr.log", "capture/effects.bin")
    files = {name: pin(case / name) for name in names if (case / name).exists()}
    for name in ("trace-before-drain.bin", "before-drain.json", "descendant-before.json", "descendant-after.json"):
        if (case / name).exists():
            files[name] = pin(case / name)
    return {"name": definition["name"], "status": validation["status"],
            "files": files, "error": validation.get("message")}


def validate_case(case: Path, definition: dict, module) -> dict:
    receipt = strict_json(raw_file(case / "process.json"))
    if (receipt["exit_code"] != 0 or receipt["timed_out"]
            or receipt["exception"] is not None or receipt["failure_cleanup"]):
        raise ValueError("fixture process did not finish without containment")
    if type(receipt["pid"]) is not int or receipt["pid"] <= 0:
        raise ValueError("missing actual controller PID")
    if (type(receipt["started_ns"]) is not int or type(receipt["finished_ns"]) is not int
            or receipt["finished_ns"] < receipt["started_ns"]
            or receipt["duration_ns"] != receipt["finished_ns"] - receipt["started_ns"]):
        raise ValueError("execution timing is inconsistent")
    validate_identity(receipt["controller_identity_at_launch"], receipt["pid"])
    observations = strict_json(raw_file(case / "proc-observations.json"))
    if type(observations) is not list:
        raise ValueError("proc observation inventory differs")
    for observation in observations:
        if (type(observation) is not dict or type(observation.get("pid")) is not int
                or type(observation.get("owned")) is not bool
                or type(observation.get("time_ns")) is not int
                or not receipt["started_ns"] <= observation["time_ns"] <= receipt["finished_ns"]):
            raise ValueError("proc observation schema or timing differs")
        identity = observation["identity"]
        validate_identity(identity, observation["pid"])
        expected_owned = identity is not None and identity["ppid"] == receipt["pid"]
        if observation["owned"] is not expected_owned:
            raise ValueError("first child ownership was not bound to the controller PPID")
    initial = module.frame(1, definition["command"], os.fsencode(receipt["cwd"]))
    expected_parts = [("start", initial)]
    if definition.get("partial"):
        expected_parts.append(("partial_control", struct.pack("<Q", 40)[:3]))
    if definition.get("descendant_shutdown"):
        expected_parts.append(("group_shutdown", module.frame(4)))
    if raw_file(case / "input.bin") != b"".join(value for _, value in expected_parts):
        raise ValueError("regenerated complete input differs")
    controls = strict_json(raw_file(case / "controls.json"))
    if len(controls) != len(expected_parts):
        raise ValueError("control segmentation differs")
    last_write = receipt["started_ns"]
    for control, (kind, value) in zip(controls, expected_parts):
        if (control["kind"] != kind or bytes.fromhex(control["bytes_hex"]) != value
                or type(control["written"]) is not int or control["written"] != len(value)
                or type(control["started_ns"]) is not int or type(control["finished_ns"]) is not int
                or not last_write <= control["started_ns"] <= control["finished_ns"] <= receipt["finished_ns"]):
            raise ValueError("actual control write differs")
        last_write = control["finished_ns"]
    if receipt["close_stderr_before_exec"] is not bool(definition.get("close_stderr")):
        raise ValueError("closed-FD control changed")
    if receipt["env"] != {"PATH": definition.get("path", "/bin:/usr/bin"), "LC_ALL": "C"}:
        raise ValueError("fixture environment differs")
    raw = raw_file(case / "raw-stdout.bin")
    prefill = raw_file(case / "stdout-prefill.bin")
    if len(prefill) != receipt["prefilled_bytes"] or raw[:len(prefill)] != prefill:
        raise ValueError("stdout prefill differs")
    fixture = raw_file(case / "fixture-output.bin")
    if fixture != raw[len(prefill):] or raw_file(case / "raw-stderr.bin") != b"":
        raise ValueError("complete native transport streams differ")
    for key, file in (("stdin", "input.bin"), ("stdout", "raw-stdout.bin"), ("stderr", "raw-stderr.bin")):
        if receipt[key] != pin(case / file):
            raise ValueError("process stream receipt differs")
    parsed = frames(fixture, module)
    events = [row["event"] for row in parsed if row["event"] is not None]
    trace_raw = raw_file(case / "capture/effects.bin")
    trace = trace_checks(trace_raw, module, receipt["pid"],
                         group_shutdown=bool(definition.get("descendant_shutdown")))
    stdout, stderr = raw_file(case / "capture/stdout.log"), raw_file(case / "capture/stderr.log")
    kinds = [event["kind"] for event in events]
    expected_kinds = ([6, 2] if definition.get("descendant_shutdown") else [3, 4]
                      if definition.get("backpressure") else [1] if definition["name"] == NAMES[2] else [2])
    if kinds != expected_kinds or any(e["pid"] != trace["child_pid"] for e in events):
        raise ValueError("event kinds or child identity differ")
    if any(e["sequence"] != i + 1 or e["child_token"] != 1 for i, e in enumerate(events)):
        raise ValueError("event sequence or custody token differs")
    if definition["name"] == NAMES[2]:
        if events[0]["error_kind"] != 1 or events[0]["errno"] != 2 or stdout or stderr:
            raise ValueError("closed-stderr NOEX did not preserve ENOENT")
    else:
        wanted_exit = -1 if definition.get("descendant_shutdown") else 0
        if any(e["error_kind"] != 0 for e in events) or events[-1]["exit_code"] != wanted_exit:
            raise ValueError("command exit does not match its registered control")
        if not events[-1]["flags"] & 2:
            raise ValueError("final event was not reaped")
    if definition["name"] == NAMES[0]:
        if stdout != b"partial-survived\n" or stderr:
            raise ValueError("partial frame interfered with child execution")
    if definition["name"] == NAMES[1]:
        if stdout != b"owned-out" or stderr != b"owned-err":
            raise ValueError("closed inherited stderr corrupted capture")
    fd_observation = None
    if definition["name"] == NAMES[3]:
        fd_observation = strict_json(stdout)
        if (set(fd_observation) != {"0", "1", "2"} or stderr
                or fd_observation["0"] != "/dev/null"
                or fd_observation["1"] != receipt["argv"][2] + "/stdout.log"
                or fd_observation["2"] != receipt["argv"][2] + "/stderr.log"):
            raise ValueError("private native descriptor escaped exec")
    descendant_result = None
    if definition.get("descendant_shutdown"):
        before = strict_json(raw_file(case / "descendant-before.json"))
        after = strict_json(raw_file(case / "descendant-after.json"))
        if (type(before) is not dict or set(before) != {
                "schema", "observed_ns", "announcement_hex", "controller", "direct", "descendant"}
                or before["schema"] != "hepta.runtime.shell-process-descendant-before.v1"
                or type(before["observed_ns"]) is not int
                or not controls[0]["finished_ns"] <= before["observed_ns"] <= controls[1]["started_ns"]
                or bytes.fromhex(before["announcement_hex"]) != stdout or stderr):
            raise ValueError("group signal was not gated by the retained descendant readiness bytes")
        announcement = strict_json(stdout)
        if (type(announcement) is not dict or set(announcement) != {"ready", "pid", "ppid", "pgid", "sid"}
                or announcement["ready"] is not True
                or any(type(announcement[key]) is not int or announcement[key] <= 0
                       for key in ("pid", "ppid", "pgid", "sid"))):
            raise ValueError("retained descendant readiness fields differ")
        controller, direct, worker = before["controller"], before["direct"], before["descendant"]
        validate_identity(controller, receipt["pid"])
        validate_identity(direct, trace["child_pid"])
        validate_identity(worker, announcement["pid"])
        if (controller is None or direct is None or worker is None
                or controller["starttime_ticks"] != receipt["controller_identity_at_launch"]["starttime_ticks"]
                or len({controller["pid"], direct["pid"], worker["pid"]}) != 3
                or direct["ppid"] != controller["pid"] or worker["ppid"] != direct["pid"]
                or direct["pgid"] != direct["pid"] or direct["sid"] != direct["pid"]
                or worker["pgid"] != direct["pid"] or worker["sid"] != direct["pid"]
                or announcement["ppid"] != direct["pid"] or announcement["pgid"] != worker["pgid"]
                or announcement["sid"] != worker["sid"]
                or direct["state"] in ("Z", "X", "x") or worker["state"] in ("Z", "X", "x")
                or worker["starttime_ticks"] < direct["starttime_ticks"]):
            raise ValueError("saved descendant PPID/PGID/SID/starttime does not bind the actual owned group")
        direct_observations = [row["identity"] for row in observations
                               if row["owned"] and row["pid"] == direct["pid"]]
        if (len(direct_observations) != 1
                or direct_observations[0]["starttime_ticks"] != direct["starttime_ticks"]):
            raise ValueError("group leader was not first observed as this controller's actual child")
        if (type(after) is not dict or set(after) != {"schema", "observations", "runtime_reaped_descendant"}
                or after["schema"] != "hepta.runtime.shell-process-descendant-after.v1"
                or after["runtime_reaped_descendant"] is not False
                or type(after["observations"]) is not list or not after["observations"]):
            raise ValueError("missing saved post-shutdown descendant observations")
        last_time = controls[1]["finished_ns"]
        last_states = None
        for observation in after["observations"]:
            if (type(observation) is not dict or set(observation) != {
                    "observed_ns", "direct", "descendant", "direct_disposition", "descendant_disposition"}
                    or type(observation["observed_ns"]) is not int
                    or not last_time <= observation["observed_ns"] <= receipt["finished_ns"]):
                raise ValueError("post-shutdown observation timing differs")
            last_time = observation["observed_ns"]
            validate_identity(observation["direct"], direct["pid"])
            validate_identity(observation["descendant"], worker["pid"])
            last_states = (inactive_observation(observation["direct"], direct),
                           inactive_observation(observation["descendant"], worker))
            if (observation["direct_disposition"], observation["descendant_disposition"]) != last_states:
                raise ValueError("post-shutdown disposition is not reconstructed from retained proc bytes")
        if (last_states[0] not in ("absent", "pid-reused") or last_states[1] is None
                or events[-1]["wait_status"] != 9):
            raise ValueError("owned direct child was not reaped or observed descendant remained live")
        descendant_result = {
            "direct_pid": direct["pid"], "descendant_pid": worker["pid"],
            "descendant_ppid_pgid_sid_verified": True,
            "descendant_nonlive_after_group_signal": True,
            "direct_disposition": last_states[0], "descendant_disposition": last_states[1],
            "runtime_reaped_descendant": False,
        }
    pre_drain = None
    if definition.get("backpressure"):
        writes = strict_json(raw_file(case / "prefill-writes.json"))
        if not prefill or prefill != b"x" * len(prefill):
            raise ValueError("pipe was not prefilled with exact known bytes")
        if not writes or writes[-1]["result"] != -1 or writes[-1]["errno"] not in (11, 35):
            raise ValueError("pipe fullness was not actually observed")
        if sum(w["result"] for w in writes if w["result"] > 0) != len(prefill):
            raise ValueError("prefill syscall extents differ")
        pre_drain = strict_json(raw_file(case / "before-drain.json"))
        early = raw_file(case / "trace-before-drain.bin")
        if (digest(early) != pre_drain["trace_sha256"] or len(early) != pre_drain["trace_size"]
                or not trace_raw.startswith(early)):
            raise ValueError("pre-drain trace is not an actual prefix")
        early_rows = module.decode_trace(early, complete=False)["records"]
        observed = pre_drain["actual_reap"]
        if (observed not in early_rows or observed["role"] != 1
                or observed["self_pid"] != receipt["pid"] or observed["action"] != 16
                or observed["phase"] != 1 or observed["result"] != 1
                or observed["errno"] != 0 or observed["raw_aux"] != trace["child_pid"]):
            raise ValueError("missing actual successful wait before draining")
        if (pre_drain["controller_running"] is not True
                or pre_drain["observed_ns"] >= pre_drain["first_output_read_ns"]
                or pre_drain["controller_identity"]["pid"] != receipt["pid"]
                or pre_drain["controller_identity"]["starttime_ticks"]
                   != receipt["controller_identity_at_launch"]["starttime_ticks"]
                or pre_drain["prefilled_bytes"] != len(prefill)):
            raise ValueError("backpressure timing receipt differs")
        validate_identity(pre_drain["controller_identity"], receipt["pid"])
        after = pre_drain["child_after_reap"]
        validate_identity(after, trace["child_pid"])
        seen = strict_json(raw_file(case / "proc-observations.json"))
        owned_seen = [x["identity"] for x in seen if x.get("owned")
                      and x["pid"] == trace["child_pid"]]
        if len(owned_seen) != 1:
            raise ValueError("backpressure child lacks a unique PPID-bound live observation")
        if after is not None and any(after["starttime_ticks"] == x["starttime_ticks"] for x in owned_seen):
            raise ValueError("same observed child remains after the claimed reap")
        if stdout != b"after-promotion\n" or stderr:
            raise ValueError("backpressure changed semantic log bytes")
    elif prefill or strict_json(raw_file(case / "prefill-writes.json")):
        raise ValueError("unexpected prefill in ordinary control")
    return {"status": "PASS", "event_kinds": kinds, "events": events,
            "trace": trace, "fd_observation": fd_observation,
            "backpressure_reap_observed_before_output_read": pre_drain is not None,
            "descendant_group_shutdown": descendant_result}



class ReadOnlyViolation(RuntimeError):
    pass


def readonly_audit(event, args):
    forbidden = {
        "subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
        "os.exec", "os.kill", "os.killpg", "ctypes.dlopen", "ctypes.dlsym", "mmap.__new__",
        "os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown",
        "os.utime", "os.link", "os.symlink", "shutil.copyfile", "shutil.rmtree",
    }
    if event in forbidden:
        raise ReadOnlyViolation("read-only transport verifier attempted " + event)
    if event in ("open", "os.listdir", "os.scandir") and args:
        path = args[0]
        if isinstance(path, (str, bytes, os.PathLike)):
            value = os.fsencode(path)
            if value == b"/proc" or value.startswith(b"/proc/"):
                raise ReadOnlyViolation("read-only transport verifier inspected live /proc")
        if event == "open":
            mode, flags = args[1], args[2]
            if (type(mode) is str and any(x in mode for x in "wax+")
                    or type(flags) is int and flags & (
                        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                raise ReadOnlyViolation("read-only transport verifier wrote a file")


def reorder_group_signal(raw: bytes, module, parent_pid: int) -> bytes:
    """One registered physical recipe: move both signal records past the reap."""
    trace_checks(raw, module, parent_pid, group_shutdown=True)
    rows = module.decode_trace(raw)["records"]
    moved = [raw[row["offset"]:row["offset"] + 128] for row in rows if row["action"] == 18]
    kept = [raw[row["offset"]:row["offset"] + 128] for row in rows if row["action"] != 18]
    if len(moved) != 2:
        raise ValueError("trace-order control lacks one exact signal pair")
    result = b"".join(kept + moved) + raw[-128:]
    if len(result) != len(raw) or result == raw:
        raise ValueError("trace-order recipe made no physical change")
    return result


def trace_verdict(raw: bytes, module, parent_pid: int, audited: bool) -> dict:
    try:
        trace_checks(raw, module, parent_pid, group_shutdown=True)
        return {"status": "PASS", "read_only_audit_enforced": audited, **SCOPE}
    except (ValueError, KeyError, TypeError, AssertionError) as error:
        return {"status": "REJECTED", "error_type": type(error).__name__, "message": str(error),
                "read_only_audit_enforced": audited, **SCOPE}


def run_order_control(output: Path, module) -> dict:
    folder = output / "trace-order-control"
    folder.mkdir()
    case = output / "descendant_group_shutdown"
    parent_pid = strict_json(raw_file(case / "process.json"))["pid"]
    original = raw_file(case / "capture/effects.bin")
    mutated = reorder_group_signal(original, module, parent_pid)
    (folder / "trace.bin").write_bytes(mutated)
    python = Path(sys.executable).resolve(strict=True)
    argv = [str(python), "-B", str(SOURCE), "--verify-trace", str(folder / "trace.bin"),
            "--parent-pid", str(parent_pid), "--audit-read-only"]
    environment = {"PATH": os.defpath, "LC_ALL": "C", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    source_before, python_before = pin(SOURCE), pin(python)
    started = time.monotonic_ns()
    process = None
    stdout = stderr = b""
    timed_out, error = False, None
    try:
        process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    except Exception as failure:
        error = {"type": type(failure).__name__, "message": str(failure)}
        if process is not None and process.poll() is None:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    finished = time.monotonic_ns()
    (folder / "stdout.bin").write_bytes(stdout)
    (folder / "stderr.bin").write_bytes(stderr)
    receipt = {
        "schema": "hepta.runtime.shell-process-transport-order-process.v1",
        "argv": argv, "cwd": str(ROOT), "environment": environment,
        "python": {"path": str(python), **python_before}, "python_after": pin(python),
        "entrypoint": {"path": str(SOURCE), **source_before}, "entrypoint_after": pin(SOURCE),
        "pid": process.pid if process is not None else None,
        "started_ns": started, "finished_ns": finished, "duration_ns": finished - started,
        "deadline_ms": 10000, "exit_code": process.returncode if process is not None else None,
        "timed_out": timed_out, "exception": error,
        "original_trace": pin(case / "capture/effects.bin"), "input": pin(folder / "trace.bin"),
        "stdout": pin(folder / "stdout.bin"), "stderr": pin(folder / "stderr.bin"),
    }
    write_json(folder / "process.json", receipt)
    verdict = trace_verdict(mutated, module, parent_pid, True)
    expected = (json.dumps(verdict, sort_keys=True) + "\n").encode()
    valid = (
        receipt["exit_code"] == 1 and not timed_out and error is None and not stderr
        and source_before == receipt["entrypoint_after"] and python_before == receipt["python_after"]
        and verdict["status"] == "REJECTED" and stdout == expected
    )
    validation = {"status": "PASS" if valid else "FAIL", "verdict": verdict}
    write_json(folder / "validation.json", validation)
    return {"status": validation["status"], "recipe": "group-signal-after-direct-reap",
            "files": {name: pin(folder / name) for name in (
                "trace.bin", "stdout.bin", "stderr.bin", "process.json", "validation.json")}}


def read_order_control(output: Path, recorded: dict, module) -> None:
    folder = output / "trace-order-control"
    names = {"trace.bin", "stdout.bin", "stderr.bin", "process.json", "validation.json"}
    if (type(recorded) is not dict or recorded.get("status") != "PASS"
            or recorded.get("recipe") != "group-signal-after-direct-reap"
            or set(recorded.get("files", {})) != names):
        raise ValueError("missing registered physical trace-order refusal")
    for name in names:
        if pin(folder / name) != recorded["files"][name]:
            raise ValueError("physical trace-order control member changed")
    case = output / "descendant_group_shutdown"
    native = strict_json(raw_file(case / "process.json"))
    parent_pid = native["pid"]
    original = raw_file(case / "capture/effects.bin")
    mutated = raw_file(folder / "trace.bin")
    if mutated != reorder_group_signal(original, module, parent_pid):
        raise ValueError("trace-order bytes are not the named deterministic mutation")
    receipt = strict_json(raw_file(folder / "process.json"))
    source = Path(receipt["entrypoint"]["path"])
    python = Path(receipt["python"]["path"])
    expected_trace_path = Path(native["cwd"]).parent / "trace-order-control/trace.bin"
    argv = [str(python), "-B", str(source), "--verify-trace", str(expected_trace_path),
            "--parent-pid", str(parent_pid), "--audit-read-only"]
    environment = {"PATH": os.defpath, "LC_ALL": "C", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    python_pin = {key: receipt["python"][key] for key in ("size", "sha256")}
    if (type(python_pin["size"]) is not int or python_pin["size"] <= 0
            or type(python_pin["sha256"]) is not str or len(python_pin["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in python_pin["sha256"])
            or not python.is_absolute() or ".." in python.parts
            or set(receipt["python"]) != {"path", "size", "sha256"}):
        raise ValueError("actual trace-reader interpreter identity is malformed")
    if (receipt.get("schema") != "hepta.runtime.shell-process-transport-order-process.v1"
            or receipt.get("argv") != argv
            or not source.is_absolute() or ".." in source.parts
            or source.parts[-3:] != ("tests", "hia_native", "shell_process_transport.py")
            or receipt.get("cwd") != str(source.parents[2])
            or receipt.get("environment") != environment
            or receipt.get("entrypoint") != {"path": str(source), **pin(SOURCE)}
            or receipt.get("entrypoint_after") != pin(SOURCE)
            or receipt.get("python_after") != python_pin
            or type(receipt.get("pid")) is not int or receipt["pid"] <= 0
            or receipt.get("exit_code") != 1 or receipt.get("timed_out") is not False
            or receipt.get("exception") is not None or receipt.get("deadline_ms") != 10000
            or type(receipt.get("started_ns")) is not int
            or type(receipt.get("finished_ns")) is not int
            or not 0 <= receipt["started_ns"] <= receipt["finished_ns"]
            or receipt.get("duration_ns") != receipt["finished_ns"] - receipt["started_ns"]
            or not 0 <= receipt["duration_ns"] <= 15_000_000_000
            or receipt.get("original_trace") != pin(case / "capture/effects.bin")
            or receipt.get("input") != pin(folder / "trace.bin")
            or receipt.get("stdout") != pin(folder / "stdout.bin")
            or receipt.get("stderr") != pin(folder / "stderr.bin")
            or raw_file(folder / "stderr.bin") != b""):
        raise ValueError("actual trace-order refusal process receipt differs")
    verdict = trace_verdict(mutated, module, parent_pid, True)
    if (verdict["status"] != "REJECTED"
            or raw_file(folder / "stdout.bin") != (json.dumps(verdict, sort_keys=True) + "\n").encode()
            or strict_json(raw_file(folder / "validation.json")) != {"status": "PASS", "verdict": verdict}):
        raise ValueError("actual trace-order refusal was not reconstructed from retained raw bytes")


def native_binding(manifest: Path) -> tuple[dict, Path]:
    manifest = manifest.resolve(strict=True)
    metadata = strict_json(raw_file(manifest))
    if (metadata.get("schema") != "hepta.runtime.shell-process.v1"
            or metadata.get("elf") != "shell-process.elf"
            or metadata.get("runtime_python_required") is not False
            or metadata.get("runtime_libc_required") is not False
            or any(metadata.get(k) is not False for k in (
                "production_activated", "production_shell_execution_qualified",
                "whole_runtime_replaced", "old_stack_removal_qualified"))):
        raise ValueError("wrong native executable manifest")
    executable = manifest.parent / metadata["elf"]
    if pin(executable)["sha256"] != metadata.get("elf_sha256"):
        raise ValueError("actual native executable differs")
    return {"manifest": pin(manifest), "elf": pin(executable),
            "manifest_path": str(manifest), "executable_path": str(executable),
            "owner_source_sha256": metadata["owner_source_sha256"],
            "adapter_source_sha256": metadata["adapter_source_sha256"]}, executable


def run(native_manifest: Path, output: Path) -> dict:
    binding, executable = native_binding(native_manifest)
    pins = source_pins()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    module = cases_module()
    for relative in pins:
        snapshot = output / "source-snapshots" / relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(raw_file(ROOT / relative))
    (output / "native-manifest.json").write_bytes(raw_file(native_manifest.resolve()))
    (output / "native.elf").write_bytes(raw_file(executable))
    rows = []
    for definition in specifications():
        rows.append(run_case(definition, output, executable, module))
    order_control = run_order_control(output, module) if all(row["status"] == "PASS" for row in rows) else None
    changed = source_pins() != pins or native_binding(native_manifest)[0] != binding
    report = {
        "schema": "hepta.runtime.shell-process-transport.v1",
        "status": "PASS" if not changed and all(row["status"] == "PASS" for row in rows)
                          and order_control is not None and order_control["status"] == "PASS" else "FAIL",
        "source_or_executable_changed": changed, "source_files": pins, "native": binding, "case_count": len(rows),
        "cases": rows, "trace_order_control": order_control, **SCOPE,
    }
    write_json(output / "report.json", report)
    return report


def read_evidence(folder: Path, native_manifest: Path | None = None) -> dict:
    """Verify recorded byte evidence only; never execute or rewrite artifacts."""
    folder = folder.resolve(strict=True)
    report = strict_json(raw_file(folder / "report.json"))
    if (type(report) is not dict or report.get("schema") != "hepta.runtime.shell-process-transport.v1"
            or report.get("status") != "PASS"
            or report.get("source_files") != source_pins()
            or report.get("source_or_executable_changed") is not False
            or report.get("case_count") != len(NAMES)):
        raise ValueError("transport qualification identity differs")
    if any(report.get(key) is not value for key, value in SCOPE.items()):
        raise ValueError("transport evidence overclaims its scope")
    if native_manifest is not None:
        current, _ = native_binding(native_manifest)
        # Downloaded artifacts may be relocated; bytes bind independently of the
        # producer's recorded paths. This is not a claim of strong path replay.
        for key in ("manifest", "elf", "owner_source_sha256", "adapter_source_sha256"):
            if current[key] != report["native"][key]:
                raise ValueError("native source/image binding differs")
    for relative, expected_pin in report["source_files"].items():
        if pin(folder / "source-snapshots" / relative) != expected_pin:
            raise ValueError("sealed producer source differs")
    if (pin(folder / "native-manifest.json") != report["native"]["manifest"]
            or pin(folder / "native.elf") != report["native"]["elf"]):
        raise ValueError("sealed native manifest or executable differs")
    sealed = strict_json(raw_file(folder / "native-manifest.json"))
    sealed_elf = raw_file(folder / "native.elf")
    if (type(sealed) is not dict or sealed.get("schema") != "hepta.runtime.shell-process.v1"
            or sealed.get("elf_sha256") != digest(sealed_elf)
            or sealed.get("owner_source_sha256") != report["native"]["owner_source_sha256"]
            or sealed.get("adapter_source_sha256") != report["native"]["adapter_source_sha256"]
            or sealed.get("runtime_python_required") is not False
            or sealed.get("runtime_libc_required") is not False
            or any(sealed.get(key) is not False for key in (
                "production_activated", "production_shell_execution_qualified",
                "whole_runtime_replaced", "old_stack_removal_qualified"))):
        raise ValueError("sealed native source/image or scope binding differs")
    rows = report.get("cases")
    if (type(rows) is not list or any(type(row) is not dict for row in rows)
            or [row.get("name") for row in rows] != list(NAMES)):
        raise ValueError("transport case inventory differs")
    module = cases_module()
    for row, definition in zip(rows, specifications()):
        if row.get("status") != "PASS":
            raise ValueError("failed transport case")
        case = folder / definition["name"]
        expected = {
            "input.bin", "stdout-prefill.bin", "prefill-writes.json", "raw-stdout.bin",
            "raw-stderr.bin", "fixture-output.bin", "controls.json", "proc-observations.json",
            "process.json", "validation.json", "capture/stdout.log", "capture/stderr.log",
            "capture/effects.bin",
        }
        if definition.get("backpressure"):
            expected |= {"trace-before-drain.bin", "before-drain.json"}
        if definition.get("descendant_shutdown"):
            expected |= {"descendant-before.json", "descendant-after.json"}
        if set(row["files"]) != expected:
            raise ValueError("transport file inventory differs")
        for relative in expected:
            if pin(case / relative) != row["files"][relative]:
                raise ValueError("transport evidence member changed: " + relative)
        receipt = strict_json(raw_file(case / "process.json"))
        if (receipt["argv"][0] != report["native"]["executable_path"]
                or receipt["argv"][1] != "--process-fixture"
                or len(receipt["argv"]) != 3):
            raise ValueError("actual recorded invocation differs")
        reconstructed = validate_case(case, definition, module)
        if reconstructed != strict_json(raw_file(case / "validation.json")):
            raise ValueError("transport validation was not reconstructed from raw evidence")
    read_order_control(folder, report.get("trace_order_control"), module)
    return {"status": "PASS", "cases": len(NAMES), "trace_order_refusals": 1,
            "verification": "portable-byte-evidence",
            "current_native_binding_checked": native_manifest is not None, **SCOPE}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--verify-trace", type=Path)
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--audit-read-only", action="store_true")
    args = parser.parse_args()
    if args.verify_trace is not None:
        if args.parent_pid is None or args.parent_pid <= 0:
            parser.error("--verify-trace requires a positive --parent-pid")
        module = cases_module()
        if args.audit_read_only:
            sys.addaudithook(readonly_audit)
        try:
            result = trace_verdict(raw_file(args.verify_trace), module, args.parent_pid, args.audit_read_only)
        except ReadOnlyViolation as error:
            print(json.dumps({"status": "READ_ONLY_VIOLATION", "message": str(error), **SCOPE},
                             sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "PASS" else 1
    if args.audit_read_only:
        if args.verify is None:
            parser.error("--audit-read-only requires --verify or --verify-trace")
        sys.addaudithook(readonly_audit)
    if args.verify is not None:
        result = read_evidence(args.verify, args.native_manifest)
    else:
        if args.native_manifest is None or args.output is None:
            parser.error("--native-manifest and --output are required for actual execution")
        result = run(args.native_manifest, args.output)
        if result["status"] == "PASS":
            result = read_evidence(args.output, args.native_manifest)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
