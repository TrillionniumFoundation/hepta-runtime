"""Real Linux foreground IO through the HIA owner; pure retained-evidence reader.

The prepared capture token and wait value are fixture inputs. This suite does not
claim native process wait, original capture preparation or production dispatch.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests/hia_native")]
from hia_native_build import json_bytes, write_new
from hia_native_shell_output_build import read_evidence as read_build
from hia_native_shell_process_build import ordinary, pin, sha, strict_json
from shell_output_original_io import io_specs
U64 = (1 << 64) - 1
SCOPE = {
    "production_activated": False, "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
    "actual_native_process_wait": False, "original_capture_preparation_qualified": False,
}
SOURCES = ("tests/hia_native/shell_output_io.py",
           "tests/hia_native/shell_output_original_io.py")
SCHEMA = "hepta.runtime.shell-output-io.v1"
CASE_SCHEMA = "hepta.runtime.shell-output-io-case.v1"
DEADLINE_NS = 30_000_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def specs():
    result = io_specs()
    def add(name, out=b"alpha\n", err=b"beta\n", **kw):
        result.append({"name": name, "stdout_hex": out.hex(), "stderr_hex": err.hex(),
                       "exit_code": 0, "faults": [], **kw})
    add("empty", b"", b"")
    add("binary", bytes(range(256)) + b"\0\xff\r\n", b"\x80\x81\0end")
    add("large_repeated", b"", b"",
        stdout_recipe={"repeat_hex": b"same\n".hex(), "count": 1_900_000})
    add("append_after_metadata", b"old\n", b"err\n",
        hook={"at": "first_read", "op": "append", "bytes_hex": b"grown\n".hex()})
    add("truncate_after_metadata", b"initial-long-value\n", b"err\n",
        hook={"at": "first_read", "op": "truncate", "bytes_hex": b"new".hex()})
    add("replace_after_open", b"held-old\n", b"err\n",
        hook={"at": "first_metadata", "op": "replace_file",
              "bytes_hex": b"path-new\n".hex()})
    add("unlink_after_open", b"held-old\n", b"err\n",
        hook={"at": "first_metadata", "op": "unlink"})
    add("cancel_before_open", hook={"at": "admit", "op": "cancel"})
    add("cancel_during_read", b"a"*10_000, b"later\n",
        hook={"at": "first_read", "op": "cancel"})
    add("cancel_during_unlink",
        hook={"at": "first_unlink", "op": "cancel"})
    add("fifo_eintr", b"old-held\n", b"err\n",
        faults=[{"stream": "stdout", "op": "replace_fifo"}],
        fifo_hex=b"fifo-after-interrupt\n".hex())
    add("symlink_before_open", b"held-old\n", b"err\n",
        faults=[{"stream": "stdout", "op": "replace_symlink",
                 "replacement_hex": b"owned-target\n".hex()}])
    add("initial_reservation_oom", b"a"*5000, b"beta\n",
        allocation={"stage": "initial"})
    add("probe_extension_oom", b"a"*5000, b"beta\n",
        allocation={"stage": "probe"},
        hook={"at": "first_read", "op": "append", "bytes_hex": (b"b"*32).hex()})
    require(len(result) == 20 and len({x["name"] for x in result}) == len(result),
            "registered IO corpus differs")
    return result


def initial_bytes(spec, stream):
    if stream + "_recipe" in spec:
        recipe = spec[stream + "_recipe"]
        return bytes.fromhex(recipe["repeat_hex"]) * recipe["count"]
    return bytes.fromhex(spec[stream + "_hex"])


def expected_reads(spec):
    result = {name: (0, 0, initial_bytes(spec, name)) for name in ("stdout", "stderr")}
    for fault in spec["faults"]:
        name, op = fault["stream"], fault["op"]
        if op == "unlink":
            result[name] = (2, 2, b"")
        elif op == "replace_dir":
            result[name] = (2, 21, b"")
        elif op in ("replace_file", "replace_symlink"):
            result[name] = (0, 0, bytes.fromhex(fault["replacement_hex"]))
        elif op == "replace_fifo":
            result[name] = (0, 0, bytes.fromhex(spec["fifo_hex"]))
        else:
            raise ValueError("unknown registered fault")
    hook = spec.get("hook", {})
    if hook.get("op") == "append":
        old = result["stdout"][2]
        result["stdout"] = (0, 0, old + bytes.fromhex(hook["bytes_hex"]))
    elif hook.get("op") == "truncate":
        result["stdout"] = (0, 0, bytes.fromhex(hook["bytes_hex"]))
    if spec.get("allocation", {}).get("stage") == "initial":
        result["stdout"] = (3, 0, b"")
    return result


def frame(spec, op=1):
    return b"HSHOIQ01" + struct.pack("<4Q", op, 1, 0, spec["exit_code"] << 8)


def signed(value):
    return value if value < 1 << 63 else value - (1 << 64)


def info(path):
    s = path.lstat()
    kind = ("regular" if stat.S_ISREG(s.st_mode) else
            "directory" if stat.S_ISDIR(s.st_mode) else
            "symlink" if stat.S_ISLNK(s.st_mode) else
            "fifo" if stat.S_ISFIFO(s.st_mode) else "special")
    result = {"type": kind, "mode": stat.S_IMODE(s.st_mode), "dev": s.st_dev,
              "ino": s.st_ino, "nlink": s.st_nlink, "size": s.st_size,
              "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}
    if kind == "symlink":
        result["target_hex"] = os.fsencode(os.readlink(path)).hex()
    return result


def exists(path):
    return os.path.lexists(path)


def parse_process_identity(raw):
    require(b"(" in raw and b")" in raw, "process stat syntax")
    pid = int(raw.split(b"(", 1)[0].strip())
    fields = raw[raw.rfind(b")") + 2:].split()
    require(len(fields) >= 20, "process stat fields")
    return {"pid": pid, "ppid": int(fields[1]), "state": fields[0].decode("ascii"),
            "starttime": int(fields[19]), "stat_hex": raw.hex()}


def process_identity(pid):
    result = parse_process_identity(Path("/proc", str(pid), "stat").read_bytes())
    require(result["pid"] == pid, "process stat PID differs")
    return result


def identity_matches(before, after):
    return before["pid"] == after["pid"] and before["starttime"] == after["starttime"]


def exact(fd, n, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(data) < n:
            left = deadline - time.monotonic_ns()
            if left <= 0 or not selector.select(left / 1e9):
                raise TimeoutError("fixture output deadline")
            part = os.read(fd, min(n - len(data), 1 << 20))
            if not part:
                raise EOFError(bytes(data))
            data.extend(part)
    return bytes(data)


def send(fd, raw):
    view = memoryview(raw)
    while view:
        n = os.write(fd, view)
        require(n > 0, "stdin write returned zero")
        view = view[n:]


def inspect_stat(raw, statx=False):
    if statx:
        require(len(raw) == 256, "statx payload extent")
        return {"ino": struct.unpack_from("<Q", raw, 32)[0],
                "size": struct.unpack_from("<Q", raw, 40)[0],
                "mode": struct.unpack_from("<H", raw, 28)[0],
                "dev": os.makedev(*struct.unpack_from("<II", raw, 136))}
    require(len(raw) == 144, "stat payload extent")
    return {"ino": struct.unpack_from("<Q", raw, 8)[0],
            "size": struct.unpack_from("<Q", raw, 48)[0],
            "mode": struct.unpack_from("<I", raw, 24)[0],
            "dev": struct.unpack_from("<Q", raw)[0]}


def decode_trace(raw, *, allow_fatal=False):
    records = []
    at = 0
    while raw[at:at+8] == b"HSHOITR1":
        require(len(raw) - at >= 128, "short effect record")
        q = struct.unpack_from("<16Q", raw, at)
        size = q[14]
        require(size <= len(raw) - at - 128 and q[15] == 0, "effect payload bounds")
        records.append({"offset": at, "q": q, "payload": raw[at+128:at+128+size]})
        at += 128 + size
    if allow_fatal and at == len(raw):
        require(records and records[-1]["q"][2:4] == (11, 0), "fatal audit has no issued abort")
        return records, None
    require(len(raw) - at == 128 and raw[at:at+8] == b"HSHOIAU1",
            "missing/extra effect footer")
    return records, struct.unpack_from("<16Q", raw, at)


def transport_prefix(raw):
    require(len(raw) >= 64 and raw[:8] == b"HSHOIRD1", "missing complete READY")
    ready = struct.unpack_from("<8Q", raw)
    gates = []
    at = 64
    while raw[at:at+8] == b"HSHOIGT1":
        require(len(raw) - at >= 64, "short gate record")
        q = struct.unpack_from("<8Q", raw, at)
        require(q[6:] == (0, 0), "gate reserved field")
        gates.append(q)
        at += 64
    return ready, gates, at


def decode_transport(raw):
    ready, gates, at = transport_prefix(raw)
    require(len(raw) - at >= 16, "missing final output")
    returned, extent = struct.unpack_from("<2Q", raw, at)
    require(returned == 64 and len(raw) - at - 16 == extent and extent >= 64,
            "final output extent/return")
    descriptor = struct.unpack_from("<8Q", raw, at + 16)
    require(raw[at+16:at+24] == b"HSHOID01" and descriptor[2] == 1
            and descriptor[5:] == (0, 0, 0), "descriptor identity/reserved")
    loan = raw[at+80:]
    if descriptor[1] == 1:
        require(descriptor[3] == 4096 and descriptor[4] == len(loan)
                and len(loan) >= 112 and loan[:8] == b"HSHOUT01",
                "outcome loan descriptor")
    else:
        require(descriptor[1] == 2 and descriptor[3:5] == (0, 0) and not loan,
                "quiet cancellation descriptor")
    return ready, gates, descriptor, loan


def expected_gate_cancel(spec, action, stream, already):
    if already:
        return False
    hook = spec.get("hook", {})
    if hook.get("op") != "cancel":
        return False
    return (hook["at"] == "admit" and action == 1
            or hook["at"] == "first_read" and action == 5 and stream == 0
            or hook["at"] == "first_unlink" and action == 8)


def verify_trace(spec, folder, receipt, raw_stdout, raw_stdin, raw_trace):
    ready, gates, descriptor, loan = decode_transport(raw_stdout)
    require(ready[1] == 1 and ready[2] == receipt["pid"] and ready[3] > 2
            and ready[4] > 2 and ready[3] != ready[4], "READY process/custody")
    expected_mode = (1 if spec.get("hook") or spec.get("fifo_hex") or spec.get("allocation") else 0)
    if spec.get("fifo_hex"):
        expected_mode |= 2
    require(ready[7] == expected_mode, "fixture mode differs")
    records, footer = decode_trace(raw_trace)
    require(len(records) >= 4 and (len(records)-2) % 2 == 0, "effect pair count")
    for i, record in enumerate(records[:2]):
        q, payload = record["q"], record["payload"]
        require(q[1:4] == (0, 0, 1) and q[4] == receipt["pid"]
                and q[5] == q[4] and q[6] == 1 and q[7] == ready[3+i]
                and q[8:14] == (i, 0, 0, 0, 0, 3), "initial custody fstat record")
        metadata = inspect_stat(payload)
        require(metadata["ino"] == ready[5+i] and stat.S_ISREG(metadata["mode"])
                and metadata["size"] == 0, "initial owned inode differs")
    pairs = []
    for seq, index in enumerate(range(2, len(records), 2), 1):
        issued, completed = records[index:index+2]
        a, b = issued["q"], completed["q"]
        require(a[1] == b[1] == seq and a[2] == b[2] and a[3] == 0 and b[3] == 1
                and a[4:7] == b[4:7] == (receipt["pid"], receipt["pid"], 1)
                and a[8:11] == b[8:11] and a[11:13] == (0, 0),
                "effect sequence/role/immutable pair differs")
        require(1 <= a[2] <= 9 and b[12] <= 4095, "effect action or errno")
        if b[12]:
            require(signed(b[11]) == -b[12] and b[13:15] == (0, 0),
                    "actual syscall errno/payload differs")
        else:
            require(signed(b[11]) >= 0, "successful syscall has negative raw result")
        if a[2] in (2, 8):
            stream = ("stdout", "stderr")[a[9]] if a[9] in (0, 1) else None
            require(a[8] == 1 and stream is not None and a[10] == 0
                    and a[13] == 1
                    and issued["payload"] == os.fsencode(Path(receipt["capture_root"]) /
                                                         (stream + ".log")) + b"\0",
                    "prepared path capability differs")
        else:
            require(a[13:15] == (0, 0), "unexpected issue payload")
        pairs.append((issued, completed))
    require(footer[1] == receipt["pid"] and footer[2] == len(records)
            and footer[3] == footer[4] == len(pairs)
            and footer[5:7] == (0, 0) and footer[7:10] == (U64, U64, U64)
            and footer[10] == 0 and footer[11] == expected_mode
            and footer[12:] == (0, 0, 0, 0), "footer counts/custody/errors")
    require(len(gates) == (len(pairs) if expected_mode & 1 else 0),
            "gate/actual effect count")
    expected_stdin = bytearray(frame(spec))
    gate_stream, cancelled = None, False
    for gate, pair in zip(gates, pairs):
        q = pair[0]["q"]
        require(gate[1:6] == (q[1], q[2], *q[8:11]), "gate differs from actual effect")
        if q[2] == 2:
            gate_stream = q[9]
        do_cancel = expected_gate_cancel(spec, q[2], gate_stream, cancelled)
        expected_stdin.extend(frame(spec, 3 if do_cancel else 2))
        cancelled |= do_cancel
    require(raw_stdin == bytes(expected_stdin), "initial/control stdin differs from registered case")
    expected = expected_reads(spec)
    results = {}
    read_bytes = {"stdout": bytearray(), "stderr": bytearray()}
    active = None
    serial = 0
    next_stream = 0
    discards = []
    metadata_records = []
    read_eintr = 0
    last_eintr = None
    growth = 0
    statx_available = 0
    workspace = 8192
    ended = False
    seen_admit = False
    for issued, completed in pairs:
        a, b = issued["q"], completed["q"]
        action, args, error = a[2], a[8:11], b[12]
        payload = completed["payload"]
        if last_eintr is not None:
            require((action, args, a[7]) == last_eintr, "EINTR not retried with exact syscall span")
            last_eintr = None
        if action == 1:
            require(not seen_admit and len(results) == 0 and args == (1, 0, 0)
                    and not error and b[11] == 0 and b[13:15] == (0, 0),
                    "capture admission differs")
            seen_admit = True
        elif action == 2:
            require(seen_admit and active is None and not discards
                    and next_stream < 2 and args == (1, next_stream, 0),
                    "read open order differs")
            name = ("stdout", "stderr")[next_stream]
            if error:
                if error == 4:
                    last_eintr = (action, args, a[7])
                else:
                    results[name] = (2, error, b"")
                    next_stream += 1
            else:
                serial += 1
                require(b[7] > 2 and b[11] == b[7] and b[13:15] == (0, 0), "opened owned FD")
                active = {"name": name, "fd": b[7], "handle": serial, "metadata": False,
                          "metadata_next": "fstat" if statx_available == 2 else "statx",
                          "failure_kind": 0, "read_error": 0}
                ended = False
        elif action in (3, 4):
            require(active is not None and not active["metadata"] and not ended and not discards
                    and active["metadata_next"] == ("statx" if action == 3 else "fstat")
                    and (action != 4 or statx_available == 2)
                    and a[7] == b[7] == active["fd"] and args[0] == active["handle"]
                    and args[1:] == ((384, 256) if action == 3 else (640, 144)),
                    "metadata FD/order/span differs")
            if not error:
                require(b[11] == 0 and b[13] == 3, "metadata success payload")
                metadata = inspect_stat(payload, action == 3)
                metadata_records.append({"stream": active["name"], "seq": a[1], **metadata})
                active["metadata"] = True
                active["metadata_next"] = None
                if action == 3:
                    statx_available = 1
            elif action == 4 or statx_available == 1:
                active["metadata"] = True
                active["metadata_next"] = None
            else:
                active["metadata_next"] = "probe"
        elif action == 9:
            require(active is not None and args == (0, 0, 0) and not active["metadata"]
                    and not ended and active["metadata_next"] == "probe" and statx_available == 0
                    and b[13:15] == (0, 0), "metadata probe not admitted")
            if error == 14:
                statx_available = 1
                active["metadata"] = True
                active["metadata_next"] = None
            else:
                statx_available = 2
                active["metadata_next"] = "fstat"
        elif action == 5:
            require(active is not None and active["metadata"] and not ended
                    and a[7] == b[7] == active["fd"] and args[0] == active["handle"]
                    and args[2] > 0 and (args[1:] == (800, 32) or args[1] >= 4208)
                    and args[1] + args[2] <= workspace, "read FD/order/bounds differs")
            if error == 4:
                read_eintr += 1
                last_eintr = (action, args, a[7])
            elif error:
                active["read_error"] = error
                active["failure_kind"] = 2
                ended = True
            else:
                require(b[13] == 2 and b[11] == len(payload) <= args[2],
                        "actual read byte count differs")
                read_bytes[active["name"]].extend(payload)
                if not payload:
                    ended = True
        elif action == 6:
            require(active is not None and ended and a[7] == b[7] == active["fd"]
                    and args == (active["handle"], 0, 0) and b[13:15] == (0, 0),
                    "read close missing/early/wrong custody")
            name, read_error, failed = active["name"], active["read_error"], active["failure_kind"]
            results[name] = ((failed, read_error, b"") if failed else
                             (0, 0, bytes(read_bytes[name])))
            active = None
            next_stream += 1
        elif action == 7:
            require(active is not None and active["metadata"] and not ended and args[1:] == (0, 0)
                    and args[0] > workspace and b[13:15] == (0, 0),
                    "real workspace growth differs")
            if error:
                require(error == 12 and spec.get("allocation", {}).get("stage") == "initial"
                        and active["name"] == "stdout" and not read_bytes["stdout"]
                        and args[0] == 4208 + len(initial_bytes(spec, "stdout")),
                        "unexpected allocation failure")
                active["failure_kind"] = 3
                ended = True
            else:
                require(b[11] % 4096 == 0, "real grown mapping address")
                workspace = (args[0] + 4095) & ~4095
                growth += 1
        elif action == 8:
            require(active is None and next_stream == 2 and args == (1, len(discards), 0)
                    and len(discards) < 2 and b[13:15] == (0, 0),
                    "discard did not follow both completed reads")
            discards.append(error)
    require(active is None and last_eintr is None, "live read custody or unretried EINTR")
    hook = spec.get("hook", {})
    cancel = hook.get("op") == "cancel"
    if cancel:
        require(descriptor[1] == 2 and not loan, "cancel fabricated foreground outcome")
        if hook["at"] == "admit":
            require(results == {} and not discards and len(pairs) == 1,
                    "cancel-before-read started an await")
        elif hook["at"] == "first_read":
            require(results == {"stdout": expected["stdout"]} and not discards,
                    "cancelled read did not finish its task or started stderr")
        else:
            require(results == expected and discards == [0],
                    "cancelled discard started next unlink")
    else:
        require(descriptor[1] == 1 and results == expected and len(discards) == 2,
                "both actual Results/discards differ")
        q = struct.unpack_from("<14Q", loan)
        expect_header = (int.from_bytes(b"HSHOUT01", "little"), 1, 0, spec["exit_code"] << 8,
                         expected["stdout"][0], expected["stdout"][1],
                         expected["stderr"][0], expected["stderr"][1], 0, 0,
                         len(expected["stdout"][2]), len(expected["stderr"][2]), 0, 0)
        require(q == expect_header and loan[112:] == expected["stdout"][2] + expected["stderr"][2],
                "HIA typed loan differs from actual raw Results")
    expected_discards = [0, 0]
    for fault in spec["faults"]:
        if fault["op"] == "unlink":
            expected_discards[("stdout", "stderr").index(fault["stream"])] = 2
        if fault["op"] == "replace_dir":
            expected_discards[("stdout", "stderr").index(fault["stream"])] = 21
    if hook.get("op") == "unlink":
        expected_discards[0] = 2
    require(discards == expected_discards[:len(discards)], "ignored unlink errno differs")
    require(read_eintr == (1 if spec.get("fifo_hex") else 0), "actual EINTR coverage differs")
    if spec["name"] == "large_repeated":
        require(len(loan) > 8*1024*1024 and growth > 0, "raw log quota/growth proof missing")
    return {"effects": len(pairs), "records": len(records), "read_eintr": read_eintr,
            "growth_effects": growth, "workspace_capacity": workspace,
            "discard_errno": discards, "descriptor_kind": descriptor[1],
            "loan_bytes": len(loan), "loan_sha256": sha(loan),
            "metadata": metadata_records}, loan



def verify_fatal_trace(spec, folder, receipt, raw_stdout, raw_stdin, raw_trace):
    require(spec.get("allocation", {}).get("stage") == "probe"
            and receipt["exit_code"] == -signal.SIGABRT, "fatal allocation case/exit")
    ready, gates, end = transport_prefix(raw_stdout)
    require(end == len(raw_stdout) and ready[1] == 1 and ready[2] == receipt["pid"]
            and ready[3] > 2 and ready[4] > 2 and ready[3] != ready[4] and ready[7] == 1,
            "fatal READY/gates must end without a return frame")
    require(raw_stdin == frame(spec) + frame(spec, 2)*len(gates),
            "fatal allocation exact stdin")
    records, footer = decode_trace(raw_trace, allow_fatal=True)
    actions = [1, 2, 3, 7, 5, 5, 7, 10, 11]
    require(footer is None and len(gates) == len(actions) and len(records) == 2*len(actions)+1,
            "fatal full action inventory")
    for i, record in enumerate(records[:2]):
        q = record["q"]
        metadata = inspect_stat(record["payload"])
        require(q[1:4] == (0, 0, 1) and q[4:7] == (receipt["pid"], receipt["pid"], 1)
                and q[7] == ready[3+i] and q[8:14] == (i, 0, 0, 0, 0, 3)
                and metadata["ino"] == ready[5+i] and metadata["size"] == 0,
                "fatal initial writer custody")
    pairs = []
    for index, action in enumerate(actions):
        issued = records[2+2*index]
        a = issued["q"]
        require(a[1:4] == (index+1, action, 0)
                and a[4:7] == (receipt["pid"], receipt["pid"], 1)
                and a[11:13] == (0, 0)
                and gates[index][1:6] == (index+1, action, *a[8:11]),
                "fatal issue/gate sequence differs")
        if action == 11:
            require(a[7] == U64 and a[8:15] == (0, 0, 0, 0, 0, 0, 0),
                    "fatal intrinsic is not a fixed self-abort")
            continue
        completed = records[3+2*index]
        b = completed["q"]
        require(b[1:4] == (index+1, action, 1) and a[4:7] == b[4:7]
                and a[8:11] == b[8:11] and b[12] <= 4095,
                "fatal completed effect pair differs")
        if b[12]:
            require(signed(b[11]) == -b[12] and b[13:15] == (0, 0),
                    "fatal actual errno record")
        else:
            require(signed(b[11]) >= 0, "fatal success has negative syscall return")
        if action not in (2, 10):
            require(a[13:15] == (0, 0), "fatal unexpected issue payload")
        pairs.append((issued, completed))
    require(pairs[0][0]["q"][8:11] == (1, 0, 0)
            and pairs[0][1]["q"][11:15] == (0, 0, 0, 0), "fatal capture admission")
    opening, opened = pairs[1]
    fd = opened["q"][7]
    require(opening["q"][8:11] == (1, 0, 0) and opening["q"][13] == 1
            and opening["payload"] == os.fsencode(Path(receipt["capture_root"]) / "stdout.log") + b"\0"
            and opened["q"][11] == fd > 2 and opened["q"][12:15] == (0, 0, 0),
            "fatal source open differs")
    metadata_issue, metadata_done = pairs[2]
    require(metadata_issue["q"][7] == metadata_done["q"][7] == fd
            and metadata_issue["q"][8:11] == (1, 384, 256)
            and metadata_done["q"][11:14] == (0, 0, 3), "fatal metadata")
    metadata = inspect_stat(metadata_done["payload"], True)
    initial = initial_bytes(spec, "stdout")
    appended = bytes.fromhex(spec["hook"]["bytes_hex"])
    require(metadata["size"] == len(initial) == 5000, "fatal initial Vec capacity")
    first_growth, grown = pairs[3]
    require(first_growth["q"][7] == grown["q"][7] == fd
            and first_growth["q"][8:11] == (9208, 0, 0)
            and grown["q"][11] > 0 and grown["q"][11] % 4096 == 0
            and grown["q"][12:15] == (0, 0, 0), "actual initial grown arena")
    for pair, destination, requested, raw in ((pairs[4], 4208, 5000, initial),
                                             (pairs[5], 800, 32, appended)):
        issued, completed = pair
        require(issued["q"][7] == completed["q"][7] == fd
                and issued["q"][8:11] == (1, destination, requested)
                and completed["q"][11:15] == (len(raw), 0, 2, len(raw))
                and completed["payload"] == raw, "fatal actual main/probe reads")
    failed, failure = pairs[6]
    require(failed["q"][7] == failure["q"][7] == fd
            and failed["q"][8:11] == (14208, 0, 0)
            and failure["q"][11:15] == (U64-11, 12, 0, 0),
            "probe extension did not encounter actual ENOMEM")
    diagnostic = (b"memory allocation of 10000 bytes failed\n"
                  b"note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n")
    written, result = pairs[7]
    require(written["q"][7] == result["q"][7] == 2
            and written["q"][8:11] == (1024, len(diagnostic), 0)
            and written["q"][13:15] == (4, len(diagnostic))
            and written["payload"] == diagnostic
            and result["q"][11:15] == (len(diagnostic), 0, 0, 0)
            and ordinary(folder / "stderr.bin") == diagnostic,
            "fatal HIA diagnostic or actual write differs")
    return {"effects": len(actions), "records": len(records), "read_eintr": 0,
            "growth_effects": 1, "workspace_capacity": 12288, "discard_errno": [],
            "descriptor_kind": None, "loan_bytes": 0, "loan_sha256": sha(b""),
            "fatal_signal": signal.SIGABRT, "fatal_layout_bytes": 10000,
            "metadata": [{"stream": "stdout", "seq": 3, **metadata}]}, b""


def verify_case_trace(spec, folder, receipt, raw_stdout, raw_stdin, raw_trace):
    if spec.get("allocation", {}).get("stage") == "probe":
        return verify_fatal_trace(spec, folder, receipt, raw_stdout, raw_stdin, raw_trace)
    return verify_trace(spec, folder, receipt, raw_stdout, raw_stdin, raw_trace)


def write_owned(path, raw, *, create=False, append=False):
    flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= os.O_CREAT | os.O_EXCL if create else (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "write target is not owned regular fixture")
        send(fd, raw)
    finally:
        os.close(fd)


def mutate(capture, fault, folder, *, stage, gate_seq):
    stream, op = fault["stream"], fault["op"]
    require(stream in ("stdout", "stderr"), "unknown fixture stream")
    path = capture / (stream + ".log")
    before = info(path) if exists(path) else None
    require(before is not None, "fixture mutation lost its expected source")
    raw = bytes.fromhex(fault.get("replacement_hex", fault.get("bytes_hex", "")))
    record = {"stream": stream, "op": op, "stage": stage, "gate_seq": gate_seq,
              "path_hex": os.fsencode(path).hex(), "before": before,
              "started_ns": time.monotonic_ns()}
    if op in ("unlink", "replace_dir", "replace_file", "replace_fifo", "replace_symlink"):
        require(before["type"] == "regular", "replacement source is not the owned regular file")
        path.unlink()
        if op == "replace_dir":
            path.mkdir(mode=0o700)
        elif op == "replace_file":
            write_owned(path, raw, create=True)
        elif op == "replace_fifo":
            os.mkfifo(path, 0o600)
        elif op == "replace_symlink":
            target = capture / "target.bin"
            write_owned(target, raw, create=True)
            os.symlink("target.bin", path)
            record["target"] = info(target)
    elif op in ("append", "truncate"):
        require(before["type"] == "regular", "growth/truncation source is not regular")
        write_owned(path, raw, append=op == "append")
    else:
        raise ValueError("unregistered fixture mutation")
    record["after"] = info(path) if exists(path) else None
    record["finished_ns"] = time.monotonic_ns()
    if op in ("replace_file", "replace_dir", "replace_fifo", "replace_symlink"):
        require((record["after"]["dev"], record["after"]["ino"]) !=
                (before["dev"], before["ino"]), "replacement reused still-held old inode")
    return record


def expected_remaining(spec):
    names = {"effects.bin": "regular"}
    if spec.get("allocation", {}).get("stage") == "probe":
        names.update({"stdout.log": "regular", "stderr.log": "regular"})
    hook = spec.get("hook", {})
    if hook.get("op") == "cancel":
        names["stderr.log"] = "regular"
        if hook["at"] != "first_unlink":
            names["stdout.log"] = "regular"
    for fault in spec["faults"]:
        if fault["op"] == "replace_dir":
            names[fault["stream"] + ".log"] = "directory"
        if fault["op"] == "replace_symlink":
            names["target.bin"] = "regular"
    return names


def retire_fixture(capture, folder, spec, receipt, validation, root_identity):
    require(info(capture)["dev"] == root_identity["dev"]
            and info(capture)["ino"] == root_identity["ino"]
            and info(capture)["type"] == "directory", "capture root custody changed")
    expected = expected_remaining(spec)
    with os.scandir(capture) as scan:
        names = sorted(x.name for x in scan)
    require(set(names) == set(expected), "unexpected live fixture member before retirement")
    snapshots = folder / "fixture-snapshot"
    snapshots.mkdir(mode=0o700)
    entries = []
    for index, name in enumerate(names):
        path = capture / name
        observed = info(path)
        require(observed["type"] == expected[name] and observed["nlink"] >= 1,
                "fixture retirement type differs")
        item = {"name": name, "relative_path_hex": os.fsencode(name).hex(), "identity": observed}
        if observed["type"] == "regular":
            raw = ordinary(path)
            payload = snapshots / (str(index) + ".bin")
            write_new(payload, raw)
            item["payload"] = {"path": str(payload.relative_to(folder)), **pin(payload)}
            require(pin(path) == pin(payload), "fixture snapshot differed before delete")
        elif observed["type"] == "directory":
            with os.scandir(path) as scan:
                require(list(scan) == [], "owned replacement directory became nonempty")
        entries.append(item)
    removed = []
    for item in entries:
        path = capture / item["name"]
        require(info(path) == item["identity"], "fixture member changed before exact retirement")
        if item["identity"]["type"] == "regular":
            require(pin(path) == {k: item["payload"][k] for k in ("size", "sha256")},
                    "fixture member contents changed before exact retirement")
            path.unlink()
        else:
            path.rmdir()
        absent = not exists(path)
        require(absent, "fixture member remained after exact retirement")
        removed.append({"relative_path_hex": item["relative_path_hex"],
                        "identity_before": item["identity"], "observed_absent": absent})
    final_root = info(capture)
    require((final_root["dev"], final_root["ino"], final_root["mode"]) ==
            (root_identity["dev"], root_identity["ino"], root_identity["mode"]),
            "capture directory changed before rmdir")
    with os.scandir(capture) as scan:
        require(list(scan) == [], "capture directory unexpectedly nonempty")
    capture.rmdir()
    require(not exists(capture), "capture root remained after retirement")
    result = {"schema": "hepta.runtime.shell-output-fixture-retirement.v1",
              "capture_root": str(capture), "root_identity": root_identity,
              "root_before_delete": final_root, "root_observed_absent": True,
              "validated": validation, "process_receipt_sha256": sha(json_bytes(receipt)),
              "spec_sha256": sha(json_bytes(spec)), "entries": entries, "removed": removed,
              "finished_ns": time.monotonic_ns()}
    write_new(folder / "retirement.json", json_bytes(result))
    return result


def verify_retirement(folder, spec, receipt, validation, raw_trace):
    record = strict_json(ordinary(folder / "retirement.json"))
    require(record.get("schema") == "hepta.runtime.shell-output-fixture-retirement.v1"
            and record.get("capture_root") == receipt["capture_root"]
            and record.get("validated") == validation
            and record.get("process_receipt_sha256") == sha(json_bytes(receipt))
            and record.get("spec_sha256") == sha(json_bytes(spec))
            and record.get("root_observed_absent") is True,
            "fixture retirement binding differs")
    before, final = record["root_identity"], record["root_before_delete"]
    require(before == receipt["capture_identity"] and before["type"] == final["type"] == "directory"
            and before["mode"] == final["mode"] == 0o700
            and (before["dev"], before["ino"]) == (final["dev"], final["ino"]),
            "retirement root type/identity differs")
    expected = expected_remaining(spec)
    require([x["name"] for x in record["entries"]] == sorted(expected)
            and len(record["removed"]) == len(expected), "retirement member inventory")
    for index, (item, removed) in enumerate(zip(record["entries"], record["removed"])):
        name = item["name"]
        require(item["relative_path_hex"] == os.fsencode(name).hex()
                and item["identity"]["type"] == expected[name]
                and removed == {"relative_path_hex": item["relative_path_hex"],
                                "identity_before": item["identity"], "observed_absent": True},
                "retirement exact removal receipt")
        if expected[name] == "regular":
            require(item["payload"]["path"] == "fixture-snapshot/" + str(index) + ".bin",
                    "fixture snapshot path")
            data = ordinary(folder / item["payload"]["path"])
            require({"size": len(data), "sha256": sha(data)} ==
                    {k: item["payload"][k] for k in ("size", "sha256")}
                    and item["identity"]["size"] == len(data), "fixture payload changed")
            if name == "effects.bin":
                require(data == raw_trace, "retired audit differs from raw trace")
            elif name == "target.bin":
                target = next(x for x in spec["faults"] if x["op"] == "replace_symlink")
                require(data == bytes.fromhex(target["replacement_hex"]), "retired target bytes")
            else:
                require(data == expected_held(spec, name.removesuffix(".log")),
                        "retired unpolled capture bytes")
        else:
            require("payload" not in item, "directory snapshot contains fabricated data")
    require(type(record["finished_ns"]) is int
            and record["finished_ns"] >= receipt["finished_ns"], "retirement predates process finish")
    return {"retired": True, "members": len(expected), "snapshot_bytes":
            sum(x.get("payload", {}).get("size", 0) for x in record["entries"])}


def keep_outcome(folder, wire, manifest):
    import zlib
    provider = importlib.import_module("hia_native_shell_outcome_build")
    provider.read_evidence(manifest)
    output = folder / "outcome"
    output.mkdir(mode=0o700)
    write_new(output / "input.bin", wire)
    calls = []
    capacity = 64
    maximum = max(4096, len(wire)*4 + 8192)
    module = provider.NativeOutcome(manifest, source_root=ROOT)
    try:
        while True:
            at = output / str(len(calls))
            at.mkdir()
            result = module.call(wire, capacity, workspace_capacity=128,
                                 output_fill=0xa7, workspace_fill=0xb8)
            arrays = {}
            for name, raw in result["arrays"].items():
                path = at / (name + ".bin.z")
                write_new(path, zlib.compress(raw, 9))
                arrays[name] = {"path": str(path.relative_to(folder)),
                                "compressed": pin(path),
                                "uncompressed": {"size": len(raw), "sha256": sha(raw)}}
            record = {"entry": result["entry"], "arrays": arrays, "capacity": capacity,
                      "workspace_capacity": 128, "body": None}
            if result["body"] is not None:
                path = at / "body.bin"
                write_new(path, result["body"])
                record["body"] = {"path": str(path.relative_to(folder)), **pin(path)}
            write_new(at / "call.json", json_bytes(record))
            calls.append(str((at / "call.json").relative_to(folder)))
            if result["body"] is not None:
                break
            require(result["entry"]["returned"] == 0xfffffffe and capacity < maximum,
                    "outcome refused after private capacity retries")
            capacity = min(capacity*2, maximum)
    finally:
        module.close()
    record = {"schema": "hepta.runtime.shell-output-outcome-invocations.v1",
              "manifest": str(manifest), "manifest_pin": pin(manifest), "calls": calls,
              "input_pin": pin(output / "input.bin")}
    write_new(output / "report.json", json_bytes(record))
    return record


def verify_outcome(folder, loan, manifest):
    import zlib
    provider = importlib.import_module("hia_native_shell_outcome_build")
    review = provider.read_evidence(manifest, source_root=ROOT)
    record = strict_json(ordinary(folder / "outcome/report.json"))
    require(record.get("schema") == "hepta.runtime.shell-output-outcome-invocations.v1"
            and record.get("manifest") == str(manifest)
            and record.get("manifest_pin") == pin(manifest)
            and record.get("input_pin") == pin(folder / "outcome/input.bin")
            and ordinary(folder / "outcome/input.bin") == loan,
            "outcome invocation loan/manifest binding")
    calls = record["calls"]
    require(type(calls) is list and 1 <= len(calls) <= 32
            and calls == ["outcome/" + str(i) + "/call.json" for i in range(len(calls))],
            "outcome invocation inventory")
    capacity = 64
    maximum = max(4096, len(loan)*4 + 8192)
    body = None
    keys = {"input_before", "input_after", "output_before", "output_after",
            "workspace_before", "workspace_after"}
    for index, name in enumerate(calls):
        call = strict_json(ordinary(folder / name))
        require(call["capacity"] == capacity and call["workspace_capacity"] == 128
                and set(call["arrays"]) == keys, "outcome capacities/array inventory")
        arrays = {}
        for key, item in call["arrays"].items():
            require(item["path"] == "outcome/" + str(index) + "/" + key + ".bin.z",
                    "outcome array path")
            raw = ordinary(folder / item["path"])
            require(pin(folder / item["path"]) == item["compressed"], "outcome compressed array")
            limit = (len(loan) if key.startswith("input") else
                     capacity if key.startswith("output") else 128) + 32
            require(item["uncompressed"]["size"] == limit, "outcome admitted array size")
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(raw, limit + 1)
            require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                    and len(decoded) == limit and sha(decoded) == item["uncompressed"]["sha256"],
                    "outcome full array decompression")
            arrays[key] = decoded
        require(arrays["input_before"] == arrays["input_after"]
                and arrays["input_before"][16:-16] == loan,
                "outcome input changed")
        for prefix in ("input", "output", "workspace"):
            before, after = arrays[prefix+"_before"], arrays[prefix+"_after"]
            require(before[:16] == after[:16] and before[-16:] == after[-16:],
                    "outcome borrowed guard changed")
        require(arrays["output_before"][16:-16] == b"\xa7"*capacity
                and arrays["workspace_before"][16:-16] == b"\xb8"*128,
                "outcome initial arrays differ")
        entry = call["entry"]
        require(entry.get("status") == "returned" and entry.get("entry") == index + 1
                and type(entry.get("pid")) is int and entry["pid"] > 0
                and entry.get("input_length") == len(loan)
                and entry.get("output_capacity") == capacity and entry.get("workspace_capacity") == 128
                and entry.get("output_fill") == 0xa7 and entry.get("workspace_fill") == 0xb8
                and entry.get("manifest_sha256") == review["manifest_sha256"]
                and entry.get("shared_sha256") == review["shared_sha256"]
                and entry.get("allocator_sha256") == review["allocator_sha256"]
                and type(entry.get("started_unix_ns")) is int
                and type(entry.get("finished_unix_ns")) is int
                and entry["started_unix_ns"] <= entry["finished_unix_ns"]
                and type(entry.get("elapsed_ns")) is int and entry["elapsed_ns"] >= 0
                and entry.get("arrays") == {key: {"size": len(raw), "sha256": sha(raw)}
                                            for key, raw in arrays.items()},
                "actual HIA outcome entry identity/complete arrays")
        guards = {
            "input_unchanged": arrays["input_before"] == arrays["input_after"],
            "input_guards": arrays["input_after"][:16] == b"1"*16 and arrays["input_after"][-16:] == b"2"*16,
            "output_guards": arrays["output_after"][:16] == b"A"*16 and arrays["output_after"][-16:] == b"B"*16,
            "workspace_guards": arrays["workspace_after"][:16] == b"Q"*16 and arrays["workspace_after"][-16:] == b"R"*16,
            "output_tail_unchanged": arrays["output_after"][16+entry["extent"]:] == arrays["output_before"][16+entry["extent"]:],
            "output_unchanged": arrays["output_after"] == arrays["output_before"],
        }
        require(entry.get("guards") == guards
                and all(value for key, value in guards.items() if key != "output_unchanged"),
                "actual HIA outcome guards/tail differ")
        returned = entry["returned"]
        if index + 1 < len(calls):
            require(returned == 0xfffffffe and entry.get("extent") == 0 and call["body"] is None
                    and arrays["output_before"] == arrays["output_after"] and capacity < maximum,
                    "outcome refusal mutated output or retry differs")
            capacity = min(capacity*2, maximum)
        else:
            require(returned == 40 and call["body"] is not None, "missing successful outcome entry")
            item = call["body"]
            require(item["path"] == "outcome/" + str(index) + "/body.bin", "outcome body path")
            body = ordinary(folder / item["path"])
            require({"size": len(body), "sha256": sha(body)} ==
                    {k: item[k] for k in ("size", "sha256")}
                    and len(body) >= 40 and body[:8] == b"HSHOUR01",
                    "outcome body identity")
            q = struct.unpack_from("<5Q", body)
            require(q[1] in (0, 1) and entry.get("extent") == len(body) and q[3:] == (0, 0)
                    and len(body) == 40 + q[2] and len(body) <= capacity
                    and arrays["output_after"][16:-16] == body + b"\xa7"*(capacity-len(body)),
                    "outcome full extent/tail/foreground shape")
            body[40:].decode("utf-8", "strict")
    return {"calls": len(calls), "body_bytes": len(body), "body_sha256": sha(body),
            "complete_text_bytes": len(body)-40}


def fd_observation(pid, fd):
    path = Path("/proc", str(pid), "fd", str(fd))
    st = path.stat()
    return {"fd": fd, "link_hex": os.fsencode(os.readlink(path)).hex(),
            "stat": {"dev": st.st_dev, "ino": st.st_ino, "mode": stat.S_IMODE(st.st_mode),
                     "type": "regular" if stat.S_ISREG(st.st_mode) else
                             "fifo" if stat.S_ISFIFO(st.st_mode) else "other",
                     "size": st.st_size, "nlink": st.st_nlink},
            "fdinfo_hex": Path("/proc", str(pid), "fdinfo", str(fd)).read_bytes().hex()}


def read_held(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        raw = os.read(fd, 1 << 20)
        if not raw:
            return b"".join(chunks)
        chunks.append(raw)


def expected_held(spec, stream):
    raw = initial_bytes(spec, stream)
    hook = spec.get("hook", {})
    if stream == "stdout" and hook.get("op") == "append":
        return raw + bytes.fromhex(hook["bytes_hex"])
    if stream == "stdout" and hook.get("op") == "truncate":
        return bytes.fromhex(hook["bytes_hex"])
    return raw


def verify_setup(spec, folder, receipt, ready, validation):
    setup = strict_json(ordinary(folder / "setup.json"))
    require(setup.get("schema") == "hepta.runtime.shell-output-setup.v1"
            and setup.get("identity") == receipt["identity"]
            and setup.get("capture_identity") == receipt["capture_identity"]
            and setup.get("ready_pin") == {"size": 64, "sha256": sha(struct.pack("<8Q", *ready))},
            "setup identity/READY binding")
    require(setup["identity"] == parse_process_identity(bytes.fromhex(setup["identity"]["stat_hex"]))
            and setup["identity"]["pid"] == receipt["pid"]
            and setup["identity"]["ppid"] == receipt["controller_pid"]
            and setup["identity"]["starttime"] > 0
            and bytes.fromhex(setup["identity"]["stat_hex"]).startswith(
                str(receipt["pid"]).encode() + b" "), "initial PID identity")
    require([x["stream"] for x in setup["streams"]] == ["stdout", "stderr"],
            "setup stream inventory")
    paths = {}
    opened = {}
    for i, item in enumerate(setup["streams"]):
        name = item["stream"]
        before, after, observed = item["before"], item["after"], item["writer"]
        require(before["type"] == after["type"] == "regular"
                and before["mode"] == after["mode"] == 0o600
                and before["size"] == 0
                and (before["dev"], before["ino"]) == (after["dev"], after["ino"])
                and before["ino"] == ready[5+i]
                and observed["fd"] == ready[3+i]
                and observed["stat"]["dev"] == before["dev"]
                and observed["stat"]["ino"] == before["ino"]
                and observed["stat"]["size"] == 0
                and observed["stat"]["type"] == "regular"
                and observed["link_hex"] == os.fsencode(Path(receipt["capture_root"]) /
                                                        (name + ".log")).hex(),
                "writer FD/inode/source path binding")
        fdinfo = bytes.fromhex(observed["fdinfo_hex"]).decode("ascii")
        flags = int(next(line.split(":", 1)[1].strip()
                         for line in fdinfo.splitlines() if line.startswith("flags:")), 8)
        require(flags & os.O_CLOEXEC and flags & os.O_ACCMODE == os.O_WRONLY,
                "private writer FD flags differ")
        initial = ordinary(folder / (name + ".initial.bin"))
        held = ordinary(folder / (name + ".held.bin"))
        require(initial == initial_bytes(spec, name) and after["size"] == len(initial)
                and held == expected_held(spec, name)
                and item["observer_before"]["ino"] == before["ino"]
                and item["observer_before"]["dev"] == before["dev"]
                and item["observer_after"]["ino"] == before["ino"]
                and item["observer_after"]["dev"] == before["dev"]
                and item["observer_after"]["size"] == len(held),
                "complete initial/held capture bytes differ")
        paths[name] = after
        opened[name] = after
    expected_mutations = [(fault, "before-start") for fault in spec["faults"]]
    hook = spec.get("hook", {})
    if hook and hook["op"] != "cancel":
        expected_mutations.append(({"stream": "stdout", "op": hook["op"],
                                    "bytes_hex": hook.get("bytes_hex", "")}, "gate"))
    require(len(setup["mutations"]) == len(expected_mutations), "mutation inventory differs")
    for observed, (fault, stage) in zip(setup["mutations"], expected_mutations):
        name, op = fault["stream"], fault["op"]
        require(observed["stream"] == name and observed["op"] == op
                and observed["stage"] == stage
                and observed["path_hex"] == os.fsencode(Path(receipt["capture_root"]) /
                                                        (name + ".log")).hex()
                and observed["before"] == paths[name]
                and receipt["started_ns"] <= observed["started_ns"] <= observed["finished_ns"]
                <= receipt["finished_ns"], "mutation exact recipe/order/identity differs")
        if stage == "before-start":
            require(observed["gate_seq"] == 0, "pre-start mutation has effect sequence")
        else:
            require(type(observed["gate_seq"]) is int and observed["gate_seq"] > 0,
                    "concurrent mutation has no observed gate")
        after = observed["after"]
        if op == "unlink":
            require(after is None, "unlink fault left a path")
        else:
            typ = {"replace_dir": "directory", "replace_file": "regular",
                   "replace_fifo": "fifo", "replace_symlink": "symlink",
                   "append": "regular", "truncate": "regular"}[op]
            require(after["type"] == typ, "mutation resulting type differs")
            if op.startswith("replace_"):
                require((after["dev"], after["ino"]) !=
                        (observed["before"]["dev"], observed["before"]["ino"]),
                        "replacement retained old live inode")
            else:
                require((after["dev"], after["ino"]) ==
                        (observed["before"]["dev"], observed["before"]["ino"]),
                        "growth/truncation replaced the opened inode")
            if op == "replace_file":
                require(after["size"] == len(bytes.fromhex(fault.get("replacement_hex", fault.get("bytes_hex", "")))),
                        "replacement size differs")
            if op == "append":
                require(after["size"] == observed["before"]["size"] +
                        len(bytes.fromhex(fault["bytes_hex"])), "append size differs")
            if op == "truncate":
                require(after["size"] == len(bytes.fromhex(fault["bytes_hex"])),
                        "truncation size differs")
            if op == "replace_symlink":
                require(after["target_hex"] == os.fsencode("target.bin").hex()
                        and observed["target"]["type"] == "regular"
                        and observed["target"]["size"] == len(bytes.fromhex(fault["replacement_hex"])),
                        "symlink target identity differs")
        paths[name] = after
        if stage == "before-start":
            opened[name] = (observed["target"] if op == "replace_symlink" else after)
    for metadata in validation["metadata"]:
        expected = opened[metadata["stream"]]
        require(expected is not None and metadata["dev"] == expected["dev"]
                and metadata["ino"] == expected["ino"] and metadata["size"] == expected["size"]
                and stat.S_IMODE(metadata["mode"]) == expected["mode"],
                "opened metadata is not the expected bound inode")
    schedule = setup["schedule"]
    _, raw_gates, _ = transport_prefix(ordinary(folder / "stdout.bin"))
    controls = ordinary(folder / "stdin.bin")
    require(len(controls) == 40*(len(raw_gates)+1), "raw gate control stream extent")
    require(len(schedule) == receipt["gate_count"] == len(raw_gates), "gate schedule count")
    previous = receipt["started_ns"]
    stream = None
    hook_seq = None
    hook = spec.get("hook", {})
    for index, (event, gate) in enumerate(zip(schedule, raw_gates)):
        request = struct.unpack_from("<5Q", controls, 40*(index+1))
        require(event["seq"] == gate[1] and event["action"] == gate[2]
                and event["args"] == list(gate[3:6]) and event["op"] == request[1],
                "schedule differs from actual gate/control bytes")
        require(previous <= event["observed_ns"] <= event["written_ns"] <= receipt["finished_ns"],
                "gate schedule time/order")
        previous = event["written_ns"]
        action = gate[2]
        if action == 2:
            stream = gate[4]
        if hook and hook_seq is None and (
                hook["at"] == "admit" and action == 1
                or hook["at"] == "first_metadata" and action in (3, 4) and stream == 0
                or hook["at"] == "first_read" and action == 5 and stream == 0
                or hook["at"] == "first_unlink" and action == 8):
            hook_seq = gate[1]
    require(not hook or hook_seq is not None, "registered hook gate never occurred")
    for observed in setup["mutations"]:
        if observed["stage"] == "gate":
            require(observed["gate_seq"] == hook_seq, "mutation used the wrong registered first gate")
            event = next(x for x in schedule if x["seq"] == observed["gate_seq"])
            require(event["observed_ns"] <= observed["started_ns"]
                    <= observed["finished_ns"] <= event["written_ns"],
                    "mutation not between actual gate and dispatch")
    if spec.get("fifo_hex"):
        fifo = setup["fifo"]
        require(fifo["signal"] == signal.SIGUSR1 and fifo["signal_sent"] is True
                and fifo["identity"] == parse_process_identity(bytes.fromhex(fifo["identity"]["stat_hex"]))
                and identity_matches(receipt["identity"], fifo["identity"])
                and fifo["identity"]["pid"] == receipt["pid"]
                and fifo["blocked_fd"]["stat"]["type"] == "fifo"
                and fifo["blocked_fd"]["stat"]["ino"] == opened["stdout"]["ino"]
                and fifo["blocked_fd"]["stat"]["dev"] == opened["stdout"]["dev"],
                "actual blocked FIFO custody/signal")
        fields = bytes.fromhex(fifo["syscall_hex"]).split()
        require(int(fields[0], 0) == 0 and int(fields[1], 0) == fifo["blocked_fd"]["fd"]
                and int(fields[3], 0) == 32
                and receipt["started_ns"] <= fifo["observed_ns"]
                <= fifo["signal_ns"] <= fifo["released_ns"] <= receipt["finished_ns"],
                "signal did not interrupt the actual admitted read")
        event = next(x for x in schedule if x["seq"] == fifo["gate_seq"])
        released = next(x for x in schedule if x["seq"] == fifo["release_gate_seq"])
        require(event["action"] == released["action"] == 5 and event["args"] == released["args"]
                and event["args"][2] == 32 and released["seq"] == event["seq"] + 1
                and event["written_ns"] <= fifo["observed_ns"]
                and released["written_ns"] <= fifo["released_ns"],
                "FIFO signal/release not bound to the interrupted read")
        actual, _ = decode_trace(ordinary(folder / "effects.bin"))
        interrupted = [x["q"] for x in actual
                       if x["q"][1] == fifo["gate_seq"] and x["q"][3] == 1]
        require(len(interrupted) == 1 and interrupted[0][2] == 5
                and interrupted[0][7] == fifo["blocked_fd"]["fd"] and interrupted[0][12] == 4,
                "FIFO signal is not the actual EINTR completion")
        require(ordinary(folder / "fifo.write.bin") == bytes.fromhex(spec["fifo_hex"]),
                "actual FIFO producer bytes")
    else:
        require(setup["fifo"] is None, "unexpected signal fixture")
    if spec.get("allocation"):
        allocation = setup["allocation"]
        require(type(allocation) is dict and allocation["stage"] == spec["allocation"]["stage"]
                and allocation["pid"] == receipt["pid"]
                and allocation["identity"] == parse_process_identity(bytes.fromhex(allocation["identity"]["stat_hex"]))
                and identity_matches(receipt["identity"], allocation["identity"]),
                "allocation limit process custody")
        raw_status = bytes.fromhex(allocation["status_hex"])
        vm_size = int(next(line.split()[1] for line in raw_status.splitlines()
                          if line.startswith(b"VmSize:"))) * 1024
        require(vm_size == allocation["vm_size_bytes"] > 0
                and allocation["applied_as"] == allocation["observed_as"]
                == [vm_size, allocation["previous_as"][1]]
                and allocation["observed_core"] == [0, 0], "actual allocation limits differ")
        event = next(x for x in schedule if x["seq"] == allocation["gate_seq"])
        expected_growth = [x for x in schedule if x["action"] == 7][
            0 if allocation["stage"] == "initial" else 1]
        require(event == expected_growth and event["observed_ns"] <= allocation["started_ns"]
                <= allocation["finished_ns"] <= event["written_ns"],
                "allocation limit was not applied at the exact growth gate")
        actual, _ = decode_trace(ordinary(folder / "effects.bin"),
                                 allow_fatal=allocation["stage"] == "probe")
        failure = [x["q"] for x in actual
                   if x["q"][1] == allocation["gate_seq"] and x["q"][3] == 1]
        require(len(failure) == 1 and failure[0][2] == 7 and failure[0][12] == 12,
                "allocation limit did not cause the actual ENOMEM effect")
    else:
        require(setup.get("allocation") is None, "unregistered resource limit intervention")
    return {"writer_custody": 2, "mutations": len(expected_mutations),
            "gates": len(schedule), "actual_fifo_signal": bool(spec.get("fifo_hex"))}


def run_case(spec, folder, manifest, outcome_manifest=None):
    folder.mkdir(mode=0o700)
    capture = folder / "capture"
    capture.mkdir(mode=0o700)
    root_identity = info(capture)
    meta = strict_json(ordinary(manifest))
    executable = manifest.parent / meta["elf"]
    executable_pin = pin(executable)
    mode = bool(spec.get("hook") or spec.get("fifo_hex") or spec.get("allocation"))
    argv = [str(executable), "--output-fixture", str(capture)]
    if mode:
        argv.append("--step-effects")
    if spec.get("fifo_hex"):
        argv.append("--interruptible")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    stdout = bytearray()
    stdin = bytearray()
    schedule = []
    observers = []
    fifo_writer = None
    process = None
    error = None
    started = time.monotonic_ns()
    deadline = started + DEADLINE_NS
    setup = {"schema": "hepta.runtime.shell-output-setup.v1", "capture_identity": root_identity,
             "streams": [], "mutations": [], "schedule": schedule, "fifo": None, "allocation": None}
    try:
        process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        ready_raw = exact(process.stdout.fileno(), 64, deadline)
        stdout.extend(ready_raw)
        require(ready_raw[:8] == b"HSHOIRD1", "fixture did not publish READY")
        ready = struct.unpack("<8Q", ready_raw)
        require(ready[2] == process.pid, "fixture READY PID differs")
        identity = process_identity(process.pid)
        require(identity["ppid"] == os.getpid(), "first process custody observation differs")
        require(Path("/proc", str(process.pid), "exe").resolve(strict=True) == executable,
                "actual executable path differs")
        actual_executable = pin(Path("/proc", str(process.pid), "exe").resolve(strict=True))
        require(actual_executable == executable_pin, "actual executed image differs")
        setup["identity"] = identity
        setup["ready_pin"] = {"size": len(ready_raw), "sha256": sha(ready_raw)}
        for index, name in enumerate(("stdout", "stderr")):
            path = capture / (name + ".log")
            before = info(path)
            writer = fd_observation(process.pid, ready[3+index])
            require((writer["stat"]["dev"], writer["stat"]["ino"]) ==
                    (before["dev"], before["ino"]), "READY writer path ownership")
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            observers.append(fd)
            st = os.fstat(fd)
            observer_before = {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size}
            raw = initial_bytes(spec, name)
            write_new(folder / (name + ".initial.bin"), raw)
            write_owned(path, raw)
            setup["streams"].append({"stream": name, "before": before, "after": info(path),
                                     "writer": writer, "observer_before": observer_before})
        for fault in spec["faults"]:
            setup["mutations"].append(mutate(capture, fault, folder,
                                             stage="before-start", gate_seq=0))
        raw = frame(spec)
        send(process.stdin.fileno(), raw)
        stdin.extend(raw)
        current_stream = None
        hook_applied = False
        fifo_opened = False
        fifo_signal_sent = False
        fifo_released = False
        allocation_seen = False
        growth_count = 0
        abort_issued = False
        while True:
            try:
                first = exact(process.stdout.fileno(), 8, deadline)
            except EOFError as exc:
                partial = exc.args[0] if exc.args and type(exc.args[0]) is bytes else b""
                stdout.extend(partial)
                if spec.get("allocation", {}).get("stage") == "probe" and abort_issued and not partial:
                    break
                raise
            stdout.extend(first)
            if first != b"HSHOIGT1":
                rest = exact(process.stdout.fileno(), 8, deadline)
                stdout.extend(rest)
                returned, extent = struct.unpack("<2Q", first + rest)
                require(returned == 64 and extent >= 64, "fixture refused or failed its owner")
                stdout.extend(exact(process.stdout.fileno(), extent, deadline))
                break
            rest = exact(process.stdout.fileno(), 56, deadline)
            stdout.extend(rest)
            gate = struct.unpack("<8Q", first + rest)
            seq, action, a0, a1, a2 = gate[1:6]
            observed_ns = time.monotonic_ns()
            if action == 2:
                current_stream = a1
            hook = spec.get("hook", {})
            trigger = (not hook_applied and bool(hook) and (
                hook["at"] == "admit" and action == 1
                or hook["at"] == "first_metadata" and action in (3, 4) and current_stream == 0
                or hook["at"] == "first_read" and action == 5 and current_stream == 0
                or hook["at"] == "first_unlink" and action == 8))
            op = 2
            if action == 7:
                growth_count += 1
                target = 1 if spec.get("allocation", {}).get("stage") == "initial" else 2
                if spec.get("allocation") and not allocation_seen and growth_count == target:
                    stable = process_identity(process.pid)
                    require(identity_matches(identity, stable), "allocation fixture PID custody")
                    status = Path("/proc", str(process.pid), "status").read_bytes()
                    vm_kb = int(next(line.split()[1] for line in status.splitlines()
                                     if line.startswith(b"VmSize:")))
                    limit = vm_kb * 1024
                    old_as = resource.prlimit(process.pid, resource.RLIMIT_AS)
                    old_core = resource.prlimit(process.pid, resource.RLIMIT_CORE)
                    before_limit = time.monotonic_ns()
                    resource.prlimit(process.pid, resource.RLIMIT_CORE, (0, 0))
                    resource.prlimit(process.pid, resource.RLIMIT_AS, (limit, old_as[1]))
                    setup["allocation"] = {
                        "stage": spec["allocation"]["stage"], "gate_seq": seq,
                        "pid": process.pid, "identity": stable, "status_hex": status.hex(),
                        "vm_size_bytes": limit, "previous_as": list(old_as),
                        "applied_as": [limit, old_as[1]],
                        "observed_as": list(resource.prlimit(process.pid, resource.RLIMIT_AS)),
                        "previous_core": list(old_core),
                        "observed_core": list(resource.prlimit(process.pid, resource.RLIMIT_CORE)),
                        "started_ns": before_limit, "finished_ns": time.monotonic_ns(),
                    }
                    allocation_seen = True
            if action == 11:
                abort_issued = True
            if trigger:
                hook_applied = True
                if hook["op"] == "cancel":
                    op = 3
                else:
                    setup["mutations"].append(mutate(
                        capture, {"stream": "stdout", "op": hook["op"],
                                  "bytes_hex": hook.get("bytes_hex", "")},
                        folder, stage="gate", gate_seq=seq))
            control = frame(spec, op)
            send(process.stdin.fileno(), control)
            stdin.extend(control)
            event = {"seq": seq, "action": action, "args": [a0, a1, a2],
                     "observed_ns": observed_ns, "written_ns": time.monotonic_ns(), "op": op}
            schedule.append(event)
            if spec.get("fifo_hex") and action == 2 and a1 == 0 and not fifo_opened:
                while True:
                    try:
                        fifo_writer = os.open(capture / "stdout.log",
                                              os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                        break
                    except OSError as exc:
                        if exc.errno != 6 or time.monotonic_ns() >= deadline:
                            raise
                        time.sleep(0.002)
                fifo_opened = True
            if spec.get("fifo_hex") and action == 5 and current_stream == 0:
                if not fifo_signal_sent:
                    while True:
                        require(time.monotonic_ns() < deadline, "FIFO blocking observation deadline")
                        syscall = Path("/proc", str(process.pid), "syscall").read_bytes()
                        fields = syscall.split()
                        if fields and fields[0] != b"running" and int(fields[0], 0) == 0:
                            fd = int(fields[1], 0)
                            if fd > 2 and int(fields[3], 0) == 32:
                                observed = fd_observation(process.pid, fd)
                                if observed["stat"]["type"] == "fifo":
                                    break
                        time.sleep(0.002)
                    current_identity = process_identity(process.pid)
                    require(identity_matches(identity, current_identity), "FIFO PID custody lost")
                    fifo_record = {"identity": current_identity, "syscall_hex": syscall.hex(),
                                   "blocked_fd": observed, "gate_seq": seq, "observed_ns": time.monotonic_ns(),
                                   "signal": signal.SIGUSR1, "signal_sent": False}
                    os.kill(process.pid, signal.SIGUSR1)
                    fifo_record["signal_ns"] = time.monotonic_ns()
                    fifo_record["signal_sent"] = True
                    setup["fifo"] = fifo_record
                    fifo_signal_sent = True
                elif not fifo_released:
                    raw = bytes.fromhex(spec["fifo_hex"])
                    send(fifo_writer, raw)
                    write_new(folder / "fifo.write.bin", raw)
                    os.close(fifo_writer)
                    fifo_writer = None
                    fifo_released = True
                    setup["fifo"]["released_ns"] = time.monotonic_ns()
                    setup["fifo"]["release_gate_seq"] = seq
        process.stdin.close()
        process.stdin = None
        tail, stderr = process.communicate(timeout=max(0.001, (deadline-time.monotonic_ns())/1e9))
        stdout.extend(tail)
        finished = time.monotonic_ns()
        write_new(folder / "stdin.bin", bytes(stdin))
        write_new(folder / "stdout.bin", bytes(stdout))
        write_new(folder / "stderr.bin", stderr)
        expected_exit = -signal.SIGABRT if spec.get("allocation", {}).get("stage") == "probe" else 0
        require(process.returncode == expected_exit and not tail
                and (expected_exit != 0 or stderr == b""),
                "native fixture transport/exit failed")
        for item, fd in zip(setup["streams"], observers):
            raw = read_held(fd)
            st = os.fstat(fd)
            item["observer_after"] = {"dev": st.st_dev, "ino": st.st_ino,
                                      "size": st.st_size, "nlink": st.st_nlink}
            write_new(folder / (item["stream"] + ".held.bin"), raw)
        trace = ordinary(capture / "effects.bin")
        write_new(folder / "effects.bin", trace)
        receipt = {"schema": "hepta.runtime.shell-output-process.v1", "argv": argv,
                   "cwd": str(ROOT), "env": environment, "pid": process.pid,
                   "controller_pid": os.getpid(), "identity": identity,
                   "capture_root": str(capture), "capture_identity": root_identity,
                   "native_manifest": str(manifest), "native_manifest_pin": pin(manifest),
                   "executable": str(executable), "executable_before": executable_pin,
                   "actual_executable": actual_executable, "executable_after": pin(executable),
                   "started_ns": started, "finished_ns": finished, "duration_ns": finished-started,
                   "deadline_ns": DEADLINE_NS, "exit_code": process.returncode,
                   "timed_out": False, "exception": None, "gate_count": len(schedule),
                   "stdin": pin(folder / "stdin.bin"), "stdout": pin(folder / "stdout.bin"),
                   "stderr": pin(folder / "stderr.bin"), "effects": pin(folder / "effects.bin")}
        write_new(folder / "setup.json", json_bytes(setup))
        write_new(folder / "process.json", json_bytes(receipt))
        write_new(folder / "spec.json", json_bytes(spec))
        validation, loan = verify_case_trace(spec, folder, receipt, bytes(stdout), bytes(stdin), trace)
        validation["setup"] = verify_setup(spec, folder, receipt, ready, validation)
        for fd in observers:
            os.close(fd)
        observers = []
        retirement = retire_fixture(capture, folder, spec, receipt, validation, root_identity)
        require(retirement["root_observed_absent"], "retirement incomplete")
        validation["retirement"] = verify_retirement(
            folder, spec, receipt, {k:v for k,v in validation.items() if k != "retirement"}, trace)
        outcome = None
        if outcome_manifest is not None and loan:
            keep_outcome(folder, loan, outcome_manifest)
            outcome = verify_outcome(folder, loan, outcome_manifest)
        record = {"schema": CASE_SCHEMA, "status": "PASS", "name": spec["name"],
                  "spec_sha256": sha(json_bytes(spec)), "validation": validation,
                  "outcome": outcome, **SCOPE}
        write_new(folder / "result.json", json_bytes(record))
        return record
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if fifo_writer is not None:
            os.close(fifo_writer)
        for fd in observers:
            os.close(fd)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if error is not None:
            # Preserve failure bytes and the precise live fixture; never fabricate retirement.
            failure = {"schema": CASE_SCHEMA, "status": "FAIL", "name": spec["name"],
                       "error": error, "pid": process.pid if process else None, **SCOPE}
            if not (folder / "stdin.bin").exists():
                write_new(folder / "stdin.bin", bytes(stdin))
            if not (folder / "stdout.bin").exists():
                write_new(folder / "stdout.bin", bytes(stdout))
            write_new(folder / "failure.json", json_bytes(failure))


def inventory(folder):
    files = {}
    def onerror(exc):
        raise exc
    for base, dirs, names in os.walk(folder, onerror=onerror, followlinks=False):
        for name in dirs:
            require(stat.S_ISDIR((Path(base)/name).lstat().st_mode)
                    and not (Path(base)/name).is_symlink(), "evidence contains special directory")
        for name in names:
            path = Path(base) / name
            files[str(path.relative_to(folder))] = pin(path)
    return dict(sorted(files.items()))


def read_case_evidence(case, spec, native_manifest, outcome_manifest, producer):
    """The same pure per-case path used by the full reader and physical controls."""
    read_build(native_manifest)
    name = spec["name"]
    saved = strict_json(ordinary(case / "result.json"))
    receipt = strict_json(ordinary(case / "process.json"))
    require(strict_json(ordinary(case / "spec.json")) == spec, "case input recipe differs")
    expected_argv = [str(native_manifest.parent / "shell-output.elf"), "--output-fixture",
                     str(producer / "cases" / name / "capture")]
    if spec.get("hook") or spec.get("fifo_hex") or spec.get("allocation"):
        expected_argv.append("--step-effects")
    if spec.get("fifo_hex"):
        expected_argv.append("--interruptible")
    require(receipt.get("schema") == "hepta.runtime.shell-output-process.v1"
            and receipt.get("argv") == expected_argv and receipt.get("cwd") == str(ROOT)
            and receipt.get("capture_root") == expected_argv[2]
            and receipt.get("env") == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            and receipt.get("native_manifest") == str(native_manifest)
            and receipt.get("native_manifest_pin") == pin(native_manifest)
            and receipt.get("executable") == expected_argv[0]
            and receipt.get("executable_before") == receipt.get("actual_executable")
            == receipt.get("executable_after") == pin(Path(expected_argv[0]))
            and type(receipt.get("pid")) is int and receipt["pid"] > 0
            and type(receipt.get("controller_pid")) is int and receipt["controller_pid"] > 0
            and type(receipt.get("started_ns")) is int
            and type(receipt.get("finished_ns")) is int
            and receipt["finished_ns"] >= receipt["started_ns"]
            and receipt["duration_ns"] == receipt["finished_ns"] - receipt["started_ns"]
            and 0 <= receipt["duration_ns"] <= DEADLINE_NS
            and receipt.get("deadline_ns") == DEADLINE_NS
            and receipt.get("exit_code") == (-signal.SIGABRT if spec.get("allocation", {}).get("stage") == "probe" else 0)
            and receipt.get("timed_out") is False
            and receipt.get("exception") is None, "actual native process receipt differs")
    for label in ("stdin", "stdout", "stderr", "effects"):
        require(receipt.get(label) == pin(case / (label + ".bin")),
                "native raw stream pin differs")
    if spec.get("allocation", {}).get("stage") != "probe":
        require(ordinary(case / "stderr.bin") == b"", "native diagnostic stream nonempty")
    raw_stdout, raw_stdin, raw_trace = (ordinary(case / (name + ".bin"))
                                       for name in ("stdout", "stdin", "effects"))
    ready = transport_prefix(raw_stdout)[0]
    validation, loan = verify_case_trace(spec, case, receipt, raw_stdout, raw_stdin, raw_trace)
    validation["setup"] = verify_setup(spec, case, receipt, ready, validation)
    validation["retirement"] = verify_retirement(case, spec, receipt, validation, raw_trace)
    outcome = None
    if outcome_manifest is not None and loan:
        outcome = verify_outcome(case, loan, outcome_manifest)
    require(saved.get("schema") == CASE_SCHEMA and saved.get("status") == "PASS"
            and saved.get("name") == name and saved.get("spec_sha256") == sha(json_bytes(spec))
            and saved.get("validation") == validation and saved.get("outcome") == outcome
            and all(saved.get(key) is value for key, value in SCOPE.items()),
            "case report differs from reconstructed actual IO")
    return {"validation": validation, "outcome": outcome}


def read_evidence(folder, native_manifest, outcome_manifest=None, *, require_full=True):
    """Pure validation: no native load, subprocess, signal, or live /proc lookup."""
    folder = Path(folder).absolute()
    native_manifest = Path(native_manifest).absolute()
    outcome_manifest = Path(outcome_manifest).absolute() if outcome_manifest is not None else None
    build = read_build(native_manifest)
    report = strict_json(ordinary(folder / "report.json"))
    all_specs = specs()
    selected = report.get("case_names")
    require(type(selected) is list and selected and len(selected) == len(set(selected)),
            "missing or duplicate IO cases")
    known = {x["name"]: x for x in all_specs}
    require(all(name in known for name in selected)
            and selected == [x["name"] for x in all_specs if x["name"] in selected],
            "unregistered/reordered IO cases")
    complete = selected == [x["name"] for x in all_specs]
    require(not require_full or complete, "partial IO suite cannot qualify the full corpus")
    require(report.get("schema") == SCHEMA and report.get("status") == "NATIVE_IO_PASS"
            and report.get("complete_registered_corpus") is complete
            and report.get("registered_specs") == [known[name] for name in selected]
            and report.get("native_manifest") == str(native_manifest)
            and report.get("native_manifest_pin") == pin(native_manifest)
            and report.get("native_build") == build
            and report.get("io_only") is (outcome_manifest is None)
            and report.get("native_phase_cases_added_by_reference") == 0
            and report.get("original_rust_comparison_qualified") is False
            and all(report.get(key) is value for key, value in SCOPE.items()),
            "IO report identity/scope/registered definitions differ")
    producer = Path(report["producer_folder"])
    require(producer.is_absolute() and ".." not in producer.parts, "recorded producer path")
    require(set(report.get("source_files", {})) == set(SOURCES), "IO source inventory differs")
    for name in SOURCES:
        expected = report["source_files"][name]
        path = folder / "source-snapshots" / name
        require(pin(path) == expected and ordinary(path) == ordinary(ROOT / name),
                "IO producer/shared specification source changed")
    if outcome_manifest is None:
        require(report.get("outcome_manifest") is None and report.get("outcome_manifest_pin") is None,
                "IO-only suite claimed an outcome module")
    else:
        require(report.get("outcome_manifest") == str(outcome_manifest)
                and report.get("outcome_manifest_pin") == pin(outcome_manifest),
                "actual outcome manifest differs")
    actual_files = inventory(folder)
    del actual_files["report.json"]
    require(actual_files == report.get("files"), "IO full retained file inventory differs")
    require(type(report.get("cases")) is list
            and [row.get("name") for row in report["cases"]] == selected,
            "IO result case inventory")
    totals = {"effects": 0, "actual_read_eintr": 0, "growth_effects": 0,
              "outcome_entries": 0, "retired_fixture_members": 0}
    for row in report["cases"]:
        name, spec = row["name"], known[row["name"]]
        case = folder / "cases" / name
        require(row.get("result_pin") == pin(case / "result.json"), "case result file differs")
        checked = read_case_evidence(case, spec, native_manifest, outcome_manifest, producer)
        validation, outcome = checked["validation"], checked["outcome"]
        totals["effects"] += validation["effects"]
        totals["actual_read_eintr"] += validation["read_eintr"]
        totals["growth_effects"] += validation["growth_effects"]
        totals["retired_fixture_members"] += validation["retirement"]["members"]
        totals["outcome_entries"] += outcome["calls"] if outcome else 0
    require(report.get("totals") == totals, "native IO reconstructed totals differ")
    owner_controls = read_owner_controls(folder / "owner-controls", native_manifest)
    require(report.get("owner_controls") == owner_controls, "owner controls differ")
    reader_controls = None
    if complete:
        reader_controls = read_reader_controls(folder / "reader-controls", folder,
                                               native_manifest, outcome_manifest)
    require(report.get("reader_controls") == reader_controls, "physical reader controls differ")
    return {"schema": "hepta.runtime.shell-output-io-read.v1", "status": "PASS",
            "verification": "current-source-and-manifest;recorded-retired-fixture-bindings",
            "cases": len(selected), "complete_registered_corpus": complete,
            "shared_original_io_cases": len([x for x in io_specs() if x["name"] in selected]),
            "io_only": outcome_manifest is None, "retired_fixtures": len(selected),
            "owner_control_cases": owner_controls["cases"], "owner_control_entries": owner_controls["entries"],
            "reader_controls": reader_controls,
            "report_sha256": sha(ordinary(folder / "report.json")),
            "native_phase_cases_added_by_reference": 0,
            "original_rust_comparison_qualified": False, **totals, **SCOPE}


def run(output, native_manifest, outcome_manifest=None, selected=None):
    output = Path(output).absolute()
    native_manifest = Path(native_manifest).absolute()
    outcome_manifest = Path(outcome_manifest).absolute() if outcome_manifest is not None else None
    build = read_build(native_manifest)
    definitions = specs()
    if selected:
        names = set(selected)
        require(len(names) == len(selected) and names <= {x["name"] for x in definitions},
                "unknown/duplicate selected case")
        chosen = [x for x in definitions if x["name"] in names]
    else:
        chosen = definitions
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    (output / "cases").mkdir()
    source_files = {}
    for name in SOURCES:
        raw = ordinary(ROOT / name)
        path = output / "source-snapshots" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        write_new(path, raw)
        source_files[name] = pin(path)
    owner_controls = run_owner_controls(output / "owner-controls", native_manifest)
    rows = []
    totals = {"effects": 0, "actual_read_eintr": 0, "growth_effects": 0,
              "outcome_entries": 0, "retired_fixture_members": 0}
    for spec in chosen:
        case = output / "cases" / spec["name"]
        result = run_case(spec, case, native_manifest, outcome_manifest)
        rows.append({"name": spec["name"], "result_pin": pin(case / "result.json")})
        v, outcome = result["validation"], result["outcome"]
        totals["effects"] += v["effects"]
        totals["actual_read_eintr"] += v["read_eintr"]
        totals["growth_effects"] += v["growth_effects"]
        totals["retired_fixture_members"] += v["retirement"]["members"]
        totals["outcome_entries"] += outcome["calls"] if outcome else 0
        print(json.dumps({"case": spec["name"], "status": "NATIVE_IO_PASS",
                          "effects": v["effects"], "outcome": outcome is not None}), flush=True)
    reader_controls = None
    if chosen == definitions:
        reader_controls = run_reader_controls(output / "reader-controls", output,
                                              native_manifest, outcome_manifest)
    for name in SOURCES:
        require(pin(ROOT / name) == source_files[name], "IO source changed during actual run")
    require(read_build(native_manifest) == build, "native build changed during actual run")
    report = {"schema": SCHEMA, "status": "NATIVE_IO_PASS", "producer_folder": str(output),
              "complete_registered_corpus": chosen == definitions,
              "registered_specs": chosen, "case_names": [x["name"] for x in chosen],
              "native_manifest": str(native_manifest), "native_manifest_pin": pin(native_manifest),
              "native_build": build, "outcome_manifest": str(outcome_manifest) if outcome_manifest else None,
              "outcome_manifest_pin": pin(outcome_manifest) if outcome_manifest else None,
              "io_only": outcome_manifest is None, "source_files": source_files,
              "cases": rows, "files": inventory(output), "totals": totals,
              "owner_controls": owner_controls, "reader_controls": reader_controls,
              "native_phase_cases_added_by_reference": 0,
              "original_rust_comparison_qualified": False, **SCOPE}
    write_new(output / "report.json", json_bytes(report))
    return read_evidence(output, native_manifest, outcome_manifest,
                         require_full=chosen == definitions)


OWNER_CONTROLS = (
    "fresh-pending", "pending-resume", "cancel-pending", "dirty-workspace",
    "short-workspace", "short-output", "short-request", "trailing-request",
    "bad-magic", "unknown-operation", "zero-token", "wide-wait-status",
    "noncanonical-errno", "unknown-wait-kind", "shadow-action",
    "completion-result-with-error", "completion-aux", "completion-ready",
    "admission-error",
)


def owner_control_recipe(name):
    require(name in OWNER_CONTROLS, "unregistered owner control")
    request = frame({"exit_code": 0})
    output_capacity, workspace_capacity = 64, 8192
    workspace = bytearray(workspace_capacity)
    active = name in ("pending-resume", "cancel-pending", "shadow-action",
                      "completion-result-with-error", "completion-aux",
                      "completion-ready", "admission-error")
    if name == "dirty-workspace":
        workspace[1000] = 1
    elif name == "short-workspace":
        workspace_capacity = 8191
        workspace = workspace[:workspace_capacity]
    elif name == "short-output":
        output_capacity = 63
    elif name == "short-request":
        request = request[:-1]
    elif name == "trailing-request":
        request += b"x"
    elif name == "bad-magic":
        request = b"X" + request[1:]
    elif name in ("unknown-operation", "zero-token", "wide-wait-status",
                  "noncanonical-errno", "unknown-wait-kind"):
        request = bytearray(request)
        if name == "unknown-operation":
            struct.pack_into("<Q", request, 8, 0)
        if name == "zero-token":
            struct.pack_into("<Q", request, 16, 0)
        if name == "wide-wait-status":
            struct.pack_into("<Q", request, 32, 1 << 32)
        if name == "noncanonical-errno":
            struct.pack_into("<2Q", request, 24, 2, 1 << 31)
        if name == "unknown-wait-kind":
            struct.pack_into("<Q", request, 24, 1)
        request = bytes(request)
    if name in ("fresh-pending", "pending-resume", "cancel-pending"):
        returned = 0xfffffff0
    elif name in ("short-workspace", "short-output"):
        returned = 0xfffffffe
    elif name in ("dirty-workspace", "shadow-action", "completion-result-with-error",
                  "completion-aux", "completion-ready", "admission-error"):
        returned = 0xfffffff9
    else:
        returned = 0xffffffff
    return request, output_capacity, workspace_capacity, bytes(workspace), active, returned


def owner_pending_workspace(size=8192):
    raw = bytearray(size)
    fields = {0: int.from_bytes(b"HSHOIST1", "little"), 8: 1, 16: 1, 24: 1, 48: 4208,
              256: int.from_bytes(b"HSHOIFX1", "little"), 264: 1, 272: 1, 280: 1,
              896: 1, 904: 1, 928: 1}
    for at, value in fields.items():
        struct.pack_into("<Q", raw, at, value)
    return bytes(raw)


def owner_second_input(name, workspace):
    request = frame({"exit_code": 0}, 3 if name == "cancel-pending" else 2)
    raw = bytearray(workspace)
    if name == "shadow-action":
        struct.pack_into("<Q", raw, 272, 99)
    elif name == "completion-result-with-error":
        struct.pack_into("<Q", raw, 312, 1)
        struct.pack_into("<Q", raw, 320, 2)
        struct.pack_into("<Q", raw, 336, 1)
    elif name == "completion-aux":
        struct.pack_into("<Q", raw, 328, 1)
        struct.pack_into("<Q", raw, 336, 1)
    elif name == "completion-ready":
        struct.pack_into("<Q", raw, 336, 2)
    elif name == "admission-error":
        struct.pack_into("<Q", raw, 320, 13)
        struct.pack_into("<Q", raw, 336, 1)
    return request, bytes(raw)


def owner_expected_after(name, initial, active_entry):
    if not active_entry and (name == "fresh-pending" or owner_control_recipe(name)[4]):
        return owner_pending_workspace(len(initial))
    raw = bytearray(initial)
    if active_entry and name == "cancel-pending":
        struct.pack_into("<Q", raw, 208, 1)
    if active_entry and name == "admission-error":
        struct.pack_into("<Q", raw, 952, 13)
        struct.pack_into("<Q", raw, 336, 0)
    return bytes(raw)


def owner_manifest_path(native_manifest):
    top = strict_json(ordinary(native_manifest))
    return native_manifest.parent.parent / top["owner_manifest"]


def run_owner_controls(folder, native_manifest):
    import ctypes
    import zlib
    from hia_native_loader import NativeModule
    folder.mkdir(mode=0o700)
    owner = owner_manifest_path(native_manifest)
    owner_metadata = strict_json(ordinary(owner))
    rows = []
    with NativeModule(owner, manifest_sha256=sha(ordinary(owner))) as module:
        for name in OWNER_CONTROLS:
            case = folder / name
            case.mkdir()
            request, out_cap, work_cap, work, active, expected = owner_control_recipe(name)
            entries = []
            for index in range(2 if active else 1):
                if index:
                    request, work = owner_second_input(name, work)
                desired = expected if index or not active else 0xfffffff0
                buffers = [ctypes.create_string_buffer(len(request)+32),
                           ctypes.create_string_buffer(out_cap+32),
                           ctypes.create_string_buffer(work_cap+32)]
                lengths = [len(request), out_cap, work_cap]
                for buffer, size, left, right in zip(buffers, lengths, (0x31, 0x41, 0x51),
                                                     (0x32, 0x42, 0x52)):
                    ctypes.memset(ctypes.addressof(buffer), left, 16)
                    ctypes.memset(ctypes.addressof(buffer)+16+size, right, 16)
                ctypes.memmove(ctypes.addressof(buffers[0])+16, request, len(request))
                ctypes.memset(ctypes.addressof(buffers[1])+16, 0xa7, out_cap)
                ctypes.memmove(ctypes.addressof(buffers[2])+16, work, len(work))
                before = [bytes(x) for x in buffers]
                started = time.monotonic_ns()
                with module._lock:
                    require(module._entry is not None, "owner image not admitted")
                    returned = int(module._entry(
                        ctypes.addressof(buffers[0])+16, lengths[0],
                        ctypes.addressof(buffers[1])+16, lengths[1],
                        ctypes.addressof(buffers[2])+16, lengths[2]))
                finished = time.monotonic_ns()
                after = [bytes(x) for x in buffers]
                arrays = {}
                entry_dir = case / str(index)
                entry_dir.mkdir()
                for label, values in (("before", before), ("after", after)):
                    for kind, raw in zip(("input", "output", "workspace"), values):
                        key = kind + "_" + label
                        target = entry_dir / (key + ".bin.z")
                        write_new(target, zlib.compress(raw, 9))
                        arrays[key] = {"path": str(target.relative_to(folder)),
                                       "compressed": pin(target),
                                       "uncompressed": {"size": len(raw), "sha256": sha(raw)}}
                observed_work = after[2][16:-16]
                record = {"schema": "hepta.runtime.shell-output-owner-entry.v1",
                          "name": name, "index": index, "pid": os.getpid(), "returned": returned,
                          "expected_return": desired, "input_capacity": len(request),
                          "output_capacity": out_cap, "workspace_capacity": work_cap,
                          "started_ns": started, "finished_ns": finished,
                          "duration_ns": finished-started, "manifest_sha256": sha(ordinary(owner)),
                          "image_sha256": owner_metadata["image_sha256"],
                          "source_sha256": owner_metadata["source_sha256"], "arrays": arrays}
                write_new(entry_dir / "entry.json", json_bytes(record))
                entries.append(str((entry_dir / "entry.json").relative_to(folder)))
                require(returned == desired and before[0] == after[0] and before[1] == after[1],
                        "owner pending/refusal changed input/output")
                require(observed_work == owner_expected_after(name, work, bool(index)),
                        "owner continuation/completion state differs")
                for old, new in zip(before, after):
                    require(old[:16] == new[:16] and old[-16:] == new[-16:],
                            "owner actual guard changed")
                work = observed_work
            rows.append({"name": name, "entries": entries})
    report = {"schema": "hepta.runtime.shell-output-owner-controls.v1", "status": "PASS",
              "native_manifest": str(native_manifest), "owner_manifest": str(owner),
              "owner_manifest_pin": pin(owner), "cases": rows,
              "actual_syscall_effects": False, **SCOPE}
    write_new(folder / "report.json", json_bytes(report))
    return read_owner_controls(folder, native_manifest)


def read_owner_controls(folder, native_manifest):
    import zlib
    report = strict_json(ordinary(folder / "report.json"))
    owner = owner_manifest_path(native_manifest)
    metadata = strict_json(ordinary(owner))
    require(report.get("schema") == "hepta.runtime.shell-output-owner-controls.v1"
            and report.get("status") == "PASS" and report.get("native_manifest") == str(native_manifest)
            and report.get("owner_manifest") == str(owner) and report.get("owner_manifest_pin") == pin(owner)
            and report.get("actual_syscall_effects") is False
            and [x["name"] for x in report["cases"]] == list(OWNER_CONTROLS)
            and all(report.get(key) is value for key, value in SCOPE.items()),
            "owner control inventory/binding")
    count = 0
    for row in report["cases"]:
        name = row["name"]
        request, out_cap, work_cap, work, active, expected = owner_control_recipe(name)
        require(row["entries"] == [name + "/" + str(i) + "/entry.json"
                                   for i in range(2 if active else 1)],
                "owner control actual entry inventory")
        for index, relative in enumerate(row["entries"]):
            if index:
                request, work = owner_second_input(name, work)
            desired = expected if index or not active else 0xfffffff0
            entry = strict_json(ordinary(folder / relative))
            require(entry.get("schema") == "hepta.runtime.shell-output-owner-entry.v1"
                    and entry.get("name") == name and entry.get("index") == index
                    and entry.get("manifest_sha256") == sha(ordinary(owner))
                    and entry.get("image_sha256") == metadata["image_sha256"]
                    and entry.get("source_sha256") == metadata["source_sha256"]
                    and type(entry.get("pid")) is int and entry["pid"] > 0
                    and entry.get("returned") == entry.get("expected_return") == desired
                    and entry.get("input_capacity") == len(request)
                    and entry.get("output_capacity") == out_cap
                    and entry.get("workspace_capacity") == work_cap
                    and type(entry.get("started_ns")) is int
                    and type(entry.get("finished_ns")) is int
                    and entry["finished_ns"] >= entry["started_ns"]
                    and entry["duration_ns"] == entry["finished_ns"] - entry["started_ns"],
                    "owner actual entry receipt")
            desired_work = owner_expected_after(name, work, bool(index))
            arrays = {
                "input_before": b"1"*16 + request + b"2"*16,
                "input_after": b"1"*16 + request + b"2"*16,
                "output_before": b"A"*16 + b"\xa7"*out_cap + b"B"*16,
                "output_after": b"A"*16 + b"\xa7"*out_cap + b"B"*16,
                "workspace_before": b"Q"*16 + work + b"R"*16,
                "workspace_after": b"Q"*16 + desired_work + b"R"*16,
            }
            require(set(entry["arrays"]) == set(arrays), "owner array inventory")
            for key, desired_bytes in arrays.items():
                item = entry["arrays"][key]
                require(item["path"] == name + "/" + str(index) + "/" + key + ".bin.z"
                        and item["compressed"] == pin(folder / item["path"])
                        and item["uncompressed"] == {"size": len(desired_bytes),
                                                     "sha256": sha(desired_bytes)},
                        "owner full array pin/path")
                raw = ordinary(folder / item["path"])
                decoder = zlib.decompressobj()
                actual = decoder.decompress(raw, len(desired_bytes)+1)
                require(actual == desired_bytes and decoder.eof
                        and not decoder.unconsumed_tail and not decoder.unused_data,
                        "owner full before/after/refusal/guard bytes differ")
            work = desired_work
            count += 1
    return {"status": "PASS", "cases": len(OWNER_CONTROLS), "entries": count,
            "actual_syscall_effects": False}


READER_CONTROLS = (
    ("positive","normal",None),
    ("loan-byte","normal","HIA typed loan differs from actual raw Results"),
    ("early-unlink","normal","discard did not follow both completed reads"),
    ("missing-close","normal","read open order differs"),
    ("extra-probe","normal","metadata probe not admitted"),
    ("schedule-control","append_after_metadata","schedule differs from actual gate/control bytes"),
    ("cancel-foreground","cancel_during_read","cancel fabricated foreground outcome"),
    ("missing-footer","normal","missing/extra effect footer"),
)

def file_map(folder):
    return {name:ordinary(folder/name) for name in inventory(folder)}

def memory_pin(raw):
    return {"size":len(raw),"sha256":sha(raw)}

def control_recipe(name, baseline, spec):
    """Reconstruct the complete named physical mutation in memory."""
    result=dict(baseline)
    require(name in {x[0] for x in READER_CONTROLS},"unknown physical recipe")
    if name=="positive":
        return result
    if name=="loan-byte":
        raw=bytearray(result["stdout.bin"])
        _,_,at=transport_prefix(raw)
        raw[at+16+64+112]^=1
        result["stdout.bin"]=bytes(raw)
    elif name=="schedule-control":
        value=strict_json(result["setup.json"])
        event=next(x for x in value["schedule"] if x["action"]==5)
        event.update(action=999,args=[3,4,5],op=3)
        result["setup.json"]=json_bytes(value)
    elif name=="missing-footer":
        result["effects.bin"]=result["effects.bin"][:-128]
    elif name=="cancel-foreground":
        _,_,at=transport_prefix(result["stdout.bin"])
        values=expected_reads(spec);out=values["stdout"][2];err=values["stderr"][2]
        loan=b"HSHOUT01"+struct.pack("<13Q",1,0,0,0,0,0,0,0,0,len(out),len(err),0,0)+out+err
        desc=b"HSHOID01"+struct.pack("<7Q",1,1,4096,len(loan),0,0,0)
        result["stdout.bin"]=result["stdout.bin"][:at]+struct.pack("<2Q",64,64+len(loan))+desc+loan
    else:
        records,footer=decode_trace(result["effects.bin"])
        opening=records[:2];pairs=[records[i:i+2] for i in range(2,len(records),2)]
        if name=="early-unlink":
            i=next(i for i,p in enumerate(pairs) if p[0]["q"][2]==8)
            moved=pairs.pop(i)
            i=next(i for i,p in enumerate(pairs) if p[0]["q"][2]==6)+1
            pairs.insert(i,moved)
        elif name=="missing-close":
            i=next(i for i,p in enumerate(pairs) if p[0]["q"][2]==6)
            pairs.pop(i)
        else:
            i=next(i for i,p in enumerate(pairs) if p[0]["q"][2]==3)
            q=list(pairs[i][0]["q"]);q[1:4]=[0,9,0];q[7]=pairs[i][1]["q"][7]
            q[8:]=[0]*8
            c=list(q);c[3]=1;c[11]=U64-13;c[12]=14
            pairs.insert(i+1,[{"q":tuple(q),"payload":b""},{"q":tuple(c),"payload":b""}])
        data=bytearray()
        for item in opening:
            data.extend(struct.pack("<16Q",*item["q"])+item["payload"])
        for seq,pair in enumerate(pairs,1):
            for item in pair:
                q=list(item["q"]);q[1]=seq
                data.extend(struct.pack("<16Q",*q)+item["payload"])
        foot=list(footer);foot[2]=2+2*len(pairs);foot[3]=foot[4]=len(pairs)
        result["effects.bin"]=bytes(data)+struct.pack("<16Q",*foot)

    process=strict_json(result["process.json"])
    for label in ("stdin","stdout","stderr","effects"):
        process[label]=memory_pin(result[label+".bin"])
    result["process.json"]=json_bytes(process)
    retired=strict_json(result["retirement.json"])
    retired["process_receipt_sha256"]=sha(result["process.json"])
    if result["effects.bin"]!=baseline["effects.bin"]:
        item=next(x for x in retired["entries"] if x["name"]=="effects.bin")
        result[item["payload"]["path"]]=result["effects.bin"]
        item["payload"].update(memory_pin(result["effects.bin"]))
        item["identity"]["size"]=len(result["effects.bin"])
        removed=next(x for x in retired["removed"]
                     if x["relative_path_hex"]==os.fsencode("effects.bin").hex())
        removed["identity_before"]=item["identity"]
    result["retirement.json"]=json_bytes(retired)
    return result

def read_only_audit():
    attempted=[]
    forbidden={"os.fork","os.forkpty","os.kill","os.killpg","os.system","os.posix_spawn",
               "os.posix_spawnp","os.exec","os.remove","os.rename","os.rmdir","os.mkdir",
               "os.chmod","os.chown","os.truncate","os.symlink","os.link","os.chdir",
               "os.putenv","os.unsetenv","signal.pthread_kill"}
    def hook(event,args):
        blocked=event in forbidden or event.startswith(("subprocess.","socket.","ctypes.dlopen",
                                                        "ctypes.dlsym","ctypes.call_function"))
        if event=="open":
            mode=args[1] if len(args)>1 else None
            flags=args[2] if len(args)>2 else 0
            blocked|=isinstance(mode,str) and any(x in mode for x in ("w","a","+","x"))
            blocked|=isinstance(flags,int) and bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if event in ("open","os.listdir","os.scandir","os.readlink") and args:
            if isinstance(args[0],(str,bytes,os.PathLike)):
                path=os.fsdecode(args[0]);blocked|=path=="/proc" or path.startswith("/proc/")
        if blocked:
            attempted.append(event)
            raise RuntimeError("read-only audit rejected "+event)
    sys.addaudithook(hook)
    return attempted

def run_reader_controls(folder,evidence,native_manifest,outcome_manifest):
    folder.mkdir(mode=0o700)
    definitions={x["name"]:x for x in specs()}
    executable=Path(sys.executable).resolve(strict=True)
    tool=pin(executable);source=pin(ROOT/"tests/hia_native/shell_output_io.py")
    rows=[]
    for name,base,reason in READER_CONTROLS:
        case=folder/name;case.mkdir();copied=case/"copy";copied.mkdir()
        original=evidence/"cases"/base;spec=definitions[base]
        read_case_evidence(original,spec,native_manifest,outcome_manifest,evidence)
        before=file_map(original);desired=control_recipe(name,before,spec)
        for relative,raw in desired.items():
            target=copied/relative;target.parent.mkdir(parents=True,exist_ok=True);write_new(target,raw)
        argv=[str(executable),"-B",str(ROOT/"tests/hia_native/shell_output_io.py"),
              "--native-manifest",str(native_manifest),"--probe-case",str(copied),
              "--probe-name",base,"--recorded-producer",str(evidence)]
        if outcome_manifest:
            argv+=["--outcome-manifest",str(outcome_manifest)]
        env={"PATH":"/usr/bin:/bin","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"}
        start=time.monotonic_ns()
        child=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        timeout=False
        try:
            out,err=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timeout=True;child.kill();out,err=child.communicate(timeout=5)
        end=time.monotonic_ns()
        write_new(case/"stdout.bin",out);write_new(case/"stderr.bin",err)

        process={"schema":"hepta.runtime.shell-output-reader-process.v1","argv":argv,
                 "cwd":str(ROOT),"env":env,"pid":child.pid,"exit_code":child.returncode,
                 "timed_out":timeout,"deadline_ns":30_000_000_000,"started_ns":start,
                 "finished_ns":end,"duration_ns":end-start,"executable":str(executable),
                 "tool_before":tool,"tool_after":pin(executable),"source_before":source,
                 "source_after":pin(ROOT/"tests/hia_native/shell_output_io.py"),
                 "stdout":pin(case/"stdout.bin"),"stderr":pin(case/"stderr.bin")}
        write_new(case/"process.json",json_bytes(process))
        changes={p:{"before":memory_pin(before[p]),"after":memory_pin(raw)}
                 for p,raw in desired.items() if before[p]!=raw}
        result={"name":name,"baseline_case":base,"expected_reason":reason,"changes":changes,
                "copy_files":inventory(copied),"process_pin":pin(case/"process.json")}
        write_new(case/"result.json",json_bytes(result))
        require(not timeout and not err and child.returncode==(0 if reason is None else 2),
                "actual physical reader process failed: "+name)
        require(strict_json(out)=={"status":"PASS" if reason is None else "REJECTED",
                                   "case":base,"reason":reason,"forbidden_calls":0},
                "actual named physical refusal differs: "+name)
        rows.append({"name":name,"result_pin":pin(case/"result.json")})
    report={"schema":"hepta.runtime.shell-output-reader-controls.v1","status":"PASS",
            "recorded_evidence":str(evidence),"native_manifest":str(native_manifest),
            "outcome_manifest":str(outcome_manifest) if outcome_manifest else None,
            "source_pin":source,"cases":rows,"actual_reader_processes":len(rows),
            "physical_mutations_reconstructed":True,"reader_forbidden_calls":0}
    write_new(folder/"report.json",json_bytes(report))
    return read_reader_controls(folder,evidence,native_manifest,outcome_manifest)

def read_reader_controls(folder,evidence,native_manifest,outcome_manifest):
    report=strict_json(ordinary(folder/"report.json"))
    definitions={x["name"]:x for x in specs()}
    require(report.get("schema")=="hepta.runtime.shell-output-reader-controls.v1"
            and report.get("status")=="PASS" and report.get("recorded_evidence")==str(evidence)
            and report.get("native_manifest")==str(native_manifest)
            and report.get("outcome_manifest")== (str(outcome_manifest) if outcome_manifest else None)
            and report.get("source_pin")==pin(ROOT/"tests/hia_native/shell_output_io.py")
            and [x["name"] for x in report["cases"]]==[x[0] for x in READER_CONTROLS]
            and report.get("actual_reader_processes")==len(READER_CONTROLS)
            and report.get("physical_mutations_reconstructed") is True
            and report.get("reader_forbidden_calls")==0,"physical control inventory/scope")
    for row,(name,base,reason) in zip(report["cases"],READER_CONTROLS):
        case=folder/name;copied=case/"copy";spec=definitions[base]
        require(row["result_pin"]==pin(case/"result.json"),"physical result pin")
        result=strict_json(ordinary(case/"result.json"))
        before=file_map(evidence/"cases"/base);expected=control_recipe(name,before,spec)
        changes={p:{"before":memory_pin(before[p]),"after":memory_pin(raw)}
                 for p,raw in expected.items() if before[p]!=raw}
        require(file_map(copied)==expected and result.get("name")==name
                and result.get("baseline_case")==base and result.get("expected_reason")==reason
                and result.get("changes")==changes and result.get("copy_files")==inventory(copied)
                and bool(changes)==(reason is not None),"named physical mutation byte recipe differs")
        process=strict_json(ordinary(case/"process.json"))
        argv=[process["executable"],"-B",str(ROOT/"tests/hia_native/shell_output_io.py"),
              "--native-manifest",str(native_manifest),"--probe-case",str(copied),
              "--probe-name",base,"--recorded-producer",str(evidence)]
        if outcome_manifest:
            argv+=["--outcome-manifest",str(outcome_manifest)]

        require(result["process_pin"]==pin(case/"process.json")
                and process.get("schema")=="hepta.runtime.shell-output-reader-process.v1"
                and process.get("argv")==argv and process.get("cwd")==str(ROOT)
                and process.get("env")=={"PATH":"/usr/bin:/bin","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"}
                and process.get("tool_before")==process.get("tool_after")==pin(Path(process["executable"]))
                and process.get("source_before")==process.get("source_after")==report["source_pin"]
                and type(process.get("pid")) is int and process["pid"]>0
                and process.get("exit_code")== (0 if reason is None else 2)
                and process.get("timed_out") is False and process.get("deadline_ns")==30_000_000_000
                and 0<=process["duration_ns"]==process["finished_ns"]-process["started_ns"]<=30_000_000_000
                and process.get("stdout")==pin(case/"stdout.bin") and process.get("stderr")==pin(case/"stderr.bin")
                and ordinary(case/"stderr.bin")==b"","actual physical reader receipt differs")
        require(strict_json(ordinary(case/"stdout.bin"))==
                {"status":"PASS" if reason is None else "REJECTED","case":base,
                 "reason":reason,"forbidden_calls":0},"actual reader full stdout")
        rejected=None
        try:
            read_case_evidence(copied,spec,native_manifest,outcome_manifest,evidence)
        except Exception as exc:
            rejected=str(exc)
        require(rejected==reason,"current pure reader does not reproduce named refusal")
    return {"status":"PASS","actual_reader_processes":len(READER_CONTROLS),
            "positive_controls":1,"physical_refusals":len(READER_CONTROLS)-1,
            "physical_mutations_reconstructed":True,"reader_forbidden_calls":0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", required=True, type=Path)
    parser.add_argument("--outcome-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--case", action="append")
    parser.add_argument("--probe-case", type=Path)
    parser.add_argument("--probe-name")
    parser.add_argument("--recorded-producer", type=Path)
    parser.add_argument("--audit-read-only", action="store_true")
    args = parser.parse_args()
    if args.probe_case is not None:
        require(args.probe_name is not None and args.recorded_producer is not None
                and not args.verify and not args.output and not args.case, "pure case probe arguments")
        attempts = read_only_audit()
        reason = None
        try:
            spec = next(x for x in specs() if x["name"] == args.probe_name)
            read_case_evidence(args.probe_case,spec,args.native_manifest,args.outcome_manifest,
                               args.recorded_producer)
        except Exception as exc:
            reason = str(exc)
        print(json.dumps({"status":"PASS" if reason is None else "REJECTED","case":args.probe_name,
                          "reason":reason,"forbidden_calls":len(attempts)},sort_keys=True))
        raise SystemExit(0 if reason is None else 2)
    if args.verify:
        require(not args.output and not args.case, "--verify is a pure full reader")
        if args.audit_read_only:
            attempts = read_only_audit()
        result = read_evidence(args.verify, args.native_manifest, args.outcome_manifest)
        if args.audit_read_only:
            require(not attempts, "full reader attempted a forbidden effect")
            result["read_only_audit_forbidden_calls"] = len(attempts)
    else:
        require(args.output is not None, "--output is required for actual execution")
        result = run(args.output, args.native_manifest, args.outcome_manifest, args.case)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
