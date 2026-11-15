"""Capture the actual ELF ABI and compare relocatable filesystem observations."""
from pathlib import Path
import hashlib
import errno
import math
import os
import re
import selectors
import signal
import struct
import subprocess
import time

U64 = (1 << 64) - 1

def frame(operation, first=b"", second=b"", generation=0):
    body = b"HFSPQ002" + struct.pack("<7Q", operation, len(first), len(second), generation, 0, 0, 0) + first + second
    return struct.pack("<Q", len(body)) + body

def case_input(case, generation):
    run = frame(case["operation"], case["first"], case["second"])
    return run + run + frame(4, generation=generation)

class NativeProcess:
    def __init__(self, output, name, cases, binary, regular_input, support):
        self.output, self.name, self.cases, self.support = output, name, cases, support
        self.folder = output / "processes" / name
        self.folder.mkdir(parents=True)
        self.input_path = self.folder / "input.bin"
        with self.input_path.open("xb") as stream:
            for generation, case in enumerate(cases, 1):
                stream.write(case_input(case, generation))
        self.command = ["/usr/bin/strace", "-f", "-qq", "-ttt", "-s", "0", "-xx",
                        "-e", "trace=%file,%desc,getpgid",
                        "-e", "raw=read,write,readv,writev,pread64,pwrite64,preadv,pwritev,sendfile,splice,tee,vmsplice",
                        "-o", str(self.folder / "trace.txt"), str(binary)]
        self.regular_input = regular_input
        self.begin = time.monotonic()
        self.deadline = self.begin + 60
        self.error = (self.folder / "stderr.bin").open("xb")
        self.out = (self.folder / "stdout.bin").open("xb")
        self.infile = self.input_path.open("rb") if regular_input else None
        self.proc = subprocess.Popen(self.command, cwd=output, stdin=self.infile or subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self.error, start_new_session=True, bufsize=0,
                                     umask=0o22)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.proc.stdout, selectors.EVENT_READ)
        self.timed_out = False
        self.input_offset = self.output_offset = 0
        self.generation = 0

    def read(self, count):
        chunks = []
        total = 0
        while total < count:
            left = self.deadline - time.monotonic()
            if left <= 0 or not self.selector.select(left):
                self.timed_out = True
                raise TimeoutError("native output deadline")
            chunk = os.read(self.proc.stdout.fileno(), min(count - total, 1 << 20))
            if not chunk:
                raise EOFError(("incomplete native output", count, total, self.proc.poll()))
            chunks.append(chunk)
            self.out.write(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def read_reply(self):
        header = self.read(16)
        result, size = struct.unpack("<QQ", header)
        assert result == 80 and 80 <= size <= 1104, (result, size)
        body = self.read(size)
        assert body[:8] == b"HFSPO002"
        fields = struct.unpack_from("<9Q", body, 8)
        assert size == 80 + fields[5] + fields[6]
        return header + body, body, fields

    def call(self, case):
        self.generation += 1
        wire = case_input(case, self.generation)
        if not self.regular_input:
            view = memoryview(wire)
            while view:
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("native input deadline")
                written = os.write(self.proc.stdin.fileno(), view)
                view = view[written:]
        first, again, dropped = self.read_reply(), self.read_reply(), self.read_reply()
        assert first == again, (case["case_id"], "terminal redelivery changed")
        raw, body, fields = first
        status, op, created, diagnostic, errno, short_len, chain_len, generation, sequence = fields
        assert status in (0, 1) and op == case["operation"] and created in (0, 1) and errno <= 4095
        assert generation == self.generation
        assert dropped[2] == (2, 4, 0, 0, 0, 0, 0, generation, sequence)
        complete = raw + again[0] + dropped[0]
        result = {"case_id": case["case_id"], "operation": op, "status": status,
                  "created_any": created, "diagnostic": diagnostic, "errno": errno,
                  "short": body[80:80 + short_len].decode("utf-8"),
                  "chain": body[80 + short_len:].decode("utf-8"), "generation": generation, "sequence": sequence,
                  "input_offset": self.input_offset, "input_bytes": len(wire), "input_sha256": hashlib.sha256(wire).hexdigest(),
                  "output_offset": self.output_offset, "output_bytes": len(complete), "output_sha256": hashlib.sha256(complete).hexdigest()}
        self.input_offset += len(wire)
        self.output_offset += len(complete)
        return result

    def finish(self, failure=None):
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        if failure is None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                self.timed_out = True
            else:
                try:
                    self.proc.wait(timeout=left)
                except subprocess.TimeoutExpired:
                    self.timed_out = True
            if self.timed_out:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        else:
            if self.proc.poll() is None:
                os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        trailing = self.proc.stdout.read()
        self.out.write(trailing)
        self.out.close()
        self.error.close()
        self.selector.close()
        self.proc.stdout.close()
        if self.infile:
            self.infile.close()
        result = {"name": self.name, "command": self.command, "cwd": str(self.output), "pid": self.proc.pid,
                  "exit_code": self.proc.returncode, "timed_out": self.timed_out, "timeout_seconds": 60,
                  "elapsed_seconds": time.monotonic() - self.begin, "input_kind": "regular-file" if self.regular_input else "pipe",
                  "cases": [case["case_id"] for case in self.cases], "umask": 0o22, "failure": failure}
        for key, filename in (("stdin", "input.bin"), ("stdout", "stdout.bin"), ("stderr", "stderr.bin"), ("trace", "trace.txt")):
            path = self.folder / filename
            result[key] = {"path": str(path.relative_to(self.output)), **self.support.pin(path)}
        self.support.dump(self.folder / "process.json", result)
        if failure is None:
            assert not self.timed_out and self.proc.returncode == 0 and not trailing, result
        return result

def receipt_evidence(raw, case_ids):
    at = call_count = sequence = index = 0
    terminal_calls = 0
    physical = [-1, -1, -1]
    events = []
    rows = [{"case_id": case_id, "calls": 0, "effects": 0, "opens": 0, "closes": 0,
             "workspace_growth": 0, "output_growth": 0, "terminal_redelivery_without_effect": False} for case_id in case_ids]
    last_call = None
    last_acked = 0
    while at < len(raw):
        assert index < len(rows), "receipt after final DROP"
        row = rows[index]
        if raw[at:at + 8] == b"HFSPCL02":
            assert at + 80 <= len(raw)
            fields = struct.unpack_from("<9Q", raw, at + 8)
            call_count += 1
            assert fields[0] == call_count and fields[4] == sequence + (1 if fields[1] == 0xfffffff0 else 0)
            assert fields[1] in (80, 0xfffffff0, 0xffffffef, 0xffffffee)
            row["calls"] += 1
            result, phase, generation = fields[1:4]
            if result == 0xffffffef:
                assert phase == 0 and generation == index and physical == [-1, -1, -1]
                row["workspace_growth"] += 1
            else:
                assert generation == index + 1
            if result == 0xffffffee:
                assert phase == 100 and physical == [-1, -1, -1]
                row["output_growth"] += 1
            if result == 0xfffffff0:
                assert terminal_calls == 0 and phase in (11, 13, 14, 15, 16, 31, 33, 91)
            if result == 80:
                assert fields[8] == 0 and physical == [-1, -1, -1]
                if phase == 100:
                    terminal_calls += 1
                    assert terminal_calls <= 2
                else:
                    assert phase == 0 and terminal_calls == 2 and row["opens"] == row["closes"]
                    row["terminal_redelivery_without_effect"] = True
                    index += 1
                    terminal_calls = 0
            last_call = fields
            at += 80
        else:
            assert raw[at:at + 8] == b"HFSPAK02" and at + 192 <= len(raw)
            ack = struct.unpack_from("<7Q", raw, at + 8)
            fx_raw = raw[at + 64:at + 192]
            assert fx_raw[:8] == b"HFSPFX02"
            fx = struct.unpack_from("<15Q", fx_raw, 8)
            assert last_call and last_call[1] == 0xfffffff0 and last_call[0] > last_acked
            assert ack[1:3] == (last_call[0], last_call[2]) and ack[6] == last_call[8]
            sequence += 1
            assert fx[:2] == (sequence, index + 1) and fx[:2] == (last_call[4], last_call[3])
            kind = fx[2]
            assert 1 <= kind <= 6 and fx[12:] == (1, 1 if kind == 5 else 0, 0)
            value = ack[0] if ack[0] < (1 << 63) else ack[0] - (1 << 64)
            errno = -value if value < 0 else 0
            assert fx[10] == errno <= 4095
            assert fx[9] == (1 if kind in (1, 2) and errno == 0 else 0)
            if kind != 4 or errno:
                assert fx[11] == 0
            if kind in (1, 2) and not errno:
                slot = fx[3] if kind == 1 else fx[6]
                assert 1 <= slot <= 3 and physical[slot - 1] == -1 and value not in physical
                physical[slot - 1] = value
                row["opens"] += 1
            if kind == 6:
                slot = fx[3]
                assert 1 <= slot <= 3 and physical[slot - 1] >= 0
                physical[slot - 1] = -1
                row["closes"] += 1
            assert list(ack[3:6]) == [x if x >= 0 else U64 for x in physical]
            events.append({"case_id": row["case_id"], "call": last_call[0], "phase": ack[2],
                           "sequence": sequence, "generation": index + 1, "kind": kind,
                           "args": list(fx[3:9]), "raw_result": value, "errno": errno,
                           "stat_mode": fx[11], "owned_mask": ack[6], "physical_slots": physical[:]})
            row["effects"] += 1
            last_acked = last_call[0]
            at += 192
    assert at == len(raw) and index == len(rows) and physical == [-1, -1, -1]
    return {"cases": rows, "events": events, "native_calls": call_count, "effects": sequence,
            "opens": sum(x["opens"] for x in rows), "closes": sum(x["closes"] for x in rows)}

class StateNormalizer:
    def __init__(self, home, cross_root):
        self.prefixes = [(os.fsencode(home), b"@fixture"), (os.fsencode(cross_root), b"@cross")]
        self.inodes = {}
        self.devices = {}

    def path(self, raw):
        for old, new in self.prefixes:
            if raw == old or raw.startswith(old + b"/"):
                return new + raw[len(old):]
        return raw

    def normalize(self, state):
        rows = []
        for item in state["entries"]:
            row = {"path_hex": self.path(bytes.fromhex(item["path_hex"])).hex()}
            for key in ("lstat_error", "read_error", "list_error"):
                if key in item:
                    row[key] = {"errno": item[key]["errno"]}
            if "stat" in item:
                metadata = item["stat"]
                identity = (metadata["dev"], metadata["ino"])
                if identity not in self.inodes:
                    self.inodes[identity] = len(self.inodes)
                if metadata["dev"] not in self.devices:
                    self.devices[metadata["dev"]] = len(self.devices)
                row["stat"] = {key: metadata[key] for key in ("mode", "nlink", "uid", "gid", "size")}
                row["stat"].update({"device_identity": self.devices[metadata["dev"]], "inode_identity": self.inodes[identity]})
            for key in ("kind", "children_hex"):
                if key in item:
                    row[key] = item[key]
            if "target_hex" in item:
                row["target_hex"] = self.path(bytes.fromhex(item["target_hex"])).hex()
            if "content" in item:
                row["content"] = {key: item["content"][key] for key in ("bytes", "sha256")}
            rows.append(row)
        return {"roots_hex": [self.path(bytes.fromhex(x)).hex() for x in state["roots_hex"]], "entries": rows}

def stat_mode(display):
    match = re.search(r"\bst_mode=(S_IF[A-Z]+)(?:\|([0-7]+))?", display)
    assert match, ("missing actual stat mode", display)
    import stat
    return getattr(stat, match[1]) | (int(match[2], 8) if match[2] else 0)

def trace_evidence(raw, cases, rows, receipt, stream_bytes, strict):
    text = raw.decode("ascii")
    assert text and text.endswith("\n")
    pid = None
    reads = writes = errors = 0
    effects = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"(\d+) (\d+\.\d+) ([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*=\s*(.*)", line)
        assert match, ("incomplete native syscall record", line_number)
        actual_pid, stamp, name, arguments, tail = match.groups()
        actual_pid = int(actual_pid)
        if pid is None:
            pid = actual_pid
            assert name == "execve" and line_number == 1
        assert actual_pid == pid and math.isfinite(float(stamp))
        returned = re.match(r"(-?(?:0x[0-9a-f]+|[0-9]+))(?: ([A-Z][A-Z0-9_]+))?", tail)
        assert returned
        value = int(returned[1], 16 if "0x" in returned[1] else 10)
        error = returned[2]
        args = strict.split_args(arguments)
        if name in ("openat", "mkdirat", "newfstatat", "renameat2", "close"):
            effects.append({"name": name, "args": args, "return": value, "errno": error, "line": line_number})
        elif name in ("read", "write"):
            assert len(args) == 3 and not error and 0 <= value <= int(args[2], 0)
            fd = int(args[0], 0)
            if name == "read":
                assert fd == 0
                reads += value
            else:
                assert fd in (1, 2)
                if fd == 1:
                    writes += value
                else:
                    errors += value
        elif name == "mmap":
            assert len(args) == 6 and args[4] == "-1" and "MAP_ANONYMOUS" in args[3] and not error
        else:
            assert name == "execve" and line_number == 1 and value == 0 and not error, name
    assert (reads, writes, errors) == stream_bytes
    assert len(effects) == len(receipt["events"])
    by_case = {case["case_id"]: [] for case in cases}
    names = {1: "openat", 2: "openat", 3: "mkdirat", 4: "newfstatat", 5: "renameat2", 6: "close"}
    for event, ack in zip(effects, receipt["events"]):
        assert event["name"] == names[ack["kind"]]
        error_number = getattr(errno, event["errno"]) if event["errno"] else 0
        assert error_number == ack["errno"]
        assert ack["raw_result"] == (-error_number if error_number else event["return"])
        if ack["kind"] == 4 and not error_number:
            assert stat_mode(event["args"][2]) == ack["stat_mode"]
        by_case[ack["case_id"]].append(event)
    outcomes = {row["case_id"]: row for row in rows}
    calls = []
    for case in cases:
        row = outcomes[case["case_id"]]
        projection = {"status": row["status"], "errno_present": 1 if row["errno"] else 0, "errno": row["errno"],
                      "created_tag": row["created_any"] + 1 if row["status"] == 0 and row["operation"] == 1 else 0}
        result = strict.operation_trace(by_case[case["case_id"]], case, projection)
        calls.append({"case_id": case["case_id"], **{key: value for key, value in result.items() if key != "actions"}})
    return {"raw_lines": len(text.splitlines()), "actual_semantic_syscalls": len(effects), "calls": calls}

def comparable_calls(calls, case, fixture_home, cross_root):
    owner = os.fsencode(Path(fixture_home).parent)
    cross = os.fsencode(cross_root)
    roots = [(owner, b"/@fixture-owner"), (cross, b"/@cross-owner")]
    def path(raw):
        for old, new in roots:
            if raw == old or raw.startswith(old + b"/"):
                return new + raw[len(old):]
        return raw
    parts = [match.group() for raw in (case["first"], case["second"]) for match in re.finditer(rb"[^/]+", raw)]
    result = []
    excluded = {"return", "normalized_return", "trace_line", "parent_fd", "source_fd", "destination_fd", "fd",
                "path_bytes", "path_sha256", "path_hex", "component_hex", "component_bytes", "component_sha256", "stat_display"}
    for call in calls:
        row = {key: value for key, value in call.items() if key not in excluded}
        row["normalized_return"] = call["normalized_return"]
        if call["name"] == "openat" and call["return"] >= 0:
            row["normalized_return"] = {"opened_logical_fd": call["opened_logical_fd"]}
        for key in ("parent_path_hex", "source_parent_hex", "destination_parent_hex", "source_hex", "destination_hex"):
            if key in row and row[key] is not None:
                row[key] = path(bytes.fromhex(row[key])).hex()
        component = None
        if "component_bytes" in call:
            if call["display_truncated"]:
                candidates = [part for part in parts if len(part) == call["component_bytes"] and hashlib.sha256(part).hexdigest() == call["component_sha256"]]
                assert candidates and all(part == candidates[0] for part in candidates)
                component = candidates[0]
            else:
                component = bytes.fromhex(call["component_hex"])
            canonical_component = component
            for old, new in roots:
                if call.get("parent_path_hex") == os.path.dirname(old).hex() and component == os.path.basename(old):
                    canonical_component = os.path.basename(new)
            row["component_bytes"] = len(canonical_component)
            row["component_sha256"] = hashlib.sha256(canonical_component).hexdigest()
        if "path_hex" in call:
            if call["path_hex"] is not None:
                complete = bytes.fromhex(call["path_hex"])
            else:
                assert component is not None and call["parent_path_hex"] is not None
                complete = bytes.fromhex(call["parent_path_hex"]).rstrip(b"/") + b"/" + component
                assert len(complete) == call["path_bytes"] and hashlib.sha256(complete).hexdigest() == call["path_sha256"]
            complete = path(complete)
            row["path_bytes"] = len(complete)
            row["path_sha256"] = hashlib.sha256(complete).hexdigest()
        if call["name"] == "newfstatat" and call["return"] == 0:
            row["stat_mode"] = stat_mode(call["stat_display"])
        result.append(row)
    return result
