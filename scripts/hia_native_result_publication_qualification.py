"""Check complete native publication captures without executing replacement logic.

The component's byte domain, private-control tests, kernel writes and actual MCP
integration remain distinct evidence. Original Rust comparison is a later gate.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import stat
import struct
import sys

from hia_native_build import ABI, HEPTA_COMMIT
from hia_native_loader import NativeModule

FOLDER = "result-publication"
SUITE = "test_result_publication.py"
EVIDENCE_SUITE = "test_result_publication_evidence.py"
WINDOW = 65536
MAXIMUM = (1 << 64) - 1
INVALID, CAPACITY, STATE, GROW, RESOURCE = (0xffffffff, 0xfffffffe, 0xfffffffd, 0xffffffd0, 0xfffffffc)
COUNTS = {
    "actual_elf_processes": 11, "capacity_refusals": 16, "driver_mapping_relocations": 60,
    "elf_owner_frames": 23, "growth_requests": 60, "invalid_refusals": 69,
    "kernel_allocation_failures": 1, "native_calls": 32183, "other_refusals": 0,
    "partial_acknowledgements": 23, "private_counter_fault_cases": 6,
    "repeated_pulls": 25, "semantic_cases": 90, "semantic_output_bytes": 88906008,
    "sessions": 146, "state_refusals": 48, "successful_calls": 31990,
}
KERNEL_COUNTS = {"kernel_write_receipts", "kernel_partial_writes", "kernel_eagain"}
PUBLISHER_CASES = (87, 89, 3, 20, 0)
PUBLISHER_NAMES = tuple(f"original-case-{i:04d}" for i in PUBLISHER_CASES)
REFUSED_NAMES = ("early-eof", "unfinished-utf8-seal", "illegal-lifecycle-command")
BROKEN_NAMES = ("broken-pipe-0", "broken-pipe-1")
OWNER_NAME = "resource-failure-retry-lifecycle"
PROCESS_NAMES = PUBLISHER_NAMES + REFUSED_NAMES + BROKEN_NAMES + (OWNER_NAME,)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(actual, expected, message):
    # Unlike Python equality, this distinguishes bool, int and float receipts.
    try:
        left = json.dumps(actual, sort_keys=True, separators=(",", ":"), allow_nan=False)
        right = json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(message) from exc
    require(left == right, message)


def integer(value, minimum=0, maximum=MAXIMUM):
    require(type(value) is int and minimum <= value <= maximum, "invalid integer receipt")
    return value


def finite(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            "invalid elapsed time")


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate evidence field")
            value[key] = item
        return value
    def invalid_constant(value):
        raise ValueError("non-finite evidence number: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def owned(root, relative):
    require(type(relative) is str, "evidence path is not text")
    path = Path(relative)
    require(relative and not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == relative, "evidence path is not owned and relative")
    result = root / path
    require(result.resolve() == result.absolute() and stat.S_ISREG(result.lstat().st_mode),
            "evidence is not a regular unsymlinked file")
    return result


class Artifacts:
    def __init__(self, output):
        self.output = output
        self.hashes = {}

    def read(self, relative):
        raw = owned(self.output, relative).read_bytes()
        self.hashes[relative] = sha(raw)
        return raw

    def object(self, relative):
        return decode(self.read(relative))

    def plain(self, relative):
        return gzip.decompress(self.read(relative))


def completed_suite(root, output, report, name, completed):
    rows = [row for row in report["checks"] if row.get("name") == name]
    require(len(rows) == 1, "publication suite process missing or duplicated")
    check = rows[0]
    exact(check.get("command"), [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name)],
          "publication suite command differs")
    exact([check.get("exit_code"), check.get("timed_out"), check.get("timeout_seconds")],
          [0, False, 180], "publication suite did not finish under its fixed deadline")
    require(not check.get("start_error"), "publication suite did not start")
    finite(check.get("elapsed_seconds"))
    require(0 < check["elapsed_seconds"] < 180, "publication suite exceeded its fixed deadline")
    for suffix in ("stdout", "stderr"):
        raw = owned(output, name + "." + suffix).read_bytes()
        exact([check.get(suffix + "_bytes"), check.get(suffix + "_sha256")],
              [len(raw), sha(raw)], "publication suite raw stream differs")
    return completed(output, report, name)


def corpus_files():
    names = {"actual-native-calls.bin.gz", "events.jsonl.gz", "semantic-cases.jsonl", "publisher-cases.jsonl"}
    for cid in range(90):
        names.update((f"semantic/{cid:04d}.input.bin.gz", f"semantic/{cid:04d}.native-output.bin.gz"))
    for name in PUBLISHER_NAMES:
        names.add(f"publisher/{name}.input.bin.gz")
    for name in PROCESS_NAMES:
        names.add(f"elf/{name}.json")
        names.update(f"elf/{name}.{suffix}.bin.gz" for suffix in ("input", "stdout", "stderr"))
    require(len(names) == 233, "publication corpus inventory changed")
    return names


def cases_at(root):
    path = root / "tests/hia_native/result_publication_oracle/cases.py"
    spec = importlib.util.spec_from_file_location("_publication_qualification_inputs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = list(module.iter_cases())
    exact([row["case_id"] for row in cases], list(range(90)), "original input generator domain differs")
    return module, cases


def json_lines(raw):
    require(raw.endswith(b"\n"), "incomplete evidence line stream")
    return [decode(line) for line in raw.splitlines()]


def request(raw):
    require(len(raw) >= 64 and raw[:8] == b"HRPQ0001", "native request frame differs")
    values = struct.unpack_from("<7Q", raw, 8)
    op, gen, seq, a, b, size, reserved = values
    require(size == len(raw) - 64 and reserved == 0, "native request extent differs")
    return op, gen, seq, a, b, raw[64:]


def response(raw):
    require(len(raw) >= 64 and raw[:8] == b"HRPR0001", "native response frame differs")
    status, gen, phase, a, b, confirmed, flags = struct.unpack_from("<7Q", raw, 8)
    require(status == 0 and phase <= 5 and flags <= 3 and bool(flags & 1) == bool(confirmed),
            "native response state differs")
    return dict(generation=gen, phase=phase, a=a, b=b, confirmed=confirmed, flags=flags, payload=raw[64:])


def _semantic_call(state, wire, actual):
    op, gen, seq, a, b, payload = request(wire)
    result = response(actual)
    require(op in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13), "unexpected original semantic operation")
    require(result["generation"] == 1 and gen == (0 if op == 1 else 1), "semantic generation differs")
    if op == 1:
        require(seq == 0 and a in (0, 1, 2, 3) and b in (0, 1) and not payload,
                "semantic CREATE used invalid or reserved input fields")
    elif op == 10:
        require(not payload, "semantic ACK carried an input payload")
    else:
        require(seq == a == b == 0 and (op in (2, 5, 13) or not payload),
                "semantic operation used reserved input fields")
    if op == 1:
        require(not state["created"], "semantic object created twice")
        state.update(created=True, mode=a, is_error=bool(b), phase=1, base_sealed=False, hint_open=False)
    elif op == 2:
        require(state.get("phase") == 1 and not state["base_sealed"], "base append occurred after sealing")
        state["base"].extend(payload)
    elif op == 13:
        require(state.get("phase") == 1 and state["mode"] == 3 and not state["base_sealed"],
                "prefix append occurred outside private construction")
        state["prefix"].extend(payload)
    elif op == 3:
        require(state.get("phase") == 1 and not state["base_sealed"], "base sealed twice or out of order")
        state["base_sealed"] = True
    elif op == 4:
        require(state.get("phase") == 1 and state["base_sealed"] and not state["hint_open"],
                "hint began outside its construction phase")
        state["hints"].append(bytearray())
        state["hint_open"] = True
    elif op == 5:
        require(state.get("phase") == 1 and state["hint_open"], "hint data without an open hint")
        state["hints"][-1].extend(payload)
    elif op == 6:
        require(state.get("phase") == 1 and state["hint_open"], "hint sealed without an open record")
        state["hint_open"] = False
    elif op == 7:
        require(state.get("phase") == 1 and state["base_sealed"] and not state["hint_open"],
                "result sealed with incomplete construction")
        state["phase"] = 2
    elif op == 8:
        require(state.get("phase") == 2, "publisher started before complete sealing")
        state["phase"] = 3
    elif op == 9:
        require(state.get("phase") in (3, 4) and not state["pending"] and result["b"] == 0,
                "semantic PULL lost an unacknowledged window")
        state["pending"] = result["payload"]
        state["sequence"] = result["a"]
        if not result["payload"]:
            require(result["phase"] == 4, "semantic empty PULL is not completed")
            state["finished"] = True
        state["phase"] = result["phase"]
    elif op == 10:
        require(seq == state["sequence"] and a == 0 and b == len(state["pending"]) and b > 0,
                "semantic ACK does not confirm the exact native window")
        state["output"].extend(state["pending"])
        state["pending"] = b""
        require(result["phase"] in (3, 4), "semantic ACK ended outside publication")
        state["phase"] = result["phase"]
    elif op == 12:
        require(state["finished"] and result["phase"] == 5, "semantic object retired before publication completion")
        state["dropped"] = True
        state["phase"] = 5
    require(result["phase"] == state["phase"], "semantic native phase differs from the actual operation order")
    require(result["confirmed"] == len(state["output"]), "semantic confirmed bytes differ")
    if op != 9:
        require(not result["payload"], "unexpected payload on a state response")


def _native_calls(reader, summary, events, cases, logical):
    creates = [row for row in events if row.get("kind") == "direct_arena_create"]
    closes = [row for row in events if row.get("kind") == "direct_arena_close"]
    exact([row.get("session") for row in creates], list(range(1, 147)), "private arena inventory differs")
    exact(sorted(row.get("session") for row in closes), list(range(1, 147)), "private arena cleanup inventory differs")
    exact([row.get("case_id") for row in events if row.get("kind") == "semantic_begin"], list(range(90)),
          "semantic start inventory differs")
    exact([row.get("case_id") for row in events if row.get("kind") == "semantic_complete"], list(range(90)),
          "semantic completion inventory differs")
    relocations = [row for row in events if row.get("kind") == "direct_driver_relocation"]
    require(len(relocations) == 60, "native relocation observations differ")
    for row in relocations:
        require(integer(row.get("capacity")) > integer(row.get("previous"))
                and row["capacity"] >= integer(row.get("required"))
                and integer(row.get("growth_sequence"), 1) > 0, "invalid native relocation observation")
    for row in creates + closes:
        integer(row.get("after_native_call"), 0, COUNTS["native_calls"])
    lifetimes = {row["session"]: (row["after_native_call"],
                  next(end["after_native_call"] for end in closes if end["session"] == row["session"]))
                 for row in creates}
    workspaces = {row["session"]: integer(row.get("workspace_capacity"), 0, 32 << 20) for row in creates}
    output_limits = {row["session"]: integer(row.get("output_capacity"), 0, 8 << 20) for row in creates}
    require(all(begin < end for begin, end in lifetimes.values()), "private arena had no live call interval")
    seen_sessions, relocation_at = set(), 0
    retries, growth_sequences = {}, {}
    states = {i + 1: dict(created=False, base=bytearray(), prefix=bytearray(), hints=[], output=bytearray(),
                         pending=b"", sequence=0, finished=False, dropped=False) for i in range(90)}
    totals = dict(native_calls=0, successful_calls=0, invalid_refusals=0, capacity_refusals=0,
                  state_refusals=0, growth_requests=0, other_refusals=0)
    raw = reader.read(FOLDER + "/actual-native-calls.bin.gz")
    growth_pending = {}
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        while header := stream.read(56):
            require(len(header) == 56, "incomplete native call header")
            ordinal, sid, workspace, capacity, insize, code, outsize = struct.unpack("<7Q", header)
            totals["native_calls"] += 1
            require(ordinal == totals["native_calls"] and 1 <= sid <= 146 and code <= 0xffffffff,
                    "native call identity or ordering differs")
            require(insize <= 8 << 20 and outsize <= capacity <= 8 << 20 and workspace <= 32 << 20,
                    "native call profile differs")
            begin, end = lifetimes[sid]
            require(begin < ordinal <= end and capacity <= output_limits[sid],
                    "native call occurred outside its private arena lifetime or mapping")
            seen_sessions.add(sid)
            wire, actual = stream.read(insize), stream.read(outsize)
            require(len(wire) == insize and len(actual) == outsize, "incomplete native call bytes")
            if sid in retries:
                previous_wire, next_capacity = retries[sid]
                if workspace == next_capacity:
                    require(wire == previous_wire, "native growth retry changed its complete input")
                    workspaces[sid] = next_capacity
                    del retries[sid]
                else:
                    require(workspace == workspaces[sid] and code in (INVALID, CAPACITY, STATE),
                            "native growth continuation lost its retained object or mapping")
            require(workspace == workspaces[sid], "native mapping changed without a growth continuation")
            label = {INVALID: "invalid_refusals", CAPACITY: "capacity_refusals", STATE: "state_refusals",
                     GROW: "growth_requests"}.get(code)
            if label:
                totals[label] += 1
                require(not actual, "native refusal or growth published output")
                if code == GROW:
                    require(sid not in retries and relocation_at < len(relocations),
                            "native growth lacks a unique mapping observation")
                    relocation = relocations[relocation_at]
                    exact([relocation.get("session"), relocation.get("previous"), relocation.get("growth_sequence")],
                          [sid, workspace, growth_sequences.get(sid, 0) + 1],
                          "native growth and actual driver relocation differ")
                    growth_sequences[sid] = relocation["growth_sequence"]
                    next_capacity = integer(relocation["capacity"], workspace + 1, 32 << 20)
                    retries[sid] = (wire, next_capacity)
                    relocation_at += 1
            else:
                require(code < 0xffff0000 and code == outsize, "unknown native return or output length")
                totals["successful_calls"] += 1
                response(actual)
            if sid in states:
                if code == GROW:
                    require(sid not in growth_pending, "semantic growth was not retried")
                    growth_pending[sid] = (wire, workspace)
                else:
                    require(code < 0xffff0000, "semantic corpus includes a native-only refusal")
                    if sid in growth_pending:
                        previous_wire, previous_capacity = growth_pending.pop(sid)
                        require(wire == previous_wire and workspace > previous_capacity,
                                "semantic growth retry changed its input or mapping")
                    _semantic_call(states[sid], wire, actual)
    require(not growth_pending and not retries and relocation_at == len(relocations),
            "incomplete native growth continuation")
    exact(sorted(seen_sessions), list(range(1, 147)), "private arena inventory includes unexecuted sessions")
    exact(totals, {key: COUNTS[key] for key in totals}, "complete native-call counts differ")
    semantic_rows = json_lines(reader.read(FOLDER + "/semantic-cases.jsonl"))
    exact([row.get("case_id") for row in semantic_rows], list(range(90)), "semantic file inventory differs")
    for cid, (case, row) in enumerate(zip(cases, semantic_rows, strict=True)):
        state = states[cid + 1]
        require(state["created"] and state["finished"] and state["dropped"] and not state["pending"],
                "semantic lifecycle did not complete")
        require(bytes(state["base"]) == case["base"] and bytes(state["prefix"]) == case["prefix"]
                and [bytes(x) for x in state["hints"]] == case["hints"]
                and state["mode"] == case["mode"] and state["is_error"] is case["is_error"],
                "actual native construction differs from complete original input")
        inp = f"semantic/{cid:04d}.input.bin.gz"
        out = f"semantic/{cid:04d}.native-output.bin.gz"
        expected_input = logical.encode_cases([case])
        captured_input = reader.plain(FOLDER + "/" + inp)
        captured_output = reader.plain(FOLDER + "/" + out)
        require(captured_input == expected_input and captured_output == bytes(state["output"]),
                "semantic captures differ from actual construction/PULL/ACK bytes")
        exact(row, dict(case_id=cid, name=case["name"], mode=case["mode"], is_error=case["is_error"],
              prefix_bytes=len(case["prefix"]), base_bytes=len(case["base"]), hint_count=len(case["hints"]),
              input_path=inp, input_bytes=len(captured_input), input_sha256=sha(captured_input),
              output_path=out, output_bytes=len(captured_output), output_sha256=sha(captured_output)),
              "semantic complete-byte receipt differs")
    return totals


def _frames(raw):
    stream = io.BytesIO(raw)
    values = []
    while word := stream.read(8):
        require(len(word) == 8, "incomplete fixture input length")
        size = struct.unpack("<Q", word)[0]
        require(64 <= size <= WINDOW + 64, "fixture per-call input differs")
        wire = stream.read(size)
        require(len(wire) == size, "incomplete fixture input")
        request(wire)
        values.append(wire)
    return values


def _construction(frames, case):
    base, prefix, hints = bytearray(), bytearray(), []
    operations = []
    for wire in frames:
        op, gen, seq, a, b, payload = request(wire)
        operations.append(op)
        require(seq == 0 and gen == (0 if op == 1 else 1), "publisher construction identity differs")
        if op == 1:
            exact([a, b], [case["mode"], int(case["is_error"])], "publisher output format differs")
        elif op == 2:
            base.extend(payload)
        elif op == 13:
            prefix.extend(payload)
        elif op == 4:
            hints.append(bytearray())
        elif op == 5:
            require(hints, "publisher hint without a record")
            hints[-1].extend(payload)
        else:
            require(op in (3, 6, 7), "publisher input contains a lifecycle or output authority operation")
    require(operations[0] == 1 and operations[-1] == 7 and operations.count(1) == 1
            and operations.count(3) == 1 and operations.count(7) == 1
            and operations.count(4) == operations.count(6) == len(case["hints"]),
            "publisher input construction phases differ")
    require(bytes(base) == case["base"] and bytes(prefix) == case["prefix"]
            and [bytes(x) for x in hints] == case["hints"], "publisher construction changed original bytes")


def _receipts(raw, expected_bytes, broken=False):
    require(len(raw) % 64 == 0, "incomplete kernel write receipt")
    counts = dict(kernel_write_receipts=0, kernel_partial_writes=0, kernel_eagain=0)
    confirmed, sequence, offset, window_end = 0, None, 0, 0
    for at in range(0, len(raw), 64):
        rec = raw[at:at + 64]
        require(rec[:8] == b"HRPWACK1", "kernel write receipt magic differs")
        gen, seq, off, wanted, returned, after, ack = struct.unpack_from("<7Q", rec, 8)
        signed = returned if returned < 1 << 63 else returned - (1 << 64)
        require(gen == 1 and seq > 0 and 0 < wanted <= WINDOW, "kernel write identity differs")
        if sequence is None:
            require(seq == 1 and off == 0, "kernel publication did not start at its first window")
            window_end = wanted
        elif seq == sequence:
            require(off == offset and offset < window_end and off + wanted == window_end,
                    "kernel write changed or reused its outstanding window")
        else:
            require(seq == sequence + 1 and off == 0 and offset == window_end,
                    "kernel advanced before acknowledging its complete previous window")
            window_end = wanted
        sequence = seq
        counts["kernel_write_receipts"] += 1
        if signed > 0:
            require(not broken and signed <= wanted and ack == 64, "kernel write/ACK result differs")
            confirmed += signed
            offset = off + signed
            counts["kernel_partial_writes"] += int(signed < wanted)
        else:
            require(ack == MAXIMUM and signed in ((-32,) if broken else (-4, -11)),
                    "unexpected kernel write failure or acknowledgement")
            offset = off
            counts["kernel_eagain"] += int(signed == -11)
        require(after == confirmed, "kernel acknowledged byte count differs")
    require(confirmed == expected_bytes, "kernel confirmations do not cover the exact stdout")
    if broken:
        require(len(raw) == 64 and confirmed == 0, "broken pipe result differs")
    else:
        require(offset == window_end, "publisher exited with a partially acknowledged window")
    return counts


def _control_frame(op, gen=1, seq=0, a=0, b=0, payload=b""):
    return b"HRPQ0001" + struct.pack("<7Q", op, gen, seq, a, b, len(payload), 0) + payload


def _failure_construction(name, frames):
    control = _control_frame
    if name == "early-eof":
        expected = [control(1, 0), control(2, payload=b"private-unsealed")]
    elif name == "unfinished-utf8-seal":
        expected = [control(1, 0), control(2, payload=b"\xf0\x9f"), control(3)]
    elif name == "illegal-lifecycle-command":
        expected = [control(1, 0), control(2, payload=b"sealed-private"), control(3), control(7), control(10)]
    else:
        require(name in BROKEN_NAMES, "unknown failure construction control")
        expected = [control(1, 0), control(2, payload=b"committed-tool-result"), control(3), control(7)]
    require(frames == expected, "publisher failure control input differs")


def _owner_trace(frames, raw_stdout):
    expected_ops = [1, 2, 2, 2, 2, 3, 7, 8, 9, 10, 11, 10, 1, 10, 2, 3, 7, 8, 9, 10, 9, 12, 12]
    exact([request(w)[0] for w in frames], expected_ops, "actual native allocation/lifecycle controls differ")
    control = _control_frame
    expected_frames = [control(1, 0), control(2, payload=b"owned-prefix"),
        control(2, payload=b"G" * 60000), control(2, payload=b"+"), control(2, payload=b"G" * 60000),
        control(3), control(7), control(8), control(9), control(10, seq=1, b=2), control(11),
        control(10, seq=1, a=2, b=1), control(1, 0), control(10, seq=1, a=2, b=1),
        control(2, 2, payload=b"new"), control(3, 2), control(7, 2), control(8, 2), control(9, 2),
        control(10, 2, seq=1, b=3), control(9, 2), control(12, 2), control(12, 2)]
    require(frames == expected_frames,
            "allocation retry, cancellation or retired-generation control bytes differ")
    expected_codes = [64, 64, RESOURCE, 64, 64, 64, 64, 64, 60077, 64, 64, STATE,
                      64, STATE, 64, 64, 64, 64, 67, 64, 64, 64, STATE]
    stream = io.BytesIO(raw_stdout)
    results = []
    for code in expected_codes:
        header = stream.read(16)
        require(len(header) == 16, "incomplete native owner result")
        actual_code, size = struct.unpack("<QQ", header)
        require(actual_code == code and size == (code if code < 0xffff0000 else 0),
                "native allocation/late-ACK refusal differs")
        raw = stream.read(size)
        require(len(raw) == size, "incomplete native owner output")
        results.append(response(raw) if raw else None)
    require(not stream.read(1), "extra native owner output")
    expected_states = [(1, 1, 0, 0, 0, 0), (1, 1, 12, 0, 0, 0), None,
        (1, 1, 13, 0, 0, 0), (1, 1, 60013, 0, 0, 0), (1, 1, 60013, 0, 0, 0),
        (1, 2, 60013, 0, 0, 0), (1, 3, 60013, 0, 0, 2), (1, 3, 1, 0, 0, 2),
        (1, 3, 60013, 0, 2, 3), (1, 5, 0, 0, 2, 3), None, (2, 1, 0, 0, 0, 0), None,
        (2, 1, 3, 0, 0, 0), (2, 1, 3, 0, 0, 0), (2, 2, 3, 0, 0, 0),
        (2, 3, 3, 0, 0, 2), (2, 3, 1, 0, 0, 2), (2, 4, 3, 0, 3, 3),
        (2, 4, 1, 0, 3, 3), (2, 5, 0, 0, 3, 3), None]
    for position, (result, expected) in enumerate(zip(results, expected_states, strict=True)):
        if expected is None:
            require(result is None, "refused owner control published state")
            continue
        payload = b"owned-prefix+" + b"G" * 60000 if position == 8 else b"new" if position == 18 else b""
        require(tuple(result[key] for key in ("generation", "phase", "a", "b", "confirmed", "flags")) == expected
                and result["payload"] == payload, "native owner control response differs")
    require(results[3]["a"] == 13 and results[8]["payload"] == b"owned-prefix+" + b"G" * 60000
            and results[10]["phase"] == 5 and results[10]["confirmed"] == 2
            and results[12]["generation"] == 2 and results[18]["payload"] == b"new"
            and results[20]["phase"] == 4, "actual resource retry/cancel/reuse bytes differ")


def _processes(reader, origin, elf_relative, elf_hash, cases, logical):
    counts = dict(kernel_write_receipts=0, kernel_partial_writes=0, kernel_eagain=0)
    outputs = {}
    for name in PROCESS_NAMES:
        meta = reader.object(f"{FOLDER}/elf/{name}.json")
        owner = name == OWNER_NAME
        exact([meta.get("schema"), meta.get("name"), meta.get("command"), meta.get("elf_sha256"),
               meta.get("timed_out"), meta.get("error")],
              ["hepta.runtime.result-publication-elf-process.v1", name,
               [str(origin / elf_relative), "--owner-fixture" if owner else "--publish-fixture"],
               elf_hash, False, None], "actual native process identity or completion differs")
        streams = {}
        for key, suffix in (("stdin", "input"), ("stdout", "stdout"), ("stderr", "stderr")):
            relative = f"elf/{name}.{suffix}.bin.gz"
            raw = reader.plain(FOLDER + "/" + relative)
            exact(meta.get(key), dict(file=relative, bytes=len(raw), sha256=sha(raw)),
                  "complete native process stream differs")
            streams[key] = raw
        frames = _frames(streams["stdin"])
        if owner:
            exact([meta.get("returncode"), meta.get("timeout_seconds"), meta.get("timeout_scope"),
                   meta.get("teardown_timeout_seconds"), meta.get("mode")],
                  [0, 20, "each-stream-io", 5, "owner-fixture"], "native lifecycle process contract differs")
            require(not streams["stderr"], "native owner emitted unexpected stderr")
            _owner_trace(frames, streams["stdout"])
            continue
        exact([meta.get("timeout_scope"), meta.get("timeout_seconds")],
              ["whole-process", 120 if name in PUBLISHER_NAMES else 60], "publisher deadline differs")
        require(type(meta.get("before_flags")) is int and type(meta.get("after_flags")) is int
                and meta["after_flags"] == meta["before_flags"],
                "publisher changed its inherited shared descriptor flags")
        nonblocking = name in ("original-case-0087", "original-case-0089", "broken-pipe-1")
        broken = name in BROKEN_NAMES
        flags = integer(meta["before_flags"])
        require(flags & 3 == 1 and bool(flags & 2048) is nonblocking,
                "actual inherited pipe mode differs from the recorded setup")
        exact([meta.get("parent_set_nonblocking"), meta.get("broken_pipe")], [nonblocking, broken],
              "actual pipe setup differs")
        exact(meta.get("returncode"), 0 if name in PUBLISHER_NAMES else (74 if broken else 2),
              "publisher exit differs")
        if name in PUBLISHER_NAMES:
            cid = int(name[-4:])
            _construction(frames, cases[cid])
            outputs[name] = streams["stdout"]
            require(streams["stdout"] == reader.plain(f"{FOLDER}/semantic/{cid:04d}.native-output.bin.gz"),
                    "actual publisher bytes differ from its complete native semantic result")
            observed = _receipts(streams["stderr"], len(streams["stdout"]))
            if cid == 87:
                require(observed["kernel_partial_writes"] > 0 and observed["kernel_eagain"] > 0,
                        "actual kernel backpressure was not exercised")
            if cid == 0:
                require(not streams["stdout"] and not streams["stderr"], "empty publication emitted bytes")
        elif broken:
            _failure_construction(name, frames)
            require(not streams["stdout"], "broken pipe published captured output")
            observed = _receipts(streams["stderr"], 0, broken=True)
        else:
            _failure_construction(name, frames)
            require(not streams["stdout"] and not streams["stderr"], "unsealed/invalid result reached publication")
            observed = dict.fromkeys(KERNEL_COUNTS, 0)
        for key in counts:
            counts[key] += observed[key]
    rows = json_lines(reader.read(FOLDER + "/publisher-cases.jsonl"))
    exact([row.get("case_id") for row in rows], list(PUBLISHER_CASES), "actual publisher case domain differs")
    for row, cid, name in zip(rows, PUBLISHER_CASES, PUBLISHER_NAMES, strict=True):
        case = cases[cid]
        relative = f"publisher/{name}.input.bin.gz"
        raw = reader.plain(FOLDER + "/" + relative)
        require(raw == logical.encode_cases([case]), "publisher logical input differs")
        output = outputs[name]
        exact(row, dict(case_id=cid, run_id=name, mode=case["mode"], is_error=case["is_error"],
              input_path=relative, input_bytes=len(raw), input_sha256=sha(raw),
              output_path=f"elf/{name}.stdout.bin.gz", output_bytes=len(output), output_sha256=sha(output)),
              "actual publisher full-output receipt differs")
    require(sum(map(len, outputs.values())) == 25543155, "actual publisher byte domain differs")
    return counts


def native_evidence(root, output, report, completed):
    root, output = Path(root).resolve(), Path(output).resolve()
    reader = Artifacts(output)
    entry = report["modules"]["result_publication"]
    require(entry.get("builder") == "result_publication", "publication builder differs")
    bundle = reader.object(entry["manifest"])
    exact(reader.hashes[entry["manifest"]], entry["sha256"], "publication bundle differs")
    exact({k: bundle.get(k) for k in ("schema", "compiler_commit", "compiler_sha256", "initial_arena_bytes",
          "output_window_bytes", "fixed_total_result_limit", "fixture_argv", "production_config_route_replaced",
          "filesystem_callers_replaced", "whole_runtime_replaced")},
          dict(schema="hepta.runtime.result-publication.v1", compiler_commit=HEPTA_COMMIT,
               compiler_sha256=report["compiler_image_sha256"], initial_arena_bytes=131072,
               output_window_bytes=WINDOW, fixed_total_result_limit=None,
               fixture_argv=["--owner-fixture", "--publish-fixture"], production_config_route_replaced=False,
               filesystem_callers_replaced=False, whole_runtime_replaced=False), "publication profile or scope differs")
    build_relative = Path(entry["manifest"]).parent.parent
    modules = {}
    for key, source in (("owner", "native/result_publication.hepta"), ("packer", "native/result_publication_packer.hepta")):
        relative = (build_relative / bundle[key + "_manifest"]).as_posix()
        meta = reader.object(relative)
        exact(reader.hashes[relative], bundle[key + "_manifest_sha256"], "publication member manifest differs")
        exact({k: meta.get(k) for k in ("abi", "compiler_commit", "compiler_sha256", "source_sha256",
              "input_capacity", "output_capacity", "workspace_capacity", "standalone")},
              dict(abi=ABI, compiler_commit=HEPTA_COMMIT, compiler_sha256=report["compiler_image_sha256"],
                   source_sha256=sha((root / source).read_bytes()), input_capacity=8 << 20,
                   output_capacity=8 << 20, workspace_capacity=32 << 20, standalone=None),
              "publication member source/compiler/profile differs")
        with NativeModule(owned(output, relative), manifest_sha256=sha(reader.read(relative))):
            pass
        contents = {}
        for field in ("source", "image"):
            contents[field] = reader.read((Path(relative).parent / meta[field]).as_posix())
            exact(sha(contents[field]), meta[field + "_sha256"], "publication member bytes differ")
        require(contents["source"] == (root / source).read_bytes(), "publication source bytes changed")
        modules[key] = dict(relative=relative, meta=meta, contents=contents)
    folder = Path(entry["manifest"]).parent
    elf_relative = (folder / bundle["elf"]).as_posix()
    elf = reader.read(elf_relative)
    layout = decode((root / "native/result_publication_layout.json").read_bytes())
    offset = integer(bundle["image_offset"], 176, len(elf))
    exact(offset, layout["image_offset"], "publication image offset differs")
    require(elf[:8] == b"\x7fELF\x02\x01\x01\x00" and struct.unpack_from("<HH", elf, 16) == (2, 62)
            and struct.unpack_from("<QQ", elf, 96) == (len(elf), len(elf)), "publication static ELF envelope differs")
    require(elf[offset:] == modules["owner"]["contents"]["image"], "actual ELF embeds a different owner")
    adapter = reader.read((folder / "adapter.bin").as_posix())
    require(adapter[-1:] == b"\0" and elf[176:offset] == adapter[:-1], "actual adapter bytes differ")
    exact([sha(elf), modules["owner"]["meta"]["source_sha256"], modules["owner"]["meta"]["image_sha256"],
           sha((root / "scripts/result_publication_adapter.S").read_bytes())],
          [bundle["elf_sha256"], bundle["owner_source_sha256"], bundle["owner_image_sha256"],
           bundle["adapter_source_sha256"]], "actual publication source/image/ELF binding differs")
    _, summary = completed_suite(root, output, report, SUITE, completed)
    stored = reader.object(FOLDER + "/native-result.json")
    exact({k: v for k, v in stored.items() if k != "files"}, summary,
          "stored publication result differs from the actual process stdout")
    exact({k: summary.get(k) for k in ("schema", "status", "tests_run", "expected_test_groups", "failures", "errors",
          "skipped", "expected_elf_process_count", "original_semantic_case_count", "identities_unchanged_during_run",
          "actual_static_publication_exercised", "native_allocation_failure_exercised", "original_rust_replay",
          "production_scheduler_replaced", "whole_runtime_replaced")},
          dict(schema="hepta.runtime.result-publication-native-test.v1", status="PASS", tests_run=11,
               expected_test_groups=11, failures=[], errors=[], skipped=0, expected_elf_process_count=11,
               original_semantic_case_count=90, identities_unchanged_during_run=True,
               actual_static_publication_exercised=True, native_allocation_failure_exercised=True,
               original_rust_replay=False, production_scheduler_replaced=False, whole_runtime_replaced=False),
          "publication suite is incomplete or overstates its scope")
    finite(summary.get("elapsed_seconds"))
    counts = summary.get("counts", {})
    exact(sorted(counts), sorted(set(COUNTS) | KERNEL_COUNTS), "publication counter fields differ")
    exact({key: counts[key] for key in COUNTS}, COUNTS, "publication finite test domain differs")
    for key in KERNEL_COUNTS:
        integer(counts[key])
    identities = summary["identities"]
    recorded_manifest = identities["fixture_manifest"]["path"]
    suffix = "/" + entry["manifest"]
    require(type(recorded_manifest) is str and recorded_manifest.endswith(suffix), "recorded fixture path differs")
    origin = Path(recorded_manifest[:-len(suffix)])
    require(origin.is_absolute() and str(origin) == recorded_manifest[:-len(suffix)] and ".." not in origin.parts,
            "invalid recorded execution root")
    config_binding = None
    if "runtime_config" in report["modules"]:
        config_entry = report["modules"]["runtime_config"]
        require(config_entry.get("builder") == "runtime_config", "configuration builder differs")
        config_bundle = reader.object(config_entry["manifest"])
        exact(reader.hashes[config_entry["manifest"]], config_entry["sha256"], "configuration bundle differs")
        exact([config_bundle.get("schema"), config_bundle.get("compiler_commit"), config_bundle.get("compiler_sha256")],
              ["hepta.runtime.config-native-build.v2", HEPTA_COMMIT, report["compiler_image_sha256"]],
              "configuration publication compiler differs")
        config_relative = (build_relative / "modules/cfg-regex-publication/manifest.json").as_posix()
        config_module = reader.object(config_relative)
        exact(config_bundle["modules"]["publication"],
              dict(path=str(origin / config_relative), sha256=reader.hashes[config_relative]),
              "configuration publication member differs")
        for field in ("abi", "compiler_commit", "compiler_sha256", "source_sha256", "image_sha256",
                      "input_capacity", "output_capacity", "workspace_capacity", "standalone"):
            exact(config_module.get(field), modules["owner"]["meta"].get(field),
                  "configuration and fixture publication owners differ")
        for field in ("source", "image"):
            raw = reader.read((Path(config_relative).parent / config_module[field]).as_posix())
            require(raw == modules["owner"]["contents"][field],
                    "configuration and fixture publication bytes differ")
        config_binding = dict(bundle_sha256=config_entry["sha256"],
                              member_manifest_sha256=reader.hashes[config_relative],
                              owner_source_sha256=bundle["owner_source_sha256"],
                              owner_image_sha256=bundle["owner_image_sha256"],
                              same_owner_bytes=True, production_activated=False)
    expected_identity = {
        "fixture_manifest": (origin / entry["manifest"], entry["sha256"]),
        "fixture_elf": (origin / elf_relative, sha(elf)),
        "owner_manifest": (origin / modules["owner"]["relative"], bundle["owner_manifest_sha256"]),
        "owner_source": (root / "native/result_publication.hepta", bundle["owner_source_sha256"]),
        "test": (root / "tests/hia_native" / SUITE, sha((root / "tests/hia_native" / SUITE).read_bytes())),
        "semantic_input_generator": (root / "tests/hia_native/result_publication_oracle/cases.py",
             sha((root / "tests/hia_native/result_publication_oracle/cases.py").read_bytes())),
    }
    exact(identities, {key: dict(path=str(path), sha256=digest) for key, (path, digest) in expected_identity.items()},
          "publication execution/source identity differs")
    exact([summary.get("manifest_sha256"), summary.get("owner_source_sha256"), summary.get("test_sha256")],
          [bundle["owner_manifest_sha256"], bundle["owner_source_sha256"], expected_identity["test"][1]],
          "publication test/member identity differs")
    names = corpus_files()
    exact(sorted(stored["files"]), sorted(names), "publication artifact inventory is incomplete or contains extras")
    observed = {p.relative_to(output / FOLDER).as_posix() for p in (output / FOLDER).rglob("*") if p.is_file()}
    exact(sorted(observed), sorted(names | {"native-result.json"}), "publication artifact directory inventory differs")
    for name in sorted(names):
        raw = reader.read(FOLDER + "/" + name)
        exact(stored["files"][name], dict(bytes=len(raw), sha256=sha(raw)), "publication artifact bytes differ")
    events = json_lines(reader.plain(FOLDER + "/events.jsonl.gz"))
    for event in events:
        require(event.get("kind") in {"direct_arena_create", "direct_arena_close", "direct_driver_relocation",
                "private_counter_injection", "semantic_begin", "semantic_complete", "actual_elf_identity",
                "cancel_without_write", "actual_resource_failure", "private_counter_faults_complete"},
                "unknown publication observation")
    exact([row for row in events if row.get("kind") == "cancel_without_write"],
          [dict(kind="cancel_without_write", publisher_started=True, acknowledged_bytes=0, syscall_write_count=0)],
          "unpublished cancellation was relabelled as a kernel write")
    failures = [row for row in events if row.get("kind") == "actual_resource_failure"]
    require(len(failures) == 1, "actual allocation failure observation missing or duplicated")
    failure = failures[0]
    limit = integer(failure.get("address_space_limit"), 131072)
    require(limit % 4096 == 0, "allocation-failure address-space limit is not page aligned")
    original_limit = failure.get("original_rlimit_as")
    require(type(original_limit) is list and len(original_limit) == 2,
            "original address-space limit receipt differs")
    for value in original_limit:
        integer(value, -1)
        require(value == -1 or value >= limit, "address-space restriction did not lower the original limit")
    exact(failure,
          dict(kind="actual_resource_failure", syscall="mremap", cause="RLIMIT_AS",
               address_space_limit=limit, original_rlimit_as=original_limit, native_return=RESOURCE,
               unchanged_prior_body_observed=True, successful_same_operation_after_limit_restore=True),
          "actual allocation failure/retry observation differs")
    exact([row for row in events if row.get("kind") == "private_counter_faults_complete"],
          [dict(kind="private_counter_faults_complete", cases=6, original_rust_domain=False)],
          "private counter controls were omitted or relabelled as original semantics")
    exact([row for row in events if row.get("kind") == "actual_elf_identity"],
          [dict(kind="actual_elf_identity", elf_sha256=sha(elf),
                manifest=str(origin / entry["manifest"]), manifest_sha256=entry["sha256"],
                owner_image_sha256=bundle["owner_image_sha256"])] * 3,
          "actual process identity observations differ")
    logical, cases = cases_at(root)
    direct_counts = _native_calls(reader, summary, events, cases, logical)
    kernel_counts = _processes(reader, origin, elf_relative, sha(elf), cases, logical)
    exact(kernel_counts, {key: counts[key] for key in KERNEL_COUNTS}, "actual kernel write counters differ")
    for suffix in ("stdout", "stderr"):
        reader.read(SUITE + "." + suffix)
    return dict(schema="hepta.runtime.result-publication-evidence.v1", status="PASS",
                native_calls=COUNTS["native_calls"], semantic_cases=90, semantic_output_bytes=88906008,
                actual_elf_processes=11, actual_publisher_successes=5, publisher_stdout_bytes=25543155,
                native_only_refusals=COUNTS["invalid_refusals"] + COUNTS["capacity_refusals"] + COUNTS["state_refusals"],
                growth_requests=60, driver_mapping_relocations=60, private_counter_fault_cases=6,
                kernel_allocation_failure_cases=1, kernel_counts=kernel_counts,
                owner_source_sha256=bundle["owner_source_sha256"], owner_image_sha256=bundle["owner_image_sha256"],
                fixture_elf_sha256=sha(elf), artifact_sha256=reader.hashes,
                configuration_owner_binding=config_binding,
                original_rust_replay=False, production_scheduler_replaced=False,
                filesystem_callers_replaced=False, whole_runtime_replaced=False)


def qualification_evidence(root, output, report, completed):
    root, output = Path(root).resolve(), Path(output).resolve()
    result = native_evidence(root, output, report, completed)
    _, controls = completed_suite(root, output, report, EVIDENCE_SUITE, completed)
    expected = dict(schema="hepta.runtime.result-publication-evidence-tests.v1", status="PASS",
                    test_groups=8, expected_groups=8, controls=68, expected_controls=68,
                    skipped=0, errors=0, failures=0, expected_failures=0, unexpected_successes=0,
                    native_cases_added_by_replay=0, actual_elf_processes_added=0,
                    test_sha256=sha((root / "tests/hia_native" / EVIDENCE_SUITE).read_bytes()),
                    reader_sha256=sha((root / "scripts/hia_native_result_publication_qualification.py").read_bytes()),
                    test_unchanged_during_run=True, reader_unchanged_during_run=True,
                    baseline_native_evidence_sha256=sha((json.dumps(result, sort_keys=True, separators=(",", ":"),
                                                                  allow_nan=False) + "\n").encode()),
                    validation_kind="actual retained evidence and refusal controls; no new native execution")
    exact({key: controls.get(key) for key in expected}, expected,
          "publication evidence controls did not complete against these exact retained bytes")
    names = controls.get("control_names")
    require(type(names) is list and len(names) == 68 and all(type(name) is str and name for name in names)
            and names == sorted(set(names)), "publication evidence control inventory differs")
    result["evidence_controls"] = controls
    for suffix in ("stdout", "stderr"):
        relative = EVIDENCE_SUITE + "." + suffix
        result["artifact_sha256"][relative] = sha(owned(output, relative).read_bytes())
    return result
