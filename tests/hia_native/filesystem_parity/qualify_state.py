"""Actual HIA protocol controls, separate from real filesystem parity."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import struct
import sys
import time
import traceback
sys.dont_write_bytecode = True
INVALID, CAPACITY, STATE, EFFECT, GROW, OUTPUT_GROW = 0xffffffff, 0xfffffffe, 0xfffffff9, 0xfffffff0, 0xffffffef, 0xffffffee
WORK, MASK = 8192, (1 << 64) - 1
SMAG = int.from_bytes(b"HFSPST02", "little")
FMAG = int.from_bytes(b"HFSPFX02", "little")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def request(source=b"/a", destination=b"", operation=1, generation=0):
    return b"HFSPQ002" + struct.pack("<7Q", operation, len(source), len(destination), generation, 0, 0, 0) + source + destination

def patched(raw, changes):
    result = bytearray(raw)
    for at, value in changes:
        struct.pack_into("<Q", result, at, value)
    return bytes(result)

def ack(workspace, errno=0, mode=0):
    kind = struct.unpack_from("<Q", workspace, 536)[0]
    return patched(workspace, [(592, 1 if kind in (1, 2) and not errno else 0), (600, errno), (608, mode), (616, 1)])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.runtime / "scripts"))
    from hia_native_loader import NativeModule
    args.output.mkdir(mode=0o700)
    dump(args.output / "remote-process.json", {"pid": os.getpid(), "cgroup": Path("/proc/self/cgroup").read_text(), "argv": sys.argv})
    started = time.monotonic()
    rows, groups = [], set()
    report = {"status": "RUNNING", "original_semantic_cases": 0, "actual_filesystem_effects": 0,
              "synthetic_private_completion_controls": True, "public_filesystem_handlers_complete": False, "whole_runtime_replaced": False}
    stream = gzip.open(args.output / "calls.bin.gz", "xb", compresslevel=1)
    indices = (args.output / "calls.jsonl").open("x")

    def call(module, group, name, wire, workspace, outcap=1024, expected=None, unchanged=False):
        groups.add(group)
        output_before = b"\xa5" * outcap
        with module.session(output_capacity=outcap, workspace_capacity=len(workspace)) as session:
            if workspace:
                ctypes.memmove(session._workspace, workspace, len(workspace))
            if outcap:
                ctypes.memset(session._output, 0xa5, outcap)
            start = stream.tell()
            for raw in (wire, workspace, output_before):
                stream.write(struct.pack("<Q", len(raw)))
                stream.write(raw)
            stream.flush()
            code, output, after = session.invoke_raw(wire)
        for raw in (output, after):
            stream.write(struct.pack("<Q", len(raw)))
            stream.write(raw)
        stream.flush()
        row = {"group": group, "name": name, "native_code": code, "expected_code": expected,
               "stream_offset": start, "stream_bytes": stream.tell() - start, "input_bytes": len(wire),
               "input_sha256": sha(wire), "output_capacity": outcap, "workspace_capacity": len(workspace),
               "before_sha256": sha(workspace), "after_sha256": sha(after), "output_sha256": sha(output)}
        rows.append(row)
        indices.write(json.dumps(row, sort_keys=True) + "\n")
        indices.flush()
        if expected is not None:
            assert code == expected, (name, code, expected)
        if unchanged:
            assert output == output_before and after == workspace, (name, "rejection changed buffers")
        return code, output, after

    try:
        manifest_raw = args.manifest.read_bytes()
        assert sha(manifest_raw) == "cedc50d51c070462b90538e0cc6825c2c0191953f051178b04d175b164c91cb7"
        with NativeModule(args.manifest, manifest_sha256=sha(manifest_raw)) as module:
            assert module.metadata["source_sha256"] == "1afb3046366a16a346a21345f3710efefdd312a1f9b35878bd7aec5118ddd454"
            good = request()
            structural = [("truncated-" + str(n), good[:n]) for n in range(64)]
            structural += [("magic", b"BADMAGIC" + good[8:]), ("trailing-byte", good + b"x"),
                           ("mkdir-destination", request(b"/a", b"/b")), ("drop-source", request(b"x", operation=4)),
                           ("drop-destination", request(b"", b"x", operation=4))]
            for at, value in ((8, 0), (8, 5), (16, 0), (16, MASK), (24, 1), (32, 1), (40, 1), (48, 1), (56, 1)):
                structural.append(("field-" + str(at), patched(good, [(at, value)])))
            for name, wire in structural:
                call(module, "frame", name, wire, b"\x5a" * WORK, expected=INVALID, unchanged=True)
            for size in (0, 1, 1024, 6143):
                call(module, "capacity", "workspace-" + str(size), good, b"\x5a" * size, expected=CAPACITY, unchanged=True)
            for size in (0, 1, 79):
                call(module, "capacity", "output-" + str(size), good, bytes(WORK), outcap=size, expected=CAPACITY, unchanged=True)
            for at in range(0, 1024, 8):
                call(module, "fresh-state", "word-" + str(at), good, patched(bytes(WORK), [(at, 1)]), expected=STATE, unchanged=True)
            call(module, "fresh-state", "drop-before-run", request(b"", operation=4), bytes(WORK), expected=STATE, unchanged=True)
            _, _, pending = call(module, "pending", "root-open", good, bytes(WORK), expected=EFFECT)
            assert struct.unpack_from("<6Q", pending, 512) == (FMAG, 1, 1, 1, 1, 0x2b0000)
            assert struct.unpack_from("<Q", pending, 0)[0] == 11
            for name, wire in (("changed-path", request(b"/b")), ("changed-length", request(b"/bb")),
                               ("premature-drop", request(b"", operation=4, generation=1))):
                call(module, "pending", name, wire, pending, expected=STATE, unchanged=True)
            call(module, "pending", "missing-ACK", good, pending, expected=STATE, unchanged=True)
            completed = ack(pending)
            changes = [(0, 99), (8, len(good) + 1), (16, 1025), (24, WORK + 1), (32, 512), (40, 1),
                       (64, 0), (72, 0), (80, 4), (88, 1024), (96, 1024), (104, 1025), (120, 1025),
                       (144, 4), (152, 4), (160, 4), (168, 4), (176, 1025), (184, 1025), (240, 2),
                       (248, 17), (256, 4096), (264, 513), (272, 513), (280, 8), (288, 1),
                       (320, 2), (376, 12), (512, 0), (520, 0), (528, 2), (536, 2), (544, 2),
                       (552, 0), (560, 1), (568, 1), (576, 1), (584, 1), (592, 0), (600, 4096),
                       (608, 1), (616, 2), (624, 1), (632, 1)]
            for at, value in changes:
                call(module, "completion", "word-" + str(at), good, patched(completed, [(at, value)]), expected=STATE, unchanged=True)
            corrupted = bytearray(completed)
            corrupted[2048] ^= 1
            call(module, "completion", "changed-private-input", good, bytes(corrupted), expected=STATE, unchanged=True)
            _, body, terminal = call(module, "terminal", "root-error", good, ack(pending, errno=24), expected=80)
            values = struct.unpack_from("<9Q", body, 8)
            assert values[:5] == (1, 1, 0, 16, 24) and values[7:] == (1, 1)
            assert body[80:80 + values[5]] == body[80 + values[5]:80 + values[5] + values[6]]
            _, again, state_again = call(module, "terminal", "redelivery", good, terminal, expected=80)
            assert body == again and terminal == state_again
            for generation in (0, 2, MASK):
                call(module, "terminal", "wrong-DROP-" + str(generation), request(b"", operation=4, generation=generation), terminal, expected=STATE, unchanged=True)
            _, output, retired = call(module, "terminal", "DROP", request(b"", operation=4, generation=1), terminal, expected=80)
            assert struct.unpack_from("<9Q", output, 8) == (2, 4, 0, 0, 0, 0, 0, 1, 1)
            assert retired == patched(bytes(WORK), [(56, 1), (64, 1), (72, SMAG)])
            call(module, "terminal", "duplicate-DROP", request(b"", operation=4, generation=1), retired, expected=STATE, unchanged=True)
            _, _, reused = call(module, "terminal", "reuse", good, retired, expected=EFFECT)
            assert struct.unpack_from("<2Q", reused, 56) == (2, 2)
            call(module, "terminal", "stale-generation-ACK", good, patched(ack(reused), [(528, 1)]), expected=STATE, unchanged=True)
            short_request = request(b"relative")
            _, _, short = call(module, "output-growth", "request", short_request, bytes(WORK), outcap=80, expected=OUTPUT_GROW)
            need = struct.unpack_from("<Q", short, 48)[0]
            assert need > 80 and struct.unpack_from("<Q", short, 56)[0] == 0
            call(module, "output-growth", "short-retry", short_request, short, outcap=need - 1, expected=STATE, unchanged=True)
            _, result, finished = call(module, "output-growth", "delivery", short_request, short, outcap=need, expected=80)
            assert struct.unpack_from("<5Q", result, 8) == (1, 1, 0, 1, 0)
            assert struct.unpack_from("<Q", finished, 56)[0] == 0
            wide = request(b"/" + b"x" * 1024)
            _, _, grow = call(module, "workspace-growth", "request", wide, bytes(6144), expected=GROW)
            assert struct.unpack_from("<Q", grow, 40)[0] == 2048 and struct.unpack_from("<Q", grow, 64)[0] == 0
            call(module, "workspace-growth", "same-small-retry", wide, grow, expected=GROW, unchanged=True)
            call(module, "workspace-growth", "wrong-size-retry", request(b"/" + b"x" * 2048), grow, expected=STATE, unchanged=True)
            _, _, grown = call(module, "workspace-growth", "delivery", wide, grow + bytes(10240 - len(grow)), expected=EFFECT)
            assert struct.unpack_from("<Q", grown, 32)[0] == 2048
            for name, updates in (("generation-exhausted", [(64, MASK), (72, SMAG)]), ("sequence-exhausted", [(56, MASK), (72, SMAG)])):
                call(module, "private-counter-fault", name, good, patched(bytes(WORK), updates), expected=CAPACITY, unchanged=True)

            # These completions exercise HIA control flow. They are explicitly
            # synthetic and do not count as a concurrent kernel race test.
            for mkdir_error, reopen_error in ((17, 20), (0, 20), (17, 0), (0, 0)):
                name = "mkdir-" + str(mkdir_error) + "-reopen-" + str(reopen_error)
                _, _, current = call(module, "private-mkdir-completions", name + "-begin", good, bytes(WORK), expected=EFFECT)
                completions = [(1, 0), (2, 2), (3, mkdir_error), (2, reopen_error)]
                completions += [(6, 4)] if reopen_error else [(6, 4), (6, 9)]
                for index, (kind, error) in enumerate(completions):
                    assert struct.unpack_from("<Q", current, 536)[0] == kind
                    assert struct.unpack_from("<2Q", current, 520) == (index + 1, 1)
                    last = index == len(completions) - 1
                    _, output, current = call(module, "private-mkdir-completions", name + "-ACK-" + str(index),
                                               good, ack(current, errno=error), expected=80 if last else EFFECT)
                values = struct.unpack_from("<9Q", output, 8)
                assert values[:5] == (1 if reopen_error else 0, 1, 1 if mkdir_error == 0 else 0,
                                      9 if reopen_error else 0, reopen_error)
                assert values[7:] == (1, len(completions))
                assert struct.unpack_from("<Q", current, 280)[0] == 0
                _, second_output, repeated = call(module, "private-mkdir-completions", name + "-redelivery", good, current, expected=80)
                assert output == second_output and current == repeated

            for operation, mode, do_rename in ((2, 0o100600, True), (3, 0o40700, True),
                                               (2, 0o40700, False), (3, 0o100600, False)):
                name = "move-" + str(operation) + "-mode-" + str(mode)
                wire = request(b"/s", b"/d", operation=operation)
                _, _, current = call(module, "private-move-completions", name + "-begin", wire, bytes(WORK), expected=EFFECT)
                completions = [(1, 0, 0), (1, 0, 0), (4, 0, mode)]
                if do_rename:
                    completions.append((5, 18, 0))
                completions += [(6, 4, 0), (6, 9, 0)]
                close_slots = []
                for index, (kind, error, stat_value) in enumerate(completions):
                    assert struct.unpack_from("<Q", current, 536)[0] == kind
                    assert struct.unpack_from("<2Q", current, 520) == (index + 1, 1)
                    if kind == 5:
                        assert struct.unpack_from("<Q", current, 624)[0] == 1
                    if kind == 6:
                        close_slots.append(struct.unpack_from("<Q", current, 544)[0])
                    last = index == len(completions) - 1
                    _, output, current = call(module, "private-move-completions", name + "-ACK-" + str(index), wire,
                                               ack(current, errno=error, mode=stat_value), expected=80 if last else EFFECT)
                diagnostic = (15 if operation == 2 else 12) if do_rename else (14 if operation == 2 else 11)
                values = struct.unpack_from("<9Q", output, 8)
                assert values[:5] == (1, operation, 0, diagnostic, 18 if do_rename else 0)
                assert values[7:] == (1, len(completions)) and close_slots == [2, 1]
                assert struct.unpack_from("<Q", current, 280)[0] == 0
            assert args.manifest.read_bytes() == manifest_raw
        report.update(status="PASS", groups=len(groups), group_names=sorted(groups), actual_native_calls=len(rows),
                      source_sha256=module.metadata["source_sha256"], manifest_sha256=sha(manifest_raw))
    except BaseException:
        report.update(status="FAIL", failure=traceback.format_exc(), groups=len(groups), actual_native_calls=len(rows))
        raise
    finally:
        stream.close()
        indices.close()
        report["elapsed_seconds"] = time.monotonic() - started
        report["captures"] = {name: {"bytes": (args.output / name).stat().st_size, "sha256": sha((args.output / name).read_bytes())} for name in ("calls.bin.gz", "calls.jsonl")}
        dump(args.output / "RESULT.json", report)
    print(json.dumps(report, sort_keys=True), flush=True)

if __name__ == "__main__":
    main()
