#!/usr/bin/env python3
"""Actual complete Value -> retained typed owner -> rebuilt carrier comparison."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "runtime_support/scripts"))
from hia_native_loader import NativeModule

INVALID, CAPACITY = 0xffffffff, 0xfffffffe
HEADERS = {1: 32, 2: 64, 3: 128}
MAGICS = {1: b"HJSVR002", 2: b"HBPRR002", 3: b"HBAPRR01"}
NEEDS = {1: 24, 2: 48, 3: 80}
MODULES = {1: "value", 2: "batch_params_original", 3: "batch_params"}
SOURCE_FILES = (
    "qualify_typed.py", "corpus/batch_params_cases.py", "typed-inputs.json",
    "build_adapters.py", "runtime_support/scripts/hia_native_loader.py",
    "runtime_support/scripts/hia_native_build.py", "retained/serde_json_span.hepta",
    "retained/batch_edit_params.hepta", "native/batch_params.hepta",
    "native/batch_gateway.hepta", "native/batch_call.hepta",
    "native/adapter-author-proof.json", "retained-inputs.json",
    "retained/text_editor_gateway.hepta", "retained/text_editor_call.hepta",
    "authoring/author_adapters.py", "authoring/batch_params.pseudo",
    "authoring/batch_gateway.pseudo", "authoring/batch_call.pseudo",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": sha(raw)}


def word(raw, at):
    return struct.unpack_from("<Q", raw, at)[0]


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def load_inputs():
    spec = importlib.util.spec_from_file_location("_rebuilt_batch_inputs", ROOT / "corpus/batch_params_cases.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = list(module.iter_cases()) + list(module.extra_cases())
    assert len(rows) == 425
    assert sum(row["domain"] == "typed-object" for row in rows) == 417
    return rows


def raw_input(row):
    if "raw_json" in row:
        return row["raw_json"].encode()
    return json.dumps(row["value"], ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def typed_frame(raw):
    return b"HBPRQ002" + struct.pack("<2Q", len(raw), 0) + raw


def projected(retained):
    assert retained[:8] == b"HBPRR002" and word(retained, 8) in (0, 1)
    fields = [0] * 15
    fields[0] = word(retained, 8)
    if fields[0] == 0:
        plen = word(retained, 16)
        fields[1:5] = [1, plen, 1, len(retained)]
        payload = retained[64:64 + plen] + retained
    else:
        fields[8] = word(retained, 40)
        payload = retained[64:]
    return b"HBAPRR01" + struct.pack("<15Q", *fields) + payload


def result_size(owner, output):
    assert output[:8] == MAGICS[owner]
    status = word(output, 8)
    assert word(output, NEEDS[owner]) == 0
    if owner == 1:
        assert status == 0
        return 32 + word(output, 16)
    assert status in (0, 1)
    if owner == 2:
        assert word(output, 56) == 0
        if status == 0:
            assert word(output, 40) == 0
            return 64 + word(output, 16) + word(output, 24)
        assert output[16:40] == bytes(24)
        return 64 + word(output, 40)
    assert output[88:128] == bytes(40)
    if status == 0:
        assert word(output, 16) == 1 and word(output, 32) == 1
        assert output[48:80] == bytes(32)
        return 128 + word(output, 24) + word(output, 40)
    assert output[16:72] == bytes(56)
    return 128 + word(output, 72)


class Recorder:
    def __init__(self, build, output):
        self.build, self.output = build, output
        output.mkdir(parents=True, exist_ok=False)
        self.stream = gzip.open(output / "calls.bin.gz", "wb", compresslevel=1)
        self.index, self.semantic, self.controls = [], [], []
        self.offset = 0
        self.sources = {name: pin(ROOT / name) for name in SOURCE_FILES}
        self.artifacts = {"BUILD.json": pin(build / "BUILD.json")}
        metadata = json.loads((build / "BUILD.json").read_bytes())
        assert metadata["status"] == "PASS" and metadata["fresh_native_compilations"] == 5
        self.modules = {}
        for owner, name in MODULES.items():
            item = metadata["modules"][name]
            manifest = build / item["manifest"]
            assert pin(manifest) == item["manifest_pin"]
            doc = json.loads(manifest.read_bytes())
            assert doc["source_sha256"] == item["source_pin"]["sha256"]
            assert doc["image_sha256"] == item["image_pin"]["sha256"]
            self.modules[owner] = NativeModule(manifest, manifest_sha256=sha(manifest.read_bytes()))
            for path in (manifest, manifest.parent / doc["image"], manifest.parent / doc["source"]):
                self.artifacts[str(path.relative_to(build))] = pin(path)

    def invoke(self, owner, case_id, label, wire, before, capacity):
        with self.modules[owner].session(workspace_capacity=len(before), output_capacity=capacity) as session:
            if before:
                ctypes.memmove(session._workspace, before, len(before))
            ctypes.memset(session._output, 0xa5, capacity)
            code, out, after = session.invoke_raw(wire)
        call = len(self.index) + 1
        parts = (struct.pack("<8Q", call, owner, case_id, code, len(wire), capacity, len(before), 0),
                 wire, before, b"\xa5" * capacity, out, after)
        digest = hashlib.sha256()
        size = 0
        for part in parts:
            self.stream.write(part)
            digest.update(part)
            size += len(part)
        self.index.append({"call": call, "owner": owner, "case_id": case_id, "label": label,
            "offset": self.offset, "bytes": size, "return_code": code,
            "input_bytes": len(wire), "output_capacity": capacity, "workspace_capacity": len(before),
            "input_sha256": sha(wire), "before_sha256": sha(before),
            "output_before_sha256": sha(parts[3]), "output_sha256": sha(out),
            "after_sha256": sha(after), "record_sha256": digest.hexdigest()})
        self.offset += size
        return code, out, after, call

    def complete(self, owner, case_id, wire, *, wcap=None, ocap=None, label="semantic"):
        before = bytes(wcap if wcap is not None else (16512 if owner == 1 else 65536))
        capacity = HEADERS[owner] if ocap is None else ocap
        calls = []
        for _ in range(16):
            code, out, after, call = self.invoke(owner, case_id, label, wire, before, capacity)
            calls.append(call)
            assert code == HEADERS[owner] and out[:8] == MAGICS[owner], (owner, case_id, code)
            status, needed = word(out, 8), word(out, NEEDS[owner])
            if status in (2, 3):
                assert out[HEADERS[owner]:] == b"\xa5" * (capacity - HEADERS[owner])
                if status == 2:
                    assert needed > len(before)
                    before = after + bytes(needed - len(after))
                else:
                    assert needed > capacity
                    capacity, before = needed, after
                continue
            size = result_size(owner, out)
            assert size <= capacity and out[size:] == b"\xa5" * (capacity - size)
            return out[:size], calls
        raise AssertionError("nonconverging capacity sequence")

    def finish(self, success, elapsed, failure):
        self.stream.close()
        for module in self.modules.values():
            module.close()
        assert self.sources == {name: pin(ROOT / name) for name in self.sources}
        assert self.artifacts == {name: pin(self.build / name) for name in self.artifacts}
        for name, rows in (("calls.jsonl", self.index), ("semantic.jsonl", self.semantic), ("controls.jsonl", self.controls)):
            (self.output / name).write_bytes(b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows))
        result = {"schema": "hepta.runtime.rebuilt-batch-typed-comparison.v1",
            "status": "PASS" if success else "FAIL", "semantic_cases": len(self.semantic),
            "control_cases": len(self.controls), "actual_native_calls": len(self.index),
            "calls_by_owner": {str(owner): sum(row["owner"] == owner for row in self.index) for owner in MODULES},
            "complete_record_bytes": self.offset, "elapsed_seconds": elapsed, "failure": failure,
            "source_root": str(ROOT), "build_root": str(self.build), "output_root": str(self.output),
            "source_inputs": {"files": self.sources}, "build_artifacts": self.artifacts,
            "artifacts": {name: pin(self.output / name) for name in ("calls.bin.gz", "calls.jsonl", "semantic.jsonl", "controls.jsonl")},
            "raw_semantics_owner_unchanged": True, "fresh_current_original_compared": False,
            "effects_executed": False, "public_batch_qualified": False, "whole_runtime_replaced": False}
        save(self.output / "result.json", result)
        print(json.dumps(result, sort_keys=True))


def run(recorder):
    rows = load_inputs()
    for row in rows:
        if row["domain"] != "typed-object":
            continue
        raw = raw_input(row)
        value, vcalls = recorder.complete(1, row["case_id"], b"HJSVS002" + struct.pack("<2Q", 1, len(raw)) + raw)
        canonical = value[32:]
        wire = typed_frame(canonical)
        old, oldcalls = recorder.complete(2, row["case_id"], wire)
        new, newcalls = recorder.complete(3, row["case_id"], wire)
        assert new == projected(old), (row["case_id"], row["name"])
        recorder.semantic.append({"case_id": row["case_id"], "name": row["name"], "domain": row["domain"],
            "input_bytes": len(raw), "input_sha256": sha(raw), "canonical_bytes": len(canonical),
            "canonical_sha256": sha(canonical), "retained_bytes": len(old), "retained_sha256": sha(old),
            "carrier_bytes": len(new), "carrier_sha256": sha(new), "status": word(old, 8),
            "value_calls": vcalls, "retained_calls": oldcalls, "carrier_calls": newcalls})
    assert len(recorder.semantic) == 417

    raw = b'{"operations":[],"path":"p"}'
    good = typed_frame(raw)
    bad = [b"", good[:7], good[:23], b"XXXXXXXX" + good[8:],
        good[:8] + struct.pack("<Q", len(raw) + 1) + good[16:], good[:16] + struct.pack("<Q", 1) + good[24:],
        typed_frame(b"[]"), typed_frame(b"null"), typed_frame(b"{"), typed_frame(b"{} "),
        typed_frame(b'{"path":"p","operations":[],}'), typed_frame(b'{"path":"p","operations":[}]}'),
        typed_frame(b'{"path":"\xff","operations":[]}'), typed_frame(b'{"path":"\\ud800","operations":[]}'),
        typed_frame(b'{"path":"p","operations":[{"content":"x","operation":"insert","start":01}]}')]
    bad += [typed_frame(raw_input(row)) for row in rows if row["domain"] == "private-raw-value"]
    assert len(bad) == 23
    for n, wire in enumerate(bad):
        for owner in (2, 3):
            code, out, _, call = recorder.invoke(owner, 30000 + n, "invalid-frame", wire, b"\x7b" * 65536, 512)
            assert code == INVALID and out == b"\xa5" * 512
            recorder.controls.append({"kind": "invalid-frame", "call": call, "expected_code": INVALID})
    for owner, capacities in ((2, (0, 1, 31, 63)), (3, (0, 1, 31, 63, 127))):
        for n, capacity in enumerate(capacities):
            before = b"\x7b" * 65536
            code, out, after, call = recorder.invoke(owner, 30100 + n, "short-output", good, before, capacity)
            assert (code, out, after) == (CAPACITY, b"\xa5" * capacity, before)
            recorder.controls.append({"kind": "short-output", "call": call, "expected_code": CAPACITY})

    examples = [raw, b'{"operations":[{"content":"x","operation":{"insert":"bad"},"start":0}],"path":"p"}',
                b'{"operations":[["insert",0,null,["a","b"]]],"path":"p"}']
    expected = {}
    for n, raw in enumerate(examples):
        wire = typed_frame(raw)
        for owner in (2, 3):
            full, setup = recorder.complete(owner, 31000 + n, wire, label="control-baseline")
            expected[owner, n] = full
            for capacity in (HEADERS[owner], len(full) - 1, len(full), len(full) + 19):
                code, out, _, call = recorder.invoke(owner, 31100 + n, "output-boundary", wire, b"\x7b" * 65536, capacity)
                assert code == HEADERS[owner]
                if capacity < len(full):
                    assert out[:8] == MAGICS[owner] and word(out, 8) == 3 and word(out, NEEDS[owner]) == len(full)
                    check = bytearray(HEADERS[owner]); check[:8] = MAGICS[owner]
                    struct.pack_into("<Q", check, 8, 3); struct.pack_into("<Q", check, NEEDS[owner], len(full))
                    assert out[:HEADERS[owner]] == bytes(check)
                    assert out[HEADERS[owner]:] == b"\xa5" * (capacity - HEADERS[owner])
                else:
                    assert out[:len(full)] == full and out[len(full):] == b"\xa5" * (capacity - len(full))
                recorder.controls.append({"kind": "output-boundary", "call": call, "baseline_calls": setup,
                    "required_capacity": len(full), "expected_response_sha256": sha(full)})
            for wcap in (0, 1, 32767, 32768):
                before = b"\x7b" * wcap
                code, out, after, call = recorder.invoke(owner, 31200 + n, "workspace-growth", wire, before, HEADERS[owner])
                assert code == HEADERS[owner] and word(out, 8) == 2 and word(out, NEEDS[owner]) > wcap
                if wcap < 32768:
                    assert after == before
                actual, resumed = recorder.complete(owner, 31300 + n, wire, wcap=word(out, NEEDS[owner]), ocap=len(full), label="control-resume")
                assert actual == full
                recorder.controls.append({"kind": "workspace-growth", "call": call, "baseline_calls": setup,
                    "resume_calls": resumed, "expected_response_sha256": sha(full)})
        assert expected[3, n] == projected(expected[2, n])
    for owner in (2, 3):
        before = b"\x7b" * 65536
        for n, index in enumerate((0, 1, 2, 2, 1, 0)):
            full = expected[owner, index]
            code, out, after, call = recorder.invoke(owner, 31400 + n, "dirty-prior-state", typed_frame(examples[index]), before, 4096)
            assert code == HEADERS[owner] and out[:len(full)] == full
            assert out[len(full):] == b"\xa5" * (len(out) - len(full))
            recorder.controls.append({"kind": "dirty-prior-state", "call": call, "expected_response_sha256": sha(full), "expected_response_bytes": len(full)})
            before = after
    assert len(recorder.controls) == 115


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    recorder = Recorder(args.build.resolve(strict=True), args.output.absolute())
    success, failure = False, None
    started = time.monotonic()
    try:
        run(recorder)
        success = True
    except BaseException:
        failure = traceback.format_exc()
        sys.stderr.write(failure)
    finally:
        recorder.finish(success, time.monotonic() - started, failure)
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
