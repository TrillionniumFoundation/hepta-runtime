"""Execute the real HIA parameter/Value chain against actual Rust observations."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT))
sys.path.insert(0, str(REFERENCE / "scripts"))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
ACTION, REQUEST, REPLY, WORK = 256, 4096, 67117056, 209727488


def invoke(session, wire):
    try:
        raw = session.invoke(wire)
        return len(raw), raw
    except (NativeRejected, NativeCapacityError) as error:
        return error.code, b""


def request(raw):
    return b"HMWDPQ01" + struct.pack("<2Q", len(raw), 0) + raw


class Bridge:
    def __init__(self, owner, value):
        self.owner, self.value = owner, value
        self.entries = self.calls = 0

    def read(self, offset, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + offset, size)

    def write(self, offset, raw):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + offset, raw, len(raw))

    def word(self, offset, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + offset)
        if value is None:
            return cell.value
        cell.value = value

    def enter(self, wire):
        self.entries += 1
        return invoke(self.owner, wire)

    def complete(self):
        magic, seq, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = struct.unpack("<8s11Q", self.read(ACTION, 96))
        assert magic == b"HMWDPA01" and seq > 0 and child == 1
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and capacity == 64 << 20
        assert 24 <= size <= (8 << 20) + 24
        raw = self.read(start, size)
        assert raw[:8] == b"HSJVAL01" and struct.unpack_from("<2Q", raw, 8) == (1, size - 24)
        self.calls += 1
        child_code, reply = invoke(self.value, raw)
        self.write(REPLY, reply)
        self.word(ACTION + 64, seq)
        self.word(ACTION + 72, child_code)
        return dict(sequence=seq, child_code=child_code, input_bytes=len(raw), input_sha256=SHA(raw), output_bytes=len(reply), output_sha256=SHA(reply))

    def run(self, wire):
        first, raw = self.enter(wire)
        if first != CALL:
            return first, raw, None
        child = self.complete()
        code, raw = self.enter(wire)
        assert code != CALL
        return code, raw, child


def decode(raw):
    assert len(raw) >= 48 and raw[:8] == b"HMWDPR01"
    tag, present, reset, path_len, size = struct.unpack_from("<5Q", raw, 8)
    assert tag <= 1 and present <= 1 and reset <= 2 and len(raw) == 48 + path_len + size
    assert tag == 0 or present == reset == path_len == 0
    return dict(tag=tag, present=present, reset=reset, path=raw[48:48 + path_len], text=raw[48 + path_len:].decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["manifest", "value-manifest", "cases", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    records = json.loads(args.cases.read_bytes())
    report = dict(schema="hepta.workdir.params-native.v1", status="FAIL", cases=[], controls=[],
        original_input_sha256=SHA(args.cases.read_bytes()), whole_runtime_replaced=False,
        production_activated=False, old_stack_removal_qualified=False)
    start = time.monotonic()
    def save():
        (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    try:
        with ExitStack() as stack:
            owner = stack.enter_context(NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())))
            value = stack.enter_context(NativeModule(args.value_manifest, manifest_sha256=SHA(args.value_manifest.read_bytes())))
            report["modules"] = dict(owner=owner.metadata, value=value.metadata)
            session = stack.enter_context(owner.session(output_capacity=(64 << 20) + 48, workspace_capacity=WORK))
            child = stack.enter_context(value.session(output_capacity=64 << 20, workspace_capacity=256 << 20))
            bridge = Bridge(session, child)
            results = bytearray()
            for ordinal, row in enumerate(records["cases"]):
                raw = row["parameters"].encode()
                code, output, child_receipt = bridge.run(request(raw))
                observed = row["observed"]
                assert code == len(output) and code < 0xffff0000, (ordinal, row["label"], code)
                actual = decode(output)
                expected_tag = 0 if observed["code"] == 0 else 1
                expected_text = observed["normalized"] if expected_tag == 0 else observed["result"]
                assert actual["tag"] == expected_tag and actual["text"] == expected_text, (ordinal, row, actual)
                if expected_tag == 0:
                    normalized = json.loads(expected_text)
                    path, reset = normalized["path"], normalized["reset"]
                    assert actual["present"] == int(path is not None)
                    assert actual["path"] == (path.encode() if path is not None else b"")
                    assert actual["reset"] == (0 if reset is None else 2 if reset else 1)
                report["cases"].append(dict(ordinal=ordinal, label=row["label"], input_sha256=SHA(raw), output_sha256=SHA(output), original_text_sha256=SHA(expected_text.encode()), child=child_receipt))
                results.extend(struct.pack("<Q", len(output)) + output)
            for label, wire, expected in [
                ("short", b"", INVALID), ("magic", b"????????" + request(b"{}")[8:], INVALID),
                ("reserved", request(b"{}")[:16] + struct.pack("<Q", 1) + b"{}", INVALID),
                ("trailing", request(b"{}") + b"x", INVALID),
                ("invalid-json", request(b"{"), INVALID),
                ("depth-128", request(b"[" * 128 + b"0" + b"]" * 128), INVALID),
                ("oversized", request(b" " * (8 << 20) + b"0"), CAPACITY),
            ]:
                before = bytes(session._output)
                code, output, receipt = bridge.run(wire)
                assert code == expected and output == b"" and bytes(session._output) == before, (label, code)
                report["controls"].append(dict(label=label, actual_code=code, child=receipt, output_unchanged=True))
                code, output, _ = bridge.run(request(b"{}"))
                assert decode(output)["text"] == '{"path":null,"reset":null}'
            wire = request(b'{"path":"sub","reset":true}')
            for offset in [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88]:
                assert bridge.enter(wire)[0] == CALL
                bridge.complete()
                old = bridge.word(ACTION + offset)
                bridge.word(ACTION + offset, old ^ 1)
                before = bytes(session._output)
                code, output = bridge.enter(wire)
                assert code == INVALID and output == b"" and bytes(session._output) == before
                bridge.word(ACTION + offset, old)
                code, output = bridge.enter(wire)
                assert decode(output)["text"] == '{"path":"sub","reset":true}'
                report["controls"].append(dict(label="action-word-" + str(offset), actual_code=INVALID, output_unchanged=True, recovery=True))
            (args.output / "native.bin").write_bytes(results)
            report.update(status="PASS", native_cases=len(records["cases"]), native_entries=bridge.entries,
                native_value_calls=bridge.calls, output_sha256=SHA(results), elapsed_seconds=time.monotonic() - start)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ["cases", "controls", "modules"]}, sort_keys=True))


if __name__ == "__main__":
    main()
