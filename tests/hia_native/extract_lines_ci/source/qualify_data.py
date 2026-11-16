#!/usr/bin/env python3
"""Actual native data composition and unchanged legacy-line-owner comparison.

This development gate is additive. It is not the fresh target Rust or public
handler qualification. Every complete input/output/workspace is retained.
"""
from pathlib import Path
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import importlib.util
import json
import random
import struct
import sys
import time

U64 = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packet(op, a=0, b=0, c=0, parts=()):
    parts = [v.encode() if isinstance(v, str) else v for v in parts]
    assert len(parts) <= 4
    parts += [b""] * (4 - len(parts))
    return struct.pack("<8s11Q", b"HEXDATA1", op, a & U64, b & U64, c & U64, 0,
                       *(len(v) for v in parts), 0, 0) + b"".join(parts)


def rust_lines(raw):
    if not raw:
        return []
    pieces = raw.split(b"\n")
    terminated = len(pieces) - 1
    result = [p[:-1] if p.endswith(b"\r") else p for p in pieces[:terminated]]
    if pieces[-1]:
        result.append(pieces[-1])
    return result


def documents():
    fixed = [b"", b"\n", b"\r", b"\r\n", b"\r\r\n", b"x", b"x\n", b"x\r",
             b"x\r\n", b"x\r\r\n", b"x\n\n", b"\nlast", b"\x00\t\r\n", "é😀漢\nlast\r".encode()]
    for count in [2, 9, 20, 29, 30, 31, 32, 39, 61]:
        fixed.append(b"\n".join((str(i) + ["", "\r", "\r\r", "é", "😀"][i % 5]).encode() for i in range(count)) + b"\n")
    rng = random.Random(0x45585452414354)
    for _ in range(80):
        fixed.append("".join(rng.choice(["a", "é", "漢", "😀", "\n", "\r", "\x00", "\t"]) for _ in range(rng.randrange(1, 170))).encode())
    yield from fixed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--build-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.runtime / "scripts"))
    from hia_native_loader import NativeModule
    legacy_path = args.runtime / "tests/hia_native/test_line_verify.py"
    text_path = args.runtime / "tests/hia_native/test_text_budget.py"
    legacy = load_module("extract_legacy_line_test", legacy_path)
    text = load_module("extract_legacy_text_test", text_path)
    build = json.loads(args.build_result.read_bytes())
    result = {"schema": "hepta.runtime.extract-data-development.v1", "status": "FAIL",
              "fresh_rust_executed": False, "public_handler_qualified": False,
              "legacy_corpus_sha256": sha(legacy_path.read_bytes()),
              "legacy_text_corpus_sha256": sha(text_path.read_bytes()),
              "driver_sha256": sha(Path(__file__).read_bytes()), "build": build, "counts": {}, "calls": 0}
    started = time.monotonic()
    try:
        with ExitStack() as stack:
            native = {key: stack.enter_context(NativeModule(row["manifest"], manifest_sha256=row["manifest_sha256"]))
                      for key, row in build["modules"].items()}
            stream = stack.enter_context(gzip.open(args.output / "calls.bin.gz", "xb", compresslevel=1))

            def call(key, name, wire, output, workspace, fill=0xA5):
                value, out, work = native[key].invoke_raw(wire, output_capacity=output,
                    workspace_capacity=workspace, output_fill=fill, workspace_fill=0x5A)
                header = canonical({"sequence": result["calls"] + 1, "module": key, "case": name,
                                    "code": value, "input_bytes": len(wire), "output_bytes": len(out),
                                    "workspace_bytes": len(work), "output_fill": fill, "workspace_fill": 0x5A})
                stream.write(struct.pack("<Q", len(header)))
                stream.write(header)
                for data in (wire, out, work):
                    stream.write(data)
                result["calls"] += 1
                return value, out, work

            def data(name, wire, wanted):
                for capacity in sorted({32, max(32, len(wanted) - 1), max(32, len(wanted)), max(32, len(wanted)) + 33}):
                    code, out, work = call("extract-data", name, wire, capacity, 256)
                    if capacity < len(wanted):
                        assert code == 0xffffffd0 and out[:32] == struct.pack("<8s3Q", b"HGRWS002", 2, len(wanted), 0), (name, code, out[:96])
                        assert out[32:] == b"\xA5" * (capacity - 32)
                    else:
                        assert code == len(wanted) and out[:code] == wanted, (name, code, wanted[:160], out[:160])
                        assert out[code:] == b"\xA5" * (capacity - code)
                    assert work[256:] == b""
                result["counts"][name] = result["counts"].get(name, 0) + 1

            for group, wire, wanted in legacy.cases():
                capacity = max(64, len(wanted) + 37)
                before = call("line-verify-old", group, wire, capacity, 192)
                after = call("line-verify-wide", group, wire, capacity, 192)
                assert before == after and after[0] == len(wanted) and after[1][:len(wanted)] == wanted, group
                wide = call("line-verify-wide", "wide_" + group, b"HLINE002" + wire[8:], capacity, 192)
                assert wide == before, group
                result["counts"]["legacy_" + group] = result["counts"].get("legacy_" + group, 0) + 1
            for wire in legacy.invalid_frames():
                before = call("line-verify-old", "legacy_invalid", wire, 4096, 192)
                after = call("line-verify-wide", "legacy_invalid", wire, 4096, 192)
                assert before == after
                result["counts"]["legacy_invalid"] = result["counts"].get("legacy_invalid", 0) + 1

            for raw in documents():
                original = rust_lines(raw)
                data("line_count", packet(5, parts=[raw]), struct.pack("<2Q", len(original), int(raw.endswith(b"\n"))))
                for number in [-(1 << 63), -2, -1, 0, 1, len(original), len(original) + 1]:
                    wanted = legacy.packet(2, number, len(original))
                    data("numeric_packet", packet(1, 1, number, parts=[raw]), b"HLINE002" + wanted[8:])
                for number in sorted({1, max(1, len(original)), len(original) + 1}):
                    expected = legacy.hashed(original[min(number - 1, len(original) - 1)]) if original else legacy.hashed(b"")
                    wanted = legacy.packet(1, number, expected=expected, lines=original)
                    data("id_packet", packet(1, 2, number, int.from_bytes(expected.encode(), "little"), [raw]), b"HLINE002" + wanted[8:])
                if not original:
                    continue
                ranges = {(1, len(original)), (1, 1), (len(original), len(original))}
                if len(original) > 2:
                    ranges.add((2, len(original) - 1))
                for first, last in sorted(ranges):
                    selected = [line.rstrip(b"\r") for line in original[first - 1:last]]
                    inserted = b"".join(line + b"\n" for line in selected)
                    content = b"\n".join(selected) + (b"\n" if last == len(original) and raw.endswith(b"\n") else b"")
                    echo = text.smart([v.decode() for v in selected], first, 30)
                    wanted = struct.pack("<8s7Q", b"HEXSEL01", len(selected), len(original), int(content.endswith(b"\n")), len(inserted), len(echo), 0, 0) + inserted + echo
                    data("select_and_echo", packet(2, first, last, parts=[raw]), wanted)
                    if "text-budget" in native:
                        capacity = max(64, len(echo) + 33)
                        code, check, _ = call("text-budget", "actual_retained_echo", text.packet(4, first, 1, 30, lines=selected),
                            capacity, 128 + len(selected) * 16)
                        assert code == len(echo) and check[:code] == echo and check[code:] == b"\xA5" * (capacity - code)
                    for target in [b"", b"a", b"a\r\n", b"a\nlast\r", b"\n\n"]:
                        target_lines = rust_lines(target)
                        for append in sorted({0, len(target_lines), U64}):
                            insert = len(target_lines) if append == U64 else append
                            trailing = content.endswith(b"\n") if not target or append == U64 else target.endswith(b"\n")
                            request = struct.pack("<8s5Q", b"HEDIT001", 0, len(target), 1, 0, 0) + target
                            request += struct.pack("<4Q", 1, insert, int(trailing), len(inserted)) + inserted
                            data("editable_packet", packet(3, insert, int(trailing), parts=[target, inserted]), request)
                            # Execute the real shared edit owner; the whole-body original replay
                            # independently judges its resulting filesystem bytes later.
                            edit = call("editable", "actual_shared_insert", request, len(target) + len(inserted) * 2 + 512,
                                        (len(target) + len(inserted) + 512) * 16)
                            assert edit[0] < 0xffff0000 and edit[1][:8] == b"HEDRES01", edit[0]
                            position = "beginning of file" if append == 0 else "end of file" if append == U64 else f"after line {append}"
                            message = f"Appended {len(selected)} lines ({first}-{last}) from 'source é' to 'target 😀' at {position}:\n".encode() + echo
                            if insert < len(target_lines):
                                anchor = "0" if insert == 0 else f"{insert}:{legacy.hashed(target_lines[insert - 1])}"
                                message += f"\nshift: lines after {anchor} +{len(selected)}".encode()
                            data("complete_success", packet(4, first, last, append, ["source é", "target 😀", echo, target]), message)

            good = packet(2, 1, 1, parts=[b"x\n"])
            invalid = [good[:size] for size in range(96)]
            invalid += [b"BADMAGIC" + good[8:], good + b"x", good[:-1], packet(2, 0, 1, parts=[b"x"]), packet(2, 2, 1, parts=[b"x"]), packet(2, 1, 2, parts=[b"x"]), packet(3, 0, 0, parts=[b"", b"x"])]
            for offset in [40, 80, 88]:
                bad = bytearray(good); struct.pack_into("<Q", bad, offset, 1); invalid.append(bytes(bad))
            for offset in [48, 56, 64, 72]:
                bad = bytearray(good); struct.pack_into("<Q", bad, offset, U64); invalid.append(bytes(bad))
            for raw in [b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"]:
                invalid.append(packet(5, parts=[raw]))
            for wire in invalid:
                code, out, work = call("extract-data", "invalid_atomic", wire, 4096, 256)
                assert code == 0xffffffff and out == b"\xA5" * 4096 and work == b"\x5A" * 256
            result["counts"]["invalid_atomic"] = len(invalid)
            for capacity in [0, 1, 31]:
                code, out, work = call("extract-data", "output_header_refusal", good, capacity, 256)
                assert code == 0xfffffffe and out == b"\xA5" * capacity and work == b"\x5A" * 256
            for capacity in [0, 1, 255]:
                code, out, work = call("extract-data", "workspace_growth", good, 63, capacity)
                assert code == 0xffffffd0 and out[:32] == struct.pack("<8s3Q", b"HGRWS002", 1, 256, 0)
                assert out[32:] == b"\xA5" * 31 and work == b"\x5A" * capacity
            result["counts"]["capacity_controls"] = 6
        result["status"] = "PASS"
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "detail": str(exc)}
        raise
    finally:
        result["elapsed_seconds"] = time.monotonic() - started
        capture = args.output / "calls.bin.gz"
        if capture.exists():
            result["capture"] = {"path": capture.name, "bytes": capture.stat().st_size, "sha256": sha(capture.read_bytes())}
        (args.output / "result.json").write_bytes(canonical(result))
    print(json.dumps({k: v for k, v in result.items() if k != "build"}, sort_keys=True))


if __name__ == "__main__":
    main()
