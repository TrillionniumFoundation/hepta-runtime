# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualification-only inert fixtures and whole-result comparison against original Rust."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import time
import traceback

from rea_asar_native_transport import AsarModule, request


def archive(header, data=b""):
    raw = header if isinstance(header, bytes) else json.dumps(
        header, ensure_ascii=False, separators=(",", ":")).encode()
    aligned = (len(raw) + 3) // 4 * 4
    return struct.pack("<4I", 4, 8 + aligned, 4 + aligned, len(raw)) + raw + bytes(aligned - len(raw)) + data


def integrity(data, block_size):
    parts = [data[i:i + block_size] for i in range(0, len(data), block_size)] or [b""]
    return {"algorithm": "SHA256", "hash": hashlib.sha256(data).hexdigest(),
        "blockSize": block_size, "blocks": [hashlib.sha256(part).hexdigest() for part in parts]}


def packed(data, block_size=4):
    return archive({"files": {"main.js": {"size": len(data), "offset": "0",
        "integrity": integrity(data, block_size)}}}, data)


def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "manifest", "oracle", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    events = out / "native-events"
    events.mkdir(mode=0o700)
    (out / "qualification-source.py").write_bytes(Path(__file__).read_bytes())
    manifest = args.manifest.read_bytes()
    (out / "admitted-manifest.json").write_bytes(manifest)
    source_files = [args.oracle, args.manifest,
        args.source / "src/mcp/rea_asar_parser.rs",
        args.source / "src/mcp/rea_asar_parser_tests.rs",
        args.source / "native/rea_asar_parser.hepta",
        Path(__file__), Path(__file__).with_name("rea_asar_native_transport.py")]
    before = {str(p): {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in source_files}
    (out / "source-pins.json").write_text(json.dumps(before, sort_keys=True, indent=2) + "\n")
    cases = []

    def admit(label, data, operation="index", offset=0, limit=64,
              member="main.js", length=64, require_complete=False, path=None):
        if path is None:
            path = fixtures / f"{len(cases):05}.asar"
            path.write_bytes(data)
            path.chmod(0o400)
        typed = ({"operation": operation, "offset": offset, "limit": limit}
            if operation == "index" else {"operation": operation, "member": member,
            "offset": offset, "length": length, "require_complete": require_complete})
        cases.append({"label": label, "path": str(path), "request": typed})

    seed = archive({"files": {"a": {"offset": "0", "size": 1}}}, b"x")
    for index in range(len(seed)):
        for mask in (1, 128, 255):
            changed = bytearray(seed)
            changed[index] ^= mask
            admit(f"original-shaped-byte-mutation/{index}/{mask}", changed)
    for length in range(len(seed)):
        admit(f"truncation/{length}", seed[:length])
    for limit in (0, 1, 64, 256, 257, (1 << 64) - 1):
        for offset in (0, 1, 2, 50000, 50001, (1 << 64) - 1):
            admit(f"index-request/{offset}/{limit}", seed, offset=offset, limit=limit)
    for offset in (0, 1, 2, 67108864, 67108865, (1 << 64) - 1):
        for length in (0, 1, 1048576, 1048577):
            for complete in (False, True):
                admit(f"read-request/{offset}/{length}/{complete}", seed,
                    operation="read", member="a", offset=offset, length=length,
                    require_complete=complete)

    grammar = [b"", b" ", b"null", b"true", b"false", b"0", b"-0", b"[]", b"\"x\"",
        b"{}", b'{"files":null}', b'{"files":[]}', b'{"files":{},"other":null}',
        b'{"files":{}} garbage', b'\xef\xbb\xbf{"files":{}}', b'{"files":{},}',
        b'{"files":{}} \t\r\n', b'{"files":{},"files":{}}',
        b'{"files":{"a":{"size":0,"offset":"0"},"\\u0061":{"size":0,"offset":"0"}}}',
        b'{"files":{"a":{"size":0,"\\u0073ize":0,"offset":"0"}}}',
        b'{"files":{},"x":{"a":1,"a":2}}',
        b'{"files":{},"x":{"\\ud83d\\ude00":1,"\xf0\x9f\x98\x80":2}}',
        b'{"files":{},"x":{"$serde_json::private::RawValue":"{}"}}',
        b'{"files":{},"x":{"$serde_json::private::Number":"0"}}',
        b'{"files":{},"x":[1,]}', b'{"files":{},"x":[,1]}',
        b'{"files":{},"x":[true false]}', b'{"files":{},"x":"\\x00"}',
        b'{"files":{},"x":"\\ud800"}', b'{"files":{},"x":"\\udc00"}',
        b'{"files":{},"x":"\\ud800\\u0000"}', b'{"files":{},"x":"\\u00xy"}',
        b'{"files":{},"x":"\xff"}', b'{"files":{},"x":"\xc0\x80"}',
        b'{"files":{},"x":"\xed\xa0\x80"}', b'{"files":{},"x":"\xf4\x90\x80\x80"}']
    for index, raw in enumerate(grammar):
        admit(f"json-grammar/{index}", archive(raw))
    for depth in (1, 32, 64, 125, 126, 127, 128, 129):
        for leaf in (b"0", b"{}", b"[]"):
            admit(f"json-depth/{depth}/{leaf.hex()}", archive(
                b'{"files":{},"x":' + b"[" * depth + leaf + b"]" * depth + b"}"))
    for raw in (b"0", b"-0", b"1", b"-1", b"1.0", b"0.0", b"1e0", b"1E+0",
        b"9007199254740991", b"9007199254740992", b"18446744073709551615",
        b"18446744073709551616", b"-9223372036854775808", b"-9223372036854775809",
        b"1e308", b"1e309", b"1e10000", b"1e-10000", b"0e10000",
        b"01", b"+1", b".1", b"1.", b"1e", b"1e+", b"NaN", b"Infinity",
        b"true", b"null", b'"1"', b"0." + b"0" * 700 + b"1"):
        admit("numeric-member-size/" + raw[:70].decode(), archive(
            b'{"files":{"a":{"offset":"0","size":' + raw + b"}}}", b"x"))
        admit("numeric-unknown/" + raw[:70].decode(), archive(b'{"files":{},"x":' + raw + b"}"))
    for value in (None, True, False, 0, 1, "", "0", "00", "01", "+1", "-1", " 1", "1 ",
        "1e0", "0x0", "1x", "9007199254740991", "9007199254740992",
        "18446744073709551616", "1" * 1000):
        admit("decimal-offset/" + repr(value)[:80], archive({"files": {
            "a": {"offset": value, "size": 0}}}, b"x"))

    names = ["", ".", "..", "/a", "a/b", "a\\b", "C:", "x\0y", "x\ny",
        "\x7f", "\x80", "\x9f", "\xa0", "\u00ad", "\u2028", "\u2029",
        "quote\"name", "π.js", "资料.txt", "😀", "a" * 4096, "a" * 4097]
    for ordinal, name in enumerate(names):
        data = archive({"files": {name: {"offset": "0", "size": 0}}})
        admit(f"filename/{ordinal}", data)
        admit(f"requested-member/{ordinal}", seed, operation="read", member=name, length=1)
    for node in (None, [], 0, False, {}, {"files": None}, {"files": [], "unpacked": True},
        {"files": {}, "size": 0}, {"link": 0}, {"link": "../outside"},
        {"link": "target", "offset": "0"}, {"unpacked": True, "size": 1, "offset": "0"},
        {"unpacked": "true", "size": 1, "offset": "0"},
        {"size": 1, "offset": "0", "executable": 0},
        {"size": 1, "offset": "0", "unknown": 0},
        {"size": 1, "offset": "0", "integrity": None}):
        admit("entry-kind/" + repr(node), archive({"files": {"a": node}}, b"x"))
    inventory = {"files": {
        "d": {"files": {"z": {"offset": "1", "size": 2},
            "!": {"link": "d/z"}, "π": {"size": 5, "unpacked": True}}},
        "d!": {"offset": "0", "size": 1}, "d.": {"offset": "3", "size": 0},
        "d0": {"offset": "3", "size": 0},
        "u": {"unpacked": True, "files": {"child": {"size": 9007199254740991},
            "link": {"link": "d/z"}, "sub": {"files": {
                "inherit": {"unpacked": False, "size": 7}}}}},
        "zero": {"offset": "3", "size": 0}}}
    inv_bytes = archive(inventory, b"abc")
    for offset in (0, 1, 2, 5, 10, 13, 14):
        for limit in (1, 2, 256):
            admit(f"whole-inventory-order/{offset}/{limit}", inv_bytes, offset=offset, limit=limit)
    for member in ("d", "d/z", "d/!", "d/π", "d!", "d.", "d0", "u/child", "zero", "missing"):
        admit("whole-inventory-read/" + member, inv_bytes, operation="read", member=member)
    for depth in (0, 1, 31, 32, 33, 34):
        header = {"files": {"a": {"offset": "0", "size": 0}}}
        for _ in range(depth):
            header = {"files": {"d": header}}
        admit(f"directory-depth/{depth}", archive(header))
    for second_offset, second_size in (("0", 0), ("0", 1), ("1", 0), ("1", 2), ("2", 1), ("3", 0), ("4", 0)):
        admit(f"coverage/{second_offset}/{second_size}", archive({"files": {
            "a": {"offset": "0", "size": 2},
            "b": {"offset": second_offset, "size": second_size}}}, b"abc"), limit=1)

    for size in (0, 1, 3, 4, 5, 7, 8, 10, 65, 65535, 65536, 65537, 131073):
        data = bytes((i * 17 + 13) % 256 for i in range(size))
        for block_size in (4, 65536):
            blob = packed(data, block_size)
            for offset, length, complete in ((0, 1048576, False), (min(size, 2), 5, False),
                    (0, max(1, size), True)):
                admit(f"integrity-range/{size}/{block_size}/{offset}/{length}/{complete}",
                    blob, operation="read", offset=offset, length=length, require_complete=complete)
            if size:
                changed = bytearray(blob)
                changed[-1] ^= 1
                admit(f"corruption-outside-range/{size}/{block_size}", changed,
                    operation="read", length=1)
                admit(f"unselected-corruption/{size}/{block_size}", changed)
    good = {"files": {"a": {"size": 4, "offset": "0", "integrity": integrity(b"abcd", 4)}}}
    for key, value in (("algorithm", "SHA512"), ("algorithm", None),
        ("hash", "A" * 64), ("hash", "g" * 64), ("hash", "a" * 63),
        ("blockSize", 0), ("blockSize", 1.0), ("blockSize", 67108865),
        ("blocks", []), ("blocks", None), ("blocks", ["a" * 64, "b" * 64]),
        ("blocks", ["A" * 64]), ("unknown", 0)):
        header = json.loads(json.dumps(good))
        header["files"]["a"]["integrity"][key] = value
        admit(f"integrity-declaration/{key}/{value}", archive(header, b"abcd"))
    for key in ("hash", "blocks"):
        header = json.loads(json.dumps(good))
        header["files"]["a"]["integrity"][key] = "0" * 64 if key == "hash" else ["0" * 64]
        admit("integrity-mismatch/" + key, archive(header, b"abcd"),
            operation="read", member="a", length=1)
    admit("empty-archive", archive({"files": {}}))
    admit("unreferenced-payload", archive({"files": {}}, b"unselected inert bytes"))

    (out / "cases.json").write_text(json.dumps(cases, sort_keys=True, indent=2) + "\n")
    oracle_err = (out / "oracle.stderr").open("xb")
    oracle = subprocess.Popen([str(args.oracle)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=oracle_err, text=True, bufsize=1)
    module = AsarModule(args.manifest, args.source)
    started = time.monotonic()
    compared = differences = effects = calls = successful = refused = 0
    try:
        with (out / "observations.jsonl").open("x") as observations, \
             (out / "differences.jsonl").open("x") as difference_log:
            for ordinal, case in enumerate(cases):
                fd = os.open(case["path"], os.O_RDONLY)
                try:
                    wire = request(fd, **case["request"])
                    oracle.stdin.write(json.dumps(case) + "\n")
                    oracle.stdin.flush()
                    line = oracle.stdout.readline()
                    assert line, ("reference ended", oracle.poll())
                    expected = json.loads(line)
                    with (events / f"case-{ordinal:05}.jsonl").open("x") as stream:
                        actual = module.invoke(wire, fd, stream)
                    received = ({"ok": True, "value": json.loads(actual["payload"])}
                        if actual["status"] == 0 else {"ok": False, "error": actual["payload"]})
                    equal = expected == received
                    row = {"ordinal": ordinal, "case": case, "equal": equal,
                        "reference": expected, "native": received, "native_effects": actual["effects"],
                        "native_calls": actual["native_calls"], "actual_read_bytes": actual["actual_read_bytes"]}
                    observations.write(json.dumps(row, sort_keys=True) + "\n")
                    if not equal:
                        differences += 1
                        difference_log.write(json.dumps(row, sort_keys=True) + "\n")
                        difference_log.flush()
                    compared += 1
                    effects += actual["effects"]
                    calls += actual["native_calls"]
                    successful += expected["ok"]
                    refused += not expected["ok"]
                finally:
                    os.close(fd)
                if compared % 100 == 0:
                    observations.flush()
                    print(json.dumps({"compared": compared, "total": len(cases),
                        "differences": differences, "seconds": time.monotonic() - started}), flush=True)
        oracle.stdin.close()
        assert oracle.wait(timeout=30) == 0
        for name, pin in before.items():
            data = Path(name).read_bytes()
            assert len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"]
        terminal = {"status": "PASS" if differences == 0 else "FAIL",
            "full_json_or_exact_error_comparisons": compared, "planned_cases": len(cases),
            "differences": differences, "reference_successes": successful,
            "reference_refusals": refused, "native_calls": calls, "native_effects": effects,
            "seconds": time.monotonic() - started, "source_bytes_unchanged": True,
            "original_source_and_assertions_changed": False, "public_route_qualified": False}
        (out / "terminal.json").write_text(json.dumps(terminal, indent=2, sort_keys=True) + "\n")
        print(json.dumps(terminal, sort_keys=True), flush=True)
        assert differences == 0
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"status": "FAIL",
            "compared": compared, "differences": differences, "error": repr(error),
            "traceback": traceback.format_exc(), "seconds": time.monotonic() - started,
            "public_route_qualified": False}, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        if oracle.poll() is None:
            oracle.terminate()
            oracle.wait(timeout=30)
        oracle_err.close()
        module.close()


if __name__ == "__main__":
    main()
