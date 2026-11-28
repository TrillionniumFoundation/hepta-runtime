# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare complete unchanged Rust ZIP results with the actual HIA image.

This is a qualification client, not a product parser. It creates inert archive
fixtures and passes the same descriptor metadata and bytes to both implementations.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback

from rea_zip_native_transport import ZipModule, request


FILTERS = ("all", "manifest", "dex", "native_library", "resource",
           "java_class", "signature_marker")


def classic(entries, comment=b"", gap=b"", prefix=b""):
    """Independent fixture writer: explicit classic local/central records."""
    local = bytearray(prefix)
    directory = bytearray()
    for specification in entries:
        name = specification["name"]
        data = specification.get("data", b"")
        flags = specification.get("flags", 0)
        method = specification.get("method", 0)
        crc = specification.get("crc", 0)
        local_extra = specification.get("local_extra", b"")
        central_extra = specification.get("central_extra", b"")
        member_comment = specification.get("comment", b"")
        compressed = specification.get("compressed", len(data))
        uncompressed = specification.get("uncompressed", len(data))
        start = len(local)
        declarations = (0, 0, 0) if flags & 8 else (crc, compressed, uncompressed)
        local += struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, flags, method,
            0, 0, *declarations, len(name), len(local_extra))
        local += name + local_extra + data
        if flags & 8:
            if specification.get("descriptor_signed", True):
                local += b"PK\x07\x08"
            local += struct.pack("<3I", crc, compressed, uncompressed)
        directory += struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20,
            flags, method, 0, 0, crc, compressed, uncompressed,
            len(name), len(central_extra), len(member_comment), 0, 0, 0, start)
        directory += name + central_extra + member_comment
    offset = len(local) + len(gap)
    return bytes(local) + gap + bytes(directory) + struct.pack("<4s4H2IH",
        b"PK\x05\x06", 0, 0, len(entries), len(entries), len(directory),
        offset, len(comment)) + comment


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--oracle", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    events = out / "native-events"
    events.mkdir(mode=0o700)
    script = Path(__file__).read_bytes()
    (out / "qualification-source.py").write_bytes(script)
    manifest = args.manifest.read_bytes()
    (out / "admitted-manifest.json").write_bytes(manifest)
    before = {str(p): {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in [args.oracle, args.manifest,
            args.source / "src/mcp/rea_artifact_zip_parser.rs",
            args.source / "src/mcp/rea_artifact_zip_parser_tests.rs"]}
    (out / "source-pins.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
    cases = []

    def admit(label, data, filter_name="all", offset=0, limit=64, path=None):
        if path is None:
            path = fixtures / (str(len(cases)).zfill(5) + ".zip")
            path.write_bytes(data)
            path.chmod(0o400)
        cases.append({"label": label, "path": str(path), "filter": filter_name,
                      "offset": offset, "limit": limit})

    original_paths = ["tests/fixtures/rea_artifact_sample.zip",
        "tests/fixtures/rea_artifact_sample.jar", "tests/fixtures/rea_artifact_sample.apk",
        "tests/fixtures/rea_application/owned-aapt2.apk"]
    for name in original_paths:
        data = (args.source / name).read_bytes()
        path = fixtures / Path(name).name
        path.write_bytes(data)
        path.chmod(0o400)
        for filter_name in FILTERS:
            for offset, limit in [(0, 1), (0, 256), (1, 1), (999, 64)]:
                admit(name + "/" + filter_name + f"/{offset}/{limit}", None,
                      filter_name, offset, limit, path)

    seed = (args.source / original_paths[0]).read_bytes()
    for index in range(len(seed)):
        for mask in [1, 128, 255]:
            changed = bytearray(seed)
            changed[index] ^= mask
            admit(f"original-byte-mutation/{index}/{mask}", changed)
    for length in range(min(23, len(seed))):
        admit(f"truncated/{length}", seed[:length])
    for length in [1, 2, 19, 20, 21, 22, 23, 40, len(seed) - 1]:
        admit(f"truncated-from-end/{length}", seed[:-length])
    for limit in [0, 1, 64, 256, 257, (1 << 64) - 1]:
        admit(f"page-limit/{limit}", seed, limit=limit)
    for offset in [0, 1, 2, 3, 255, 65535, (1 << 64) - 1]:
        admit(f"page-offset/{offset}", seed, offset=offset, limit=256)

    names = [b"", b"x", b"/x", b"a/../b", b"a/./b", b"C:x", b"z:x",
        b"9:x", b"a//b", b"a/", b"a\\b", b"a\0b", b"a\nb", b"a\tb",
        b'quote"name', b"\x7f", b"\x80", b"\xff", b"\xc0\x80", b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80", "资料/é.txt".encode(), "😀.txt".encode(), b"." , b".."]
    for i, name in enumerate(names):
        for flags in [0, 1 << 11]:
            admit(f"filename/{i}/{flags}", classic([{"name": name, "flags": flags}]))
    role_names = [b"AndroidManifest.xml", b"META-INF/MANIFEST.MF", b"classes.dex",
        b"classes0.dex", b"classes01.dex", b"classesX.dex", b"lib/x.so", b"x.dll",
        b"x.dylib", b"META-INF/X.RSA", b"META-INF/X.DSA", b"META-INF/X.EC",
        b"META-INF/X.SF", b"META-INF/X.sf", b"resources.arsc", b"res/x",
        b"assets/x", b"a.class", b"directory/", b"other"]
    roles = classic([{"name": name, "flags": 1 if i % 3 == 0 else 0}
                     for i, name in enumerate(role_names)], gap=b"uninterpreted signing-block bytes")
    for filter_name in FILTERS:
        for offset, limit in [(0, 1), (0, 256), (1, 2), (20, 1)]:
            admit(f"roles/{filter_name}/{offset}/{limit}", roles, filter_name, offset, limit)
    for comment in [b"", b"x", b"PK\x05\x06" + b"x" * 30, b"x" * 65535]:
        admit(f"eocd-comment/{len(comment)}", classic([{"name": b"a"}], comment=comment))
    for data in [b"", b"\0", b"\0\0", b"\0\0\0", b"\0\0\0\0",
                 b"\xfe\xca\0\0", b"\xfe\xca\x02\0ab", b"\xfe\xca\x03\0ab",
                 b"\x01\0\0\0", b"\x75\x70\0\0"]:
        for key in ["central_extra", "local_extra"]:
            admit(f"extra/{key}/{data.hex()}", classic([{"name": b"a", key: data}]))
    for flags in [0, 1, 8, 9, 64, 65, 0x800, 0x808]:
        for signed in [False, True]:
            admit(f"descriptor/{flags}/{signed}", classic([{"name": b"abc",
                "flags": flags, "descriptor_signed": signed, "crc": 0x78563412,
                "data": b"inert payload"}]))
    for method in [0, 1, 8, 99, 65535]:
        for flags in [0, 1]:
            admit(f"sizes/{method}/{flags}", classic([{"name": b"a", "method": method,
                "flags": flags, "data": b"x", "uncompressed": 19}]))
    admit("empty-archive", classic([]))
    admit("duplicate-name", classic([{"name": b"x"}, {"name": b"x"}]))
    admit("prefix", classic([{"name": b"x"}], prefix=b"not executable"))
    admit("overlay", classic([{"name": b"x"}]) + b"overlay")
    admit("full-name-byte-boundary", classic([{"name": b"a" * 65535}]), limit=1)
    admit("all-variable-fields-boundary", classic([{"name": b"a" * 65535,
        "central_extra": struct.pack("<HH", 0xcafe, 65531) + b"x" * 65531,
        "comment": b"x" * 65535}]), limit=1)

    case_file = out / "cases.json"
    case_file.write_text(json.dumps(cases, sort_keys=True, indent=2) + "\n")
    oracle_err = (out / "oracle.stderr").open("xb")
    oracle = subprocess.Popen([str(args.oracle)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=oracle_err, text=True, bufsize=1)
    module = ZipModule(args.manifest, args.source)
    started = time.monotonic()
    compared = differences = effects = calls = 0
    successful = refused = 0
    try:
        with (out / "observations.jsonl").open("x") as observations, \
             (out / "differences.jsonl").open("x") as difference_log:
            for ordinal, case in enumerate(cases):
                fd = os.open(case["path"], os.O_RDONLY)
                try:
                    wire = request(fd, FILTERS.index(case["filter"]), case["offset"], case["limit"])
                    oracle.stdin.write(json.dumps(case) + "\n")
                    oracle.stdin.flush()
                    line = oracle.stdout.readline()
                    assert line, ("reference ended", oracle.poll())
                    expected = json.loads(line)
                    with (events / f"case-{ordinal:05}.jsonl").open("x") as stream:
                        stream.write(json.dumps({"event": "input", "bytes_hex": wire.hex()}) + "\n")
                        actual = module.invoke(wire, fd, stream)
                    received = ({"ok": True, "value": json.loads(actual["payload"])}
                        if actual["status"] == 0 else {"ok": False, "error": actual["payload"]})
                    equal = expected == received
                    row = {"ordinal": ordinal, "case": case, "equal": equal,
                        "reference": expected, "native": received, "native_effects": actual["effects"],
                        "native_calls": actual["native_calls"], "logical_read_bytes": actual["io_bytes"]}
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
        assert args.manifest.read_bytes() == manifest
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
        failure = {"status": "FAIL", "compared": compared, "differences": differences,
            "error": repr(error), "traceback": traceback.format_exc(),
            "seconds": time.monotonic() - started, "public_route_qualified": False}
        (out / "failure.json").write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        if oracle.poll() is None:
            oracle.terminate()
            oracle.wait(timeout=30)
        oracle_err.close()
        module.close()


if __name__ == "__main__":
    main()
