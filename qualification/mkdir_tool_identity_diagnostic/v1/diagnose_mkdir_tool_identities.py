#!/usr/bin/env python3
"""Read-only host comparison for an authenticated historical mkdir build receipt."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HELPER = "scripts/hia_native_shell_process_reference.py"
HELPER_SHA256 = "d825520f8edc3dafb01abe86426c3fa4cf476eeb0e6c2dd1f105c970261240cc"
SCHEMA = "hepta.runtime.shell-capture-mkdir-original-build.v1"
ROLES = ("rustc", "linker", "ld", "interpreter")
FIELDS = ("launch_path", "resolved_path", "bytes", "sha256")
DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch


def read_limited(path, maximum):
    with path.open("rb") as fp:
        raw = fp.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("diagnostic input exceeds size bound")
    return raw


def load_reference(runtime):
    path = runtime / HELPER
    raw = read_limited(path, 4 << 20)
    if hashlib.sha256(raw).hexdigest() != HELPER_SHA256:
        raise ValueError("pinned Runtime #140 helper bytes do not match")
    spec = importlib.util.spec_from_file_location("runtime_140_diagnostic_helper", path)
    module = importlib.util.module_from_spec(spec)
    # Execute the exact verified Python helpers without writing .pyc or
    # following a second file open. No examined tool is executed.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def expected_identities(ref, receipt, digest):
    raw = read_limited(receipt, 16 << 20)
    if not DIGEST(digest) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("historical result.json SHA-256 does not match")
    result = ref.decode(raw)
    if (type(result) is not dict or result.get("schema") != SCHEMA
            or result.get("status") != "PASS" or "error" not in result
            or result["error"] is not None):
        raise ValueError("original build receipt status or schema is invalid")
    expected = result.get("tools")
    if type(expected) is not dict or set(expected) != set(ROLES):
        raise ValueError("original receipt has the wrong tool roster")
    for role, row in expected.items():
        if (type(row) is not dict or set(row) != set(FIELDS)
                or any(type(row[field]) is not str or not row[field].startswith("/")
                       or len(row[field]) > 4096 for field in FIELDS[:2])
                or type(row["bytes"]) is not int or not 0 <= row["bytes"] < (1 << 63)
                or type(row["sha256"]) is not str or not DIGEST(row["sha256"])):
            raise ValueError("invalid original tool identity: " + role)
    return expected


def compare(ref, expected, paths):
    actual, differences, unavailable = {}, {}, {}
    for role, path in zip(ROLES, paths, strict=True):
        try:
            actual[role] = ref.tool_identity(path)
        except (OSError, ValueError, RuntimeError) as error:
            unavailable[role] = {"launch_path": str(path), "error_type": type(error).__name__}
            continue
        changed = {field: {"expected": expected[role][field], "actual": actual[role][field]}
                   for field in FIELDS
                   if ref.canonical(expected[role][field]) != ref.canonical(actual[role][field])}
        if changed:
            differences[role] = changed
    match = ref.canonical(expected) == ref.canonical(actual) and not unavailable
    return {"status": "MATCH" if match else "MISMATCH", "differences": differences,
            "unavailable": unavailable, "qualification_performed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True,
                        help="SHA-256 of result.json from the authenticated original STATE ZIP")
    parser.add_argument("--rustc", type=Path, required=True,
                        help="Explicit result of rustup which --toolchain 1.95.0 rustc on the observed host")
    parser.add_argument("--linker", type=Path, default=Path("/usr/bin/cc"))
    args = parser.parse_args(argv)
    try:
        ref = load_reference(args.runtime)
        expected = expected_identities(ref, args.receipt, args.receipt_sha256)
        paths = (args.rustc, args.linker, Path("/usr/bin/ld"), Path("/lib64/ld-linux-x86-64.so.2"))
        result = compare(ref, expected, paths)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "MATCH" else 1
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "INVALID_INPUT", "error": type(error).__name__,
                          "qualification_performed": False}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
