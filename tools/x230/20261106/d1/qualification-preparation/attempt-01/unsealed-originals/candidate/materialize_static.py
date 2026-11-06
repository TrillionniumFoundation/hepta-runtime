#!/usr/bin/env python3
"""Verify/materialize exact diagnostic preparation sources; never invoke Cargo.

Optional --output creates a new private directory. Any partial output is kept.
This is a static preparation tool, not qualification or benchmark execution.
"""
import argparse
import ast
import hashlib
import json
import os
import re
import stat
import tomllib
from pathlib import Path, PurePosixPath

MAX_FILE = 16 * 1024 * 1024
BASELINE_MAP_SHA256 = "c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd"
BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stamp(value):
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def regular(path, limit=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        original = os.fstat(fd)
        require(stat.S_ISREG(original.st_mode) and original.st_size <= limit, "bounded regular input required: " + str(path))
        parts, total = [], 0
        while True:
            data = os.read(fd, min(65536, limit + 1 - total))
            if not data:
                break
            total += len(data)
            require(total <= limit, "input grew beyond limit")
            parts.append(data)
        require(total == original.st_size, "input length changed")
        require(stamp(os.fstat(fd)) == stamp(original), "input descriptor changed")
        require(stamp(os.stat(path, follow_symlinks=False)) == stamp(original), "input pathname changed")
        return b"".join(parts)
    finally:
        os.close(fd)


def relative(value):
    path = PurePosixPath(value)
    require(isinstance(value, str) and value and str(path) == value
            and not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts),
            "noncanonical package path")
    return Path(*path.parts)


def read_pinned(root, row):
    data = regular(root / relative(row["path"]))
    require(len(data) == row["bytes"] and sha(data) == row["sha256"], "package input identity mismatch: " + row["path"])
    return data


def write_new(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            require(count > 0, "zero-length output write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def apply_unified(patch, originals):
    lines = patch.decode("utf-8").splitlines()
    index = 0
    output = {}
    while index < len(lines):
        header = re.fullmatch(r"diff --git a/(.+) b/(.+)", lines[index])
        require(header is not None and header[1] == header[2], "invalid patch header")
        path = header[1]
        relative(path)
        require(path not in output, "duplicate patch path")
        original = originals.get(path, b"")
        require(not original or original.endswith(b"\n"), "baseline source lacks final LF")
        old = original.decode("utf-8").splitlines()
        index += 1
        expected_old = "--- " + ("a/" + path if path in originals else "/dev/null")
        expected_new = "+++ b/" + path
        headers = []
        while index < len(lines) and not lines[index].startswith("@@ "):
            require(not lines[index].startswith("diff --git "), "patch path has no hunks")
            headers.append(lines[index])
            index += 1
        require(expected_old in headers and expected_new in headers, "patch file markers disagree")
        retained, consumed = [], 0
        while index < len(lines) and lines[index].startswith("@@ "):
            hunk = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", lines[index])
            require(hunk is not None, "invalid hunk")
            a, count_a, b, count_b = map(int, hunk.groups())
            a -= bool(count_a)
            b -= bool(count_b)
            require(consumed <= a <= len(old), "hunk order invalid")
            retained.extend(old[consumed:a])
            consumed = a
            require(len(retained) == b, "hunk candidate offset invalid")
            index += 1
            seen_a = seen_b = 0
            while seen_a < count_a or seen_b < count_b:
                require(index < len(lines) and lines[index], "hunk unexpectedly ended")
                kind, value = lines[index][0], lines[index][1:]
                require(kind in (" ", "-", "+"), "invalid hunk operation")
                index += 1
                if kind in (" ", "-"):
                    require(consumed < len(old) and old[consumed] == value, "patch baseline context mismatch")
                    consumed += 1
                    seen_a += 1
                if kind in (" ", "+"):
                    retained.append(value)
                    seen_b += 1
            require((seen_a, seen_b) == (count_a, count_b), "hunk count invalid")
        retained.extend(old[consumed:])
        output[path] = ("\n".join(retained) + "\n").encode()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--baseline-root", required=True)
    parser.add_argument("--output", help="create-only static source tree; omitted means read-only checks")
    args = parser.parse_args()
    package = Path(args.package_root)
    base = Path(args.baseline_root)
    require(package.is_absolute() and base.is_absolute(), "absolute input roots required")
    manifest_raw = regular(package / "package-manifest.json")
    require(sha(manifest_raw) == args.expected_manifest_sha256, "manifest differs from supplied exact pin")
    manifest = json.loads(manifest_raw)
    require(manifest["schema"] == "hepta-r24-phase-cost-preparation-package/v1", "package schema mismatch")
    require(manifest["revision"] == "recovery-02" and manifest["baseline_commit"] == BASELINE_COMMIT, "package baseline mismatch")
    rows = manifest["files"]
    require(len({row["path"] for row in rows}) == len(rows), "duplicate package member")
    contents = {row["path"]: read_pinned(package, row) for row in rows}
    base_map_raw = contents["baseline-source-map.json"]
    require(sha(base_map_raw) == BASELINE_MAP_SHA256, "accepted R24 map identity mismatch")
    base_map = json.loads(base_map_raw)
    candidate_map = json.loads(contents["candidate-source-map.json"])
    declaration = json.loads(contents["input.json"])
    require(declaration["baseline_commit"] == BASELINE_COMMIT, "input baseline mismatch")
    require(declaration["baseline_compile_inputs"] == base_map
            and declaration["candidate_compile_inputs"] == candidate_map, "input source maps disagree")
    require(len(base_map) == 220 and len(candidate_map) == 222, "source cardinality changed")
    require(set(base_map) <= set(candidate_map), "baseline compile input removed")
    require(set(candidate_map) - set(base_map) == {
        "src/mcp/runtime/phase_cost.rs", "src/mcp/runtime/phase_cost_tests.rs",
    }, "unexpected new compile path")
    originals = {path: regular(base / relative(path)) for path in base_map}
    require(all(sha(originals[path]) == digest for path, digest in base_map.items()), "accepted source bytes differ")
    expected_changes = sorted(path for path, digest in candidate_map.items() if base_map.get(path) != digest)
    require(declaration["changed_paths"] == expected_changes and len(expected_changes) == 13, "candidate path declaration differs")
    patched = apply_unified(contents["candidate.patch"], originals)
    require(sorted(patched) == expected_changes, "patch path set differs")
    require(sha(contents["candidate.patch"]) == declaration["patch_sha256"], "patch identity differs")
    all_sources = dict(originals)
    for path in expected_changes:
        raw = contents["source/" + path]
        require(raw == patched[path], "full candidate file differs from applied patch: " + path)
        all_sources[path] = raw
    require({path: sha(raw) for path, raw in sorted(all_sources.items())} == candidate_map, "complete candidate map differs")
    old_cargo = tomllib.loads(originals["Cargo.toml"].decode())
    new_cargo = tomllib.loads(all_sources["Cargo.toml"].decode())
    feature = new_cargo.pop("features", None)
    require(feature == {"phase-cost-diagnostics": []} and old_cargo == new_cargo, "Cargo graph/profile changed beyond opt-in feature")
    require(all_sources["Cargo.lock"] == originals["Cargo.lock"], "lock changed")
    ast_paths = sorted(path for path in contents if path.endswith(".py"))
    for path in ast_paths:
        ast.parse(contents[path].decode("utf-8"), filename=path)
    # Re-read pinned inputs after preparation. This proves no source drift in
    # this interval, not a future compiler invocation or runtime lifetime.
    require(all(sha(regular(base / relative(path))) == digest for path, digest in base_map.items()), "accepted baseline changed during static preparation")
    require(all(read_pinned(package, row) == contents[row["path"]] for row in rows), "package changed during static preparation")
    report = {
        "schema": "hepta-r24-phase-cost-static-materialization/v1",
        "revision": "recovery-02",
        "manifest_sha256": sha(manifest_raw),
        "baseline_commit": BASELINE_COMMIT,
        "baseline_count": 220, "candidate_count": 222,
        "changed_paths": expected_changes,
        "candidate_compile_inputs": candidate_map,
        "python_ast_parsed": ast_paths,
        "source_patch_roundtrip": True,
        "dependencies_lock_and_release_profile_unchanged": True,
        "rust_compiled": False, "rustfmt_run": False,
        "rust_tests_run": False, "diagnostic_executed": False,
        "performance_acceptance_claim": False,
        "output": args.output,
    }
    if args.output:
        destination = Path(args.output)
        require(destination.is_absolute(), "absolute new output root required")
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for path, raw in sorted(all_sources.items()):
            write_new(destination / "source" / relative(path), raw)
        report["output_source_bytes_verified"] = all(
            regular(destination / "source" / relative(path)) == raw
            for path, raw in all_sources.items()
        )
        require(report["output_source_bytes_verified"], "new static source bytes differ")
        write_new(destination / "static-materialization.json",
                  (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
