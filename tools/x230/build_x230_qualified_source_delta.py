#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Preserve and replay an exact qualified-source delta; never builds or deploys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("source symlink refused")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    return result

def put(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"name": path.name, "bytes": len(raw), "sha256": sha(raw)}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("base-qualification", "target-qualification", "output-dir", "reapply-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--prefix", required=True)
    p.add_argument("--base-label", required=True)
    p.add_argument("--candidate", required=True)
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.prefix):
        p.error("simple artifact prefix required")
    raw = [args.base_qualification.read_bytes(), args.target_qualification.read_bytes()]
    reports = [json.loads(value) for value in raw]
    roots = [Path(value["source"]) for value in reports]
    for root, report in zip(roots, reports):
        if (root.resolve() != root or root.is_symlink() or not root.is_dir()
                or report.get("qualified") is not True
                or report["source_tested"] != report["source_after"]
                or snapshot(root) != report["source_tested"]):
            raise RuntimeError("qualified immutable source/file set differs")
    if roots[0].parent != roots[1].parent or roots[0] == roots[1]:
        raise RuntimeError("distinct sibling source directories required")
    if not all(re.fullmatch(r"[A-Za-z0-9_-]+", root.name) for root in roots):
        raise RuntimeError("simple source directory names required")
    if args.reapply_dir.exists() or args.reapply_dir.is_symlink():
        raise RuntimeError("reapply directory must be fresh")
    if any(args.output_dir.resolve().is_relative_to(root) or
           args.reapply_dir.resolve().is_relative_to(root) for root in roots):
        raise RuntimeError("outputs must be outside qualified source")
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = subprocess.run(["git", "diff", "--no-index", "--", roots[0].name, roots[1].name],
                            cwd=roots[0].parent, capture_output=True)
    if result.returncode != 1 or result.stderr:
        raise RuntimeError("expected a nonempty clean source diff")
    lines = []
    for line in result.stdout.decode().splitlines(True):
        if line.startswith(("diff --git ", "--- ", "+++ ")):
            line = line.replace("a/" + roots[0].name + "/", "a/")
            line = line.replace("b/" + roots[1].name + "/", "b/")
        lines.append(line)
    patch_path = args.output_dir / (args.prefix + ".patch")
    patch = put(patch_path, "".join(lines).encode())
    shutil.copytree(roots[0], args.reapply_dir)
    for extra in (["--check"], []):
        checked = subprocess.run(["git", "apply", *extra, "--whitespace=error-all", str(patch_path.resolve())],
                                 cwd=args.reapply_dir, capture_output=True)
        if checked.returncode != 0:
            raise RuntimeError("exact source patch check/apply failed: " + checked.stderr.decode())
    actual = snapshot(args.reapply_dir)
    if actual != reports[1]["source_tested"]:
        raise RuntimeError("replayed source file set or hash differs")
    source_map = put(args.output_dir / (args.prefix + "-source-map.json"), canonical(actual))
    proof = {"schema": "hepta-x230-exact-source-patch/v1", "candidate": args.candidate,
             "base": args.base_label, "adopted": False,
             "base_qualification_report_sha256": sha(raw[0]),
             "target_qualification_report_sha256": sha(raw[1]),
             "source_map_sha256": sha(json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()),
             "source_map_hash_encoding": "sorted compact JSON without trailing newline",
             "source_file_count": len(actual), "exact_file_set_and_all_hashes_match": True,
             "git_apply_check_and_apply_passed": True, "patch": patch, "source_map": source_map,
             "builder_sha256": sha(Path(__file__).read_bytes()),
             "production_service_changes": False}
    receipt = put(args.output_dir / (args.prefix + "-proof.json"), canonical(proof))
    fd = os.open(args.output_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({"patch": patch, "source_map": source_map, "proof": receipt,
                      "source_files_verified": len(actual)}), flush=True)

if __name__ == "__main__":
    main()
