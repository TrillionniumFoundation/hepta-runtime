#!/usr/bin/env python3
"""Read-only ancestry and exact-blob verification for the Rust consolidation.

This verifies source/history custody, not performance, production adoption,
or completion of the independently preserved native HIA rewrite.
"""
import argparse
import json
from pathlib import Path
import subprocess


def git(root, *args, check=True):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result


def verify(root, revision):
    revision = git(root, "rev-parse", "--verify", revision + "^{commit}").stdout.decode().strip()
    inventory_path = "docs/audits/rust-main-20261115/branches-before.json"
    preserved_path = "docs/audits/rust-main-20261115/preserved-hia-refs.json"
    branches = json.loads(git(root, "show", revision + ":" + inventory_path).stdout)
    preserved = json.loads(git(root, "show", revision + ":" + preserved_path).stdout)
    excluded = {row["name"] for row in preserved}
    required = [row for row in branches if row["name"] not in excluded]
    missing = [row["name"] for row in required
               if git(root, "merge-base", "--is-ancestor", row["sha"], revision, check=False).returncode]
    if missing:
        raise RuntimeError("Unintegrated Rust branches: " + repr(missing))
    included_rewrites = [row["name"] for row in preserved if row["kind"] == "native_hia_rewrite"
        and git(root, "merge-base", "--is-ancestor", row["sha"], revision, check=False).returncode == 0]
    if included_rewrites:
        raise RuntimeError("Protected HIA rewrite was included: " + repr(included_rewrites))
    tree = {}
    for row in git(root, "ls-tree", "-rz", revision).stdout.split(b"\0"):
        if row:
            meta, path = row.split(b"\t", 1)
            mode, kind, sha = meta.decode().split()
            tree[path.decode()] = (mode, kind, sha)
    if any(path.startswith("native/") for path in tree):
        raise RuntimeError("Native rewrite directory was included in Rust main")
    manifests = sorted(path for path in tree
        if path.startswith("archives/rust-branches/") and path.endswith("/manifest.json")
        and path.count("/") == 3)
    checked = 0
    for path in manifests:
        data = json.loads(git(root, "show", revision + ":" + path).stdout)
        if data["production_adopted_by_this_merge"] is not False:
            raise RuntimeError("Archive incorrectly claims adoption: " + path)
        if git(root, "merge-base", "--is-ancestor", data["source_commit"], revision, check=False).returncode:
            raise RuntimeError("Archived source is unreachable: " + path)
        for row in data["paths"]:
            target = row.get("retained_path")
            if target is None:
                continue
            actual = tree.get(target)
            if actual != (row["source_mode"], "blob", row["source_blob"]):
                raise RuntimeError("Retained original bytes differ: " + target)
            checked += 1
    study = "qualification/weightspace-rs-study-20261110"
    original = "6df5e92cf5fb2cb470d9f2341548d4ac07d22f69"
    if git(root, "diff", "--exit-code", original, revision, "--", study, check=False).returncode:
        raise RuntimeError("Standalone weightspace study bytes changed")
    return {"schema": "hepta.rust-consolidation-verification.v1", "revision": revision,
        "original_branches": len(branches), "integrated_rust_refs": len(required),
        "protected_refs": len(preserved), "protected_rewrites_included": included_rewrites,
        "archive_manifests": len(manifests), "exact_retained_blob_paths": checked,
        "standalone_study_unchanged": True, "native_rewrite_directory_included": False,
        "status": "PASS", "scope": "Ancestry and exact source custody only; no production qualification"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    print(json.dumps(verify(args.repo, args.revision), indent=2))
