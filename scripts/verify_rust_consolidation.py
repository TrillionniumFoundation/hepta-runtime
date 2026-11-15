#!/usr/bin/env python3
"""Read-only ancestry and exact-blob verification for the Rust consolidation.

This verifies source/history custody, not performance, production adoption,
or completion of the independently preserved native HIA rewrite.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


# This complete cleanup checkpoint includes all current retirement waves. Later work
# may change disposition or add a new manifest, but cannot erase an existing
# source row merely to avoid checking its original object.
RETENTION_INVENTORY_BASELINE = "b81d1b3780eb4a01f0ba0f67b63d52140285538b"


def git(root, *args, check=True, input_bytes=None):
    # Verification must neither substitute local replacement objects nor fetch
    # missing history as a hidden side effect in a partial clone.
    environment = dict(os.environ, GIT_NO_LAZY_FETCH="1")
    result = subprocess.run(["git", "--no-replace-objects", *args], cwd=root,
                            capture_output=True, env=environment, input=input_bytes)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result


def require_history(root):
    if git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true":
        raise RuntimeError("Complete ancestry is required: this is a shallow checkout. "
                           "Fetch the repository history explicitly (for example, "
                           "git fetch --unshallow origin) and rerun. This verifier never fetches.")


def object_id(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise RuntimeError("Invalid Git object identity for " + label)
    return value


def relative_path(value, label):
    if (not isinstance(value, str) or not value or "\\" in value or "\0" in value
            or PurePosixPath(value).is_absolute()
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise RuntimeError("Invalid repository path for " + label)
    return value


def read_tree(root, revision):
    tree = {}
    for row in git(root, "ls-tree", "-rz", revision).stdout.split(b"\0"):
        if row:
            meta, path = row.split(b"\t", 1)
            mode, kind, sha = meta.decode().split()
            tree[path.decode()] = (mode, kind, sha)
    return tree


def blob_sizes(root, identities):
    identities = sorted(set(identities))
    if not identities:
        return {}
    result = git(root, "cat-file", "--batch-check", input_bytes=("\n".join(identities) + "\n").encode())
    rows = result.stdout.decode().splitlines()
    if len(rows) != len(identities):
        raise RuntimeError("Incomplete Git blob availability check")
    sizes = {}
    for identity, row in zip(identities, rows):
        fields = row.split()
        if len(fields) != 3 or fields[:2] != [identity, "blob"] or not fields[2].isdigit():
            raise RuntimeError("Archived blob is unavailable: " + identity
                               + ". Fetch missing objects explicitly and rerun; no automatic fetch is performed.")
        sizes[identity] = int(fields[2])
    return sizes


def verify_inventory_continuity(root, revision, tree, baseline):
    """Keep the cleanup's original custody inventory complete in descendants."""
    baseline = object_id(baseline, "retention inventory baseline")
    git(root, "rev-parse", "--verify", baseline + "^{commit}")
    if git(root, "merge-base", "--is-ancestor", baseline, revision, check=False).returncode:
        if git(root, "merge-base", "--is-ancestor", revision, baseline, check=False).returncode == 0:
            # A caller may explicitly inspect an original pre-cleanup revision.
            # Its v1 materialized custody still gets the ordinary verification.
            return {"retention_inventory_baseline": baseline,
                    "retention_inventory_status": "not_applicable_before_cleanup"}
        raise RuntimeError("Reviewed revision is unrelated to the retention inventory baseline")

    original_tree = read_tree(root, baseline)
    required = sorted(path for path in original_tree
        if (path.startswith("archives/rust-branches/") and path.endswith("/manifest.json")
            and path.count("/") == 3)
        or (path.startswith("archives/repository-history/") and path.endswith(".json")
            and path.count("/") == 2))
    if not required:
        raise RuntimeError("Retention inventory baseline has no custody manifests")
    missing = sorted(set(required) - set(tree))
    if missing:
        raise RuntimeError("Required custody manifests are missing: " + repr(missing))

    checked = 0
    for path in required:
        original = json.loads(git(root, "show", baseline + ":" + path).stdout)
        current = json.loads(git(root, "show", revision + ":" + path).stdout)
        if any(current.get(key) != original.get(key) for key in ("source_commit", "source_tree")):
            raise RuntimeError("Custody inventory source identity changed: " + path)
        historical = path.startswith("archives/repository-history/")
        if historical and current.get("retired_roots") != original.get("retired_roots"):
            raise RuntimeError("Custody inventory retired roots changed: " + path)
        if historical and current.get("retired_files", []) != original.get("retired_files", []):
            raise RuntimeError("Custody inventory retired files changed: " + path)

        def source_rows(data):
            rows = data.get("paths")
            if not isinstance(rows, list):
                raise RuntimeError("Custody inventory paths must be a list: " + path)
            sources = {}
            for row in rows:
                if not isinstance(row, dict):
                    raise RuntimeError("Malformed custody inventory row: " + path)
                name = relative_path(row.get("path"), path + " source path")
                if name in sources:
                    raise RuntimeError("Duplicate custody inventory source path: " + name)
                binding = (row.get("source_blob"), row.get("source_mode"))
                sources[name] = binding + (row.get("bytes"),) if historical else binding
            return sources

        expected, actual = source_rows(original), source_rows(current)
        if actual != expected:
            raise RuntimeError("Custody inventory source rows changed: " + path)
        checked += len(expected)
    return {"retention_inventory_baseline": baseline,
            "retention_inventory_status": "PASS",
            "retention_inventory_manifests": len(required),
            "retention_inventory_source_rows": checked}


def verify_archive_manifests(root, revision, tree):
    """Admit materialized v1 copies and v2 paths retained in reachable history.

    Both forms bind every original path to its original commit tree, mode and
    blob. A v2 history record also names the removed working-tree copy, so it
    cannot quietly turn a missing file into an unchecked retention claim.
    Updated Markdown is an explicit third case: its original remains in
    history and its current documentation path, mode and blob are pinned.
    """
    require_history(root)
    manifests = sorted(path for path in tree
        if path.startswith("archives/rust-branches/") and path.endswith("/manifest.json")
        and path.count("/") == 3)
    materialized, historical, original_paths, documentation = 0, 0, 0, 0
    source_trees = {}
    source_blobs = set()
    documentation_blobs = set()
    for path in manifests:
        data = json.loads(git(root, "show", revision + ":" + path).stdout)
        if data.get("schema") not in {"hepta.rust-branch-consolidation.v1",
                                      "hepta.rust-branch-consolidation.v2"}:
            raise RuntimeError("Unsupported archive schema: " + path)
        if data.get("production_adopted_by_this_merge") is not False:
            raise RuntimeError("Archive incorrectly claims adoption: " + path)
        source = object_id(data.get("source_commit"), path + " source_commit")
        expected_tree = object_id(data.get("source_tree"), path + " source_tree")
        if source not in source_trees:
            original = git(root, "rev-parse", "--verify", source + "^{commit}", check=False)
            if original.returncode:
                raise RuntimeError("Archived source commit is unavailable: " + source
                                   + ". Fetch its complete history explicitly and rerun.")
            ancestry = git(root, "merge-base", "--is-ancestor", source, revision, check=False)
            if ancestry.returncode:
                raise RuntimeError("Archived source is unreachable from the reviewed revision: "
                                   + path + " (" + source + ")")
            actual_tree = git(root, "rev-parse", source + "^{tree}").stdout.decode().strip()
            source_trees[source] = (actual_tree, read_tree(root, source))
        actual_tree, source_paths = source_trees[source]
        if actual_tree != expected_tree:
            raise RuntimeError("Archived source tree differs: " + path)
        rows = data.get("paths")
        if not isinstance(rows, list):
            raise RuntimeError("Archive paths must be a list: " + path)
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("Malformed archive path record: " + path)
            name = relative_path(row.get("path"), path + " source path")
            if name in seen:
                raise RuntimeError("Duplicate archive source path: " + name)
            seen.add(name)
            blob = object_id(row.get("source_blob"), path + " source_blob")
            mode = row.get("source_mode")
            if mode not in {"100644", "100755"}:
                raise RuntimeError("Invalid archived file mode: " + name)
            expected = (mode, "blob", blob)
            if source_paths.get(name) != expected:
                raise RuntimeError("Original source blob or mode differs: " + name)
            # A historical 'already_identical' row can outlive later edits to
            # the active source. Its original object must still be available
            # even when that row never required a separate retained copy.
            source_blobs.add(blob)
            original_paths += 1
            disposition = row.get("disposition")
            if disposition == "original_in_history_with_updated_documentation":
                if (data["schema"] != "hepta.rust-branch-consolidation.v2"
                        or row.get("retained_path") is not None
                        or row.get("previous_disposition") != "import_new_historical_evidence"
                        or not name.endswith(".md")):
                    raise RuntimeError("Invalid updated documentation record: " + name)
                previous = relative_path(row.get("previous_retained_path"),
                                         path + " previous_retained_path")
                target = relative_path(row.get("current_documentation_path"),
                                       path + " current_documentation_path")
                if previous != name or target != previous:
                    raise RuntimeError("Updated documentation path differs from its original: " + name)
                current_blob = object_id(row.get("current_documentation_blob"),
                                         path + " current_documentation_blob")
                current_mode = row.get("current_documentation_mode")
                if (current_mode not in {"100644", "100755"}
                        or tree.get(target) != (current_mode, "blob", current_blob)):
                    raise RuntimeError("Current documentation bytes or mode differ: " + target)
                documentation_blobs.add(current_blob)
                historical += 1
                documentation += 1
                continue
            if disposition == "retained_in_reachable_git_history":
                if (data["schema"] != "hepta.rust-branch-consolidation.v2"
                        or row.get("retained_path") is not None):
                    raise RuntimeError("Invalid history retention record: " + name)
                previous = relative_path(row.get("previous_retained_path"),
                                         path + " previous_retained_path")
                if previous in tree:
                    raise RuntimeError("History-only archive copy is still materialized: " + previous)
                historical += 1
                continue
            if disposition not in {"import_new_historical_evidence", "already_identical",
                                   "retain_exact_variant_outside_active_build"}:
                raise RuntimeError("Unknown archive disposition: " + repr(disposition))
            target = row.get("retained_path")
            if target is None:
                if disposition != "already_identical":
                    raise RuntimeError("Archive retention path is missing: " + name)
                continue
            target = relative_path(target, path + " retained_path")
            if tree.get(target) != expected:
                raise RuntimeError("Retained original bytes or mode differ: " + target)
            materialized += 1
    blob_sizes(root, source_blobs | documentation_blobs)
    return {"archive_manifests": len(manifests), "exact_retained_blob_paths": materialized,
            "history_retained_blob_paths": historical, "updated_documentation_paths": documentation,
            "original_source_paths_checked": original_paths}


def verify_repository_history(root, revision, tree):
    """Verify complete retired directory/file inventories against reachable snapshots."""
    require_history(root)
    manifests = sorted(path for path in tree if path.startswith("archives/repository-history/")
                       and path.endswith(".json") and path.count("/") == 2)
    checked, total_bytes, seen = 0, 0, set()
    for path in manifests:
        data = json.loads(git(root, "show", revision + ":" + path).stdout)
        schema = data.get("schema")
        if schema not in {"hepta.repository-history-retention.v1",
                          "hepta.repository-history-retention.v2"}:
            raise RuntimeError("Unsupported repository history schema: " + path)
        source = object_id(data.get("source_commit"), path + " source_commit")
        expected_tree = object_id(data.get("source_tree"), path + " source_tree")
        original = git(root, "rev-parse", "--verify", source + "^{commit}", check=False)
        if original.returncode:
            raise RuntimeError("Repository history source commit is unavailable: " + source)
        if git(root, "merge-base", "--is-ancestor", source, revision, check=False).returncode:
            raise RuntimeError("Repository history source is unreachable: " + path)
        actual_tree = git(root, "rev-parse", source + "^{tree}").stdout.decode().strip()
        if actual_tree != expected_tree:
            raise RuntimeError("Repository history source tree differs: " + path)
        roots = data.get("retired_roots")
        if (not isinstance(roots, list)
                or (schema == "hepta.repository-history-retention.v1" and not roots)):
            raise RuntimeError("Repository history roots are missing: " + path)
        files = data.get("retired_files", [])
        if schema == "hepta.repository-history-retention.v1" and files != []:
            raise RuntimeError("Retired files require repository history schema v2: " + path)
        if (not isinstance(files, list)
                or (schema == "hepta.repository-history-retention.v2" and "retired_files" not in data)):
            raise RuntimeError("Repository history retired files must be a list: " + path)
        if not roots and not files:
            raise RuntimeError("Repository history retirement selection is empty: " + path)
        normalized = []
        for value in roots:
            if not isinstance(value, str) or not value.endswith("/"):
                raise RuntimeError("Retired root must be a directory path: " + path)
            normalized.append(relative_path(value[:-1], path + " retired root") + "/")
        if (len(normalized) != len(set(normalized))
                or any(a != b and a.startswith(b) for a in normalized for b in normalized)):
            raise RuntimeError("Duplicate or overlapping repository history roots: " + path)
        files = [relative_path(name, path + " retired file") for name in files]
        if (len(files) != len(set(files))
                or any(name.startswith(prefix) or prefix.startswith(name + "/")
                       for name in files for prefix in normalized)):
            raise RuntimeError("Duplicate or overlapping repository history retired files: " + path)
        source_tree = read_tree(root, source)
        expected_paths = {name for name in source_tree if any(name.startswith(r) for r in normalized)}
        if any(not any(name.startswith(r) for name in expected_paths) for r in normalized):
            raise RuntimeError("Repository history root is absent from the source: " + path)
        if any(name not in source_tree for name in files):
            raise RuntimeError("Repository history retired file is absent from the source: " + path)
        expected_paths.update(files)
        rows = data.get("paths")
        if not isinstance(rows, list):
            raise RuntimeError("Repository history paths must be a list: " + path)
        selected, byte_count, blobs = set(), 0, {}
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("Malformed repository history path: " + path)
            name = relative_path(row.get("path"), path + " retired path")
            if name in selected or name in seen:
                raise RuntimeError("Duplicate repository history path: " + name)
            selected.add(name)
            blob = object_id(row.get("source_blob"), name + " source_blob")
            mode = row.get("source_mode")
            if mode not in {"100644", "100755"} or source_tree.get(name) != (mode, "blob", blob):
                raise RuntimeError("Repository history blob or mode differs: " + name)
            if name in tree:
                raise RuntimeError("Retired repository path is still materialized: " + name)
            size = row.get("bytes")
            if type(size) is not int or size < 0:
                raise RuntimeError("Invalid repository history byte count: " + name)
            if blob in blobs and blobs[blob] != size:
                raise RuntimeError("Conflicting repository history blob sizes: " + name)
            blobs[blob] = size
            byte_count += size
        if selected != expected_paths:
            raise RuntimeError("Repository history inventory is incomplete or outside its selection: " + path)
        if (type(data.get("file_count")) is not int or data["file_count"] != len(rows)
                or type(data.get("byte_count")) is not int or data["byte_count"] != byte_count):
            raise RuntimeError("Repository history totals differ: " + path)
        if blob_sizes(root, blobs) != blobs:
            raise RuntimeError("Repository history object sizes differ: " + path)
        seen.update(selected)
        checked += len(rows)
        total_bytes += byte_count
    return {"repository_history_manifests": len(manifests), "repository_history_files": checked,
            "repository_history_bytes": total_bytes}


def verify(root, revision):
    require_history(root)
    revision = git(root, "rev-parse", "--verify", "--end-of-options",
                   revision + "^{commit}").stdout.decode().strip()
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
    tree = read_tree(root, revision)
    if any(path.startswith("native/") for path in tree):
        raise RuntimeError("Native rewrite directory was included in Rust main")
    inventory_result = verify_inventory_continuity(root, revision, tree,
                                                 RETENTION_INVENTORY_BASELINE)
    archive_result = verify_archive_manifests(root, revision, tree)
    history_result = verify_repository_history(root, revision, tree)
    study = "qualification/weightspace-rs-study-20261110"
    original = "6df5e92cf5fb2cb470d9f2341548d4ac07d22f69"
    if git(root, "diff", "--exit-code", original, revision, "--", study, check=False).returncode:
        raise RuntimeError("Standalone weightspace study bytes changed")
    return {"schema": "hepta.rust-consolidation-verification.v2", "revision": revision,
        "original_branches": len(branches), "integrated_rust_refs": len(required),
        "protected_refs": len(preserved), "protected_rewrites_included": included_rewrites,
        **inventory_result,
        **archive_result,
        **history_result,
        "standalone_study_unchanged": True, "native_rewrite_directory_included": False,
        "status": "PASS", "scope": "Ancestry and exact source custody only; no production qualification"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    print(json.dumps(verify(args.repo, args.revision), indent=2))
