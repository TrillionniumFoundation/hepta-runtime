#!/usr/bin/env python3
"""Verify the HIA integration's real ancestry and retained source objects.

This is a source/history check. It cannot establish behavior parity, live
adoption, completion of remaining frontiers, or eligibility to retire a runtime.
The original Rust-only verifier and all its archive controls remain unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

_HERE = Path(__file__).resolve().parent
_LEGACY_PATH = _HERE / "verify_rust_consolidation.py"
_LEGACY_SHA256 = "4c76d6d29811b47846c3a0c9b700aa3c007e701058aaa3ebe49704927a0d5999"
if hashlib.sha256(_LEGACY_PATH.read_bytes()).hexdigest() != _LEGACY_SHA256:
    raise RuntimeError("Original archive verifier implementation changed")
_spec = importlib.util.spec_from_file_location("_hia_original_archive_custody", _LEGACY_PATH)
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)

PLAN = "docs/qualification/hia-complete-runtime-plan-20261128/"
BRANCHES = "docs/audits/rust-main-20261115/branches-before.json"
PRESERVED = "docs/audits/rust-main-20261115/preserved-hia-refs.json"
INTEGRATION = PLAN + "frontier-integration.json"
LEDGER = PLAN + "frontier-merges.json"
DOMAIN_PLAN = PLAN + "domain-plan-input.json"
NATIVE_MANIFEST = "native/runtime_mcp_sources.json"
# These are independently retained, exact historical inputs. Their assertions
# are checked against real objects below, not accepted as execution evidence.
AUTHORITY_PINS = {
    BRANCHES: (22408, "eee61d1bd86667d3ab460fbb9407fb4d57b45da26e35c109787298316c4654a5",
               "84c9f6e8eecd74fa9fca3dcaa5b49eb4da227088"),
    PRESERVED: (1529, "e23cc457460d96b1e70323d00e53daacc3247dca1a43ec2b6e6bd556f48bac4f",
                "45aa8d3e1b7134a782e60036a0e5a08ac2a32405"),
    INTEGRATION: (699, "012eb2677238f0f20b279fb4ed7f5d7260ef6de5f0d26d9460fa54569076613e",
                  "481c3db4abe5bf93239a9712c6dcb87663dc212c"),
    LEDGER: (99462, "d573654304eccefb22a77bf2818948f2f0b218a91c4ba5aea47e4fc2ecadd7cb",
             "40926ff9e9287bd794637455635cb82c1091a5ea"),
    DOMAIN_PLAN: (17891, "018c2ed744ec5c67babc8cfa671014b77c123857c36810a24085917bc66af53e",
                  "86bd9544c5671ec7bda46aad85e6e693403afed5"),
}
NATIVE_MANIFEST_PIN = (
    129644, "280261f2df19a9b0ba988b984ddf8d70e3c77efe68c7a908cb9348db952a1cb7",
    "bdde952545e346df1f8a8b68d3e9975c58a88b34")
ORIGINAL_CONTROL_BLOBS = {
    "scripts/verify_rust_consolidation.py": "80944df6e3ee4dbd9e8fdfdf850b928998815552",
    "scripts/test_verify_rust_consolidation.py": "3370e30dd1b95f4d49f3fbfe166961681e2e8ed9",
}
STUDY_PATH = "qualification/weightspace-rs-study-20261110"
STUDY_COMMIT = "6df5e92cf5fb2cb470d9f2341548d4ac07d22f69"


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def pinned_json(root, revision, tree, path, expected):
    """Read the reviewed Git object, never a candidate's rewritten expected pin."""
    legacy.relative_path(path, "authority")
    size, digest, blob = expected
    require(tree.get(path) == ("100644", "blob", blob),
            "Fixed source authority blob or mode differs: " + path)
    raw = legacy.git(root, "cat-file", "blob", blob).stdout
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
            "Fixed source authority bytes differ: " + path)
    return json.loads(raw)


def commit_metadata(root, revision):
    revision = legacy.object_id(revision, "source commit")
    result = legacy.git(root, "cat-file", "commit", revision, check=False)
    require(result.returncode == 0, "Source commit is unavailable: " + revision)
    header = result.stdout.split(b"\n\n", 1)[0].splitlines()
    trees = [line[5:].decode("ascii") for line in header if line.startswith(b"tree ")]
    parents = [line[7:].decode("ascii") for line in header if line.startswith(b"parent ")]
    require(len(trees) == 1, "Source commit has no unique tree: " + revision)
    legacy.object_id(trees[0], "source tree")
    for parent in parents:
        legacy.object_id(parent, "source parent")
    return {"tree": trees[0], "parents": parents}


def is_ancestor(root, ancestor, descendant):
    result = legacy.git(root, "merge-base", "--is-ancestor", ancestor, descendant, check=False)
    require(result.returncode in (0, 1), "Ancestry check failed: " + ancestor)
    return result.returncode == 0


def require_ancestor(root, ancestor, revision):
    commit_metadata(root, ancestor)
    require(is_ancestor(root, ancestor, revision),
            "Required source commit is not an ancestor: " + ancestor)


def verify_branch_ancestry(root, revision, branches, preserved):
    require(isinstance(branches, list) and isinstance(preserved, list),
            "Original branch inventories must be lists")
    names = [row["name"] for row in branches]
    excluded = [row["name"] for row in preserved]
    require(len(names) == len(set(names)) and len(excluded) == len(set(excluded))
            and set(excluded) <= set(names), "Original branch inventory is incomplete or duplicated")
    required = [row for row in branches if row["name"] not in set(excluded)]
    native = [row for row in preserved if row["kind"] == "native_hia_rewrite"]
    frozen = [row for row in preserved if row["kind"] == "frozen_hia_pr_base"]
    require(len(native) + len(frozen) == len(preserved) and len(frozen) == 1,
            "Preserved source categories changed")
    original = {row["name"]: row["sha"] for row in branches}
    for row in preserved:
        require(original[row["name"]] == row["sha"], "Preserved original branch identity changed")
    for row in required + native + frozen:
        require_ancestor(root, legacy.object_id(row["sha"], row["name"]), revision)
    return {"original_branches": len(branches), "integrated_rust_refs": len(required),
            "integrated_native_hia_refs": len(native), "frozen_hia_bases_preserved": len(frozen)}


def verify_frontier_history(root, revision, integration, ledger):
    require(integration.get("schema") == "hepta.runtime.normal-frontier-integration.v1",
            "Frontier integration schema changed")
    require(ledger.get("qualification_transferred") is False
            and integration.get("physical_sources_qualified_here") is False
            and integration.get("history_rewritten") is False,
            "Source integration cannot transfer execution qualification or rewrite history")
    current = legacy.object_id(integration["initial_candidate"], "initial candidate")
    final = legacy.object_id(integration["merged_head"], "integrated frontier head")
    require(ledger.get("initial_head") == current and ledger.get("head") == final,
            "Frontier endpoint identities disagree")
    require_ancestor(root, current, revision)
    require_ancestor(root, final, revision)
    require_ancestor(root, integration["native_source_base"], current)
    merges, remaining = ledger.get("merges"), ledger.get("remaining")
    require(isinstance(merges, list) and isinstance(remaining, list),
            "Complete frontier inventories are missing")
    require(type(integration.get("normal_merges")) is int
            and type(integration.get("unresolved_frontiers")) is int
            and type(integration.get("independent_frontiers")) is int,
            "Frontier counts must be integers")
    require(len(remaining) == integration["unresolved_frontiers"]
            and len(merges) + len(remaining) == integration["independent_frontiers"],
            "Complete frontier inventory count changed")
    normal, already = 0, 0
    checkpoints, seen = {current}, set()
    for row in merges:
        require(isinstance(row, dict), "Malformed frontier merge row")
        incoming = legacy.object_id(row.get("incoming"), "incoming frontier")
        require(incoming not in seen, "Duplicate frontier input")
        seen.add(incoming)
        require(row.get("before") == current, "Frontier merge chain is discontinuous")
        require(isinstance(row.get("refs"), list) and bool(row["refs"])
                and all(isinstance(name, str) and name.startswith("refs/") for name in row["refs"]),
                "Frontier reference names are missing")
        commit_metadata(root, incoming)
        if row.get("status") == "already-ancestor":
            require(is_ancestor(root, incoming, current),
                    "An unmerged frontier was declared already-ancestor")
            already += 1
            continue
        require(row.get("status") == "normal-two-parent-merge", "Unknown frontier merge status")
        head = legacy.object_id(row.get("head"), "frontier merge head")
        metadata = commit_metadata(root, head)
        require(metadata["parents"] == [current, incoming],
                "Frontier merge does not have the exact two ordered parents")
        require(metadata["tree"] == row.get("tree"), "Frontier merge tree differs")
        require_ancestor(root, head, revision)
        current = head
        checkpoints.add(current)
        normal += 1
    require(current == final and normal == integration["normal_merges"],
            "Frontier terminal head or normal merge count differs")
    available, now_integrated = 0, 0
    for row in remaining:
        require(isinstance(row, dict) and row.get("status") == "conflict-needs-source-review",
                "Unresolved frontier status changed")
        incoming = legacy.object_id(row.get("incoming"), "unresolved frontier")
        require(incoming not in seen, "Duplicate frontier input")
        seen.add(incoming)
        require(row.get("before") in checkpoints, "Unresolved frontier baseline is outside the merge chain")
        require(isinstance(row.get("refs"), list) and bool(row["refs"])
                and all(isinstance(name, str) and name.startswith("refs/") for name in row["refs"]),
                "Unresolved frontier reference names are missing")
        require(isinstance(row.get("paths"), list) and bool(row["paths"]),
                "Unresolved frontier conflict inventory is missing")
        for path in row["paths"]:
            legacy.relative_path(path, "unresolved conflict")
        metadata = commit_metadata(root, incoming)
        require(legacy.git(root, "cat-file", "-t", metadata["tree"]).stdout.strip() == b"tree",
                "Unresolved original source tree is unavailable")
        available += 1
        now_integrated += int(is_ancestor(root, incoming, revision))
    return {"frontier_initial_candidate": ledger["initial_head"], "frontier_merged_head": final,
            "normal_two_parent_merges": normal, "already_ancestor_frontiers": already,
            "retained_unresolved_frontier_commits": available,
            "formerly_unresolved_now_ancestors": now_integrated,
            "unresolved_frontiers_still_outside_revision": available - now_integrated}


def verify_native_sources(root, source, merged, manifest, count):
    require(manifest.get("schema") == "hepta.runtime.public-source-closure.v2",
            "Original native source manifest schema differs")
    sources = manifest.get("sources")
    require(type(count) is int and count > 0 and isinstance(sources, dict)
            and len(sources) == count, "Original native source inventory is incomplete")
    original_tree, merged_tree = legacy.read_tree(root, source), legacy.read_tree(root, merged)
    objects = {}
    for name, identity in sources.items():
        legacy.relative_path(name, "original native source")
        require(isinstance(identity, dict) and type(identity.get("bytes")) is int
                and identity["bytes"] >= 0
                and isinstance(identity.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]) is not None,
                "Invalid original native byte identity: " + name)
        entry = original_tree.get(name)
        require(entry is not None and entry[0] in {"100644", "100755"} and entry[1] == "blob",
                "Original native source path or mode is unavailable: " + name)
        require(merged_tree.get(name) == entry, "Integrated original native object or mode differs: " + name)
        require(entry[2] not in objects or objects[entry[2]] == identity,
                "Conflicting original native blob identity: " + name)
        objects[entry[2]] = identity
    sizes = legacy.blob_sizes(root, objects)
    for blob, identity in objects.items():
        require(sizes[blob] == identity["bytes"], "Original native object size differs: " + blob)
        raw = legacy.git(root, "cat-file", "blob", blob).stdout
        require(len(raw) == identity["bytes"] and hashlib.sha256(raw).hexdigest() == identity["sha256"],
                "Original native object digest differs: " + blob)
    return {"native_source_base": source, "native_objects_verified_at": merged,
            "original_native_binding_paths": count, "original_native_unique_blobs": len(objects),
            "original_native_objects_preserved": True}


def verify(root, revision):
    legacy.require_history(root)
    revision = legacy.git(root, "rev-parse", "--verify", "--end-of-options",
                          revision + "^{commit}").stdout.decode().strip()
    tree = legacy.read_tree(root, revision)
    for path, blob in ORIGINAL_CONTROL_BLOBS.items():
        require(tree.get(path) == ("100644", "blob", blob),
                "Original source custody control changed: " + path)
    inputs = {path: pinned_json(root, revision, tree, path, pin)
              for path, pin in AUTHORITY_PINS.items()}
    integration, plan = inputs[INTEGRATION], inputs[DOMAIN_PLAN]
    branch_report = verify_branch_ancestry(root, revision, inputs[BRANCHES], inputs[PRESERVED])
    frontier_report = verify_frontier_history(root, revision, integration, inputs[LEDGER])
    native_source, merged = integration["native_source_base"], integration["merged_head"]
    manifest = pinned_json(root, native_source, legacy.read_tree(root, native_source),
                           NATIVE_MANIFEST, NATIVE_MANIFEST_PIN)
    pinned_json(root, merged, legacy.read_tree(root, merged), NATIVE_MANIFEST, NATIVE_MANIFEST_PIN)
    native_report = verify_native_sources(root, native_source, merged, manifest,
                                          integration["original_native_binding_paths"])
    require(plan["imported_native_source"] == native_source
            and plan["registered_target_handlers"] == 136
            and len(plan["qualified_route_names"]) == 13 and plan["remaining_handlers"] == 123
            and plan["production_activated"] is False and plan["old_stack_removal_qualified"] is False,
            "Original incomplete runtime plan was relabelled as deployment evidence")
    require(any(path.startswith("native/") for path in tree), "Integrated native source directory is missing")
    inventory = legacy.verify_inventory_continuity(root, revision, tree,
                                                   legacy.RETENTION_INVENTORY_BASELINE)
    archives = legacy.verify_archive_manifests(root, revision, tree)
    history = legacy.verify_repository_history(root, revision, tree)
    require(legacy.git(root, "diff", "--exit-code", STUDY_COMMIT, revision, "--",
                       STUDY_PATH, check=False).returncode == 0,
            "Standalone weightspace study bytes changed")
    return {"schema": "hepta.hia-consolidation-source-verification.v1",
            "revision": revision, "status": "PASS",
            "scope": "Real ancestry and exact historical source objects only",
            "fixed_authorities": {path: {"bytes": pin[0], "sha256": pin[1], "git_blob": pin[2]}
                                  for path, pin in AUTHORITY_PINS.items()},
            **branch_report, **frontier_report, **native_report, **inventory, **archives, **history,
            "standalone_study_unchanged": True, "native_source_directory_included": True,
            "runtime_execution_qualified_here": False, "production_activated_here": False,
            "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
            "branch_deletion_qualified": False, "history_rewritten": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=_HERE.parent)
    parser.add_argument("--revision", default="HEAD")
    options = parser.parse_args()
    print(json.dumps(verify(options.repo, options.revision), indent=2))
