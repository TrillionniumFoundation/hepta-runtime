"""Bind migration coverage to a production target, retaining old comparison pins.

This source reader does not execute native code or qualify production behavior.
An independently supplied target checkout must match the complete source tree.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "native/migration_target.json"
SCHEMA = "hepta.runtime.hia-migration-target.v1"
GIT_ID = re.compile(r"[0-9a-f]{40}\Z")
TOOL = re.compile(r"#\[tool\(.*?\)\]\s*async fn (\w+)", re.S)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def _json(raw):
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _regular(root, name):
    path = root / name
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.resolve() != path:
        raise ValueError("source must be a regular unsymlinked file: " + name)
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns, item.st_mode)
    if identity(before) != identity(after) or len(raw) != after.st_size:
        raise ValueError("source changed during read: " + name)
    return raw, "100755" if after.st_mode & 0o111 else "100644"


def source_tree(files):
    """Reconstruct Git's complete src tree, including file modes and subtrees."""
    tree = {}
    for name, row in files.items():
        if not name.startswith("src/"):
            continue
        pieces = name.split("/")[1:]
        parent = tree
        for piece in pieces[:-1]:
            parent = parent.setdefault(piece, {})
            if not isinstance(parent, dict):
                raise ValueError("file/directory collision in target tree")
        if pieces[-1] in parent:
            raise ValueError("duplicate target tree entry")
        parent[pieces[-1]] = (row["mode"], row["git_blob"])

    def emit(node):
        records = []
        for name, item in node.items():
            encoded = name.encode()
            if isinstance(item, dict):
                mode, digest, order = "40000", emit(item), encoded + b"/"
            else:
                mode, digest = item
                order = encoded
            records.append((order, mode.encode() + b" " + encoded + b"\0"
                            + bytes.fromhex(digest)))
        raw = b"".join(row[1] for row in sorted(records))
        return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return emit(tree)


def read_snapshot(root, inventory):
    binding = inventory.get("migration_target")
    if not isinstance(binding, dict) or binding.get("path") != SNAPSHOT:
        raise ValueError("missing migration target binding")
    raw, mode = _regular(root, SNAPSHOT)
    if mode != "100644" or hashlib.sha256(raw).hexdigest() != binding.get("sha256"):
        raise ValueError("migration target snapshot differs from inventory binding")
    snapshot = _json(raw)
    if (snapshot.get("schema") != SCHEMA
            or snapshot.get("repository") != "TrillionniumFoundation/hepta-runtime"):
        raise ValueError("unknown migration target")
    for key in ("target_commit", "target_tree", "target_src_tree", "historical_comparison_base"):
        if not isinstance(snapshot.get(key), str) or not GIT_ID.fullmatch(snapshot[key]):
            raise ValueError("missing complete target identity: " + key)
    if snapshot["historical_comparison_base"] != inventory.get("runtime_base_commit"):
        raise ValueError("target uses a different historical comparison baseline")
    names = snapshot.get("tools")
    if (not isinstance(names, list) or not names
            or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name)
                   for name in names) or len(set(names)) != len(names)):
        raise ValueError("invalid or duplicate target handler")
    rows = snapshot.get("source_files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing complete target source tree")
    files = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "mode", "git_blob", "bytes"}:
            raise ValueError("invalid target source entry")
        name = row["path"]
        if not isinstance(name, str) or "\0" in name or "\\" in name:
            raise ValueError("invalid target source path")
        path = PurePosixPath(name)
        if (path.is_absolute() or name != path.as_posix() or ".." in path.parts
                or name in files or not (name.startswith("src/")
                                         or name in ("Cargo.lock", "Cargo.toml"))):
            raise ValueError("invalid or duplicate target source path")
        if (row["mode"] not in ("100644", "100755")
                or not isinstance(row["git_blob"], str) or not GIT_ID.fullmatch(row["git_blob"])
                or type(row["bytes"]) is not int or row["bytes"] < 0):
            raise ValueError("invalid target source identity: " + name)
        files[name] = row
    if not {"src/mcp/server.rs", "Cargo.lock", "Cargo.toml"} <= files.keys():
        raise ValueError("missing target entry point or dependency declarations")
    if source_tree(files) != snapshot["target_src_tree"]:
        raise ValueError("target source entries do not reconstruct the declared Git tree")
    return snapshot, files


def actual_sources(root):
    source = root / "src"
    if not source.is_dir() or source.resolve() != source:
        raise ValueError("missing regular src directory")
    paths = []
    for path in source.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError("symlink in production source: " + path.relative_to(root).as_posix())
        if stat.S_ISREG(mode):
            paths.append(path.relative_to(root).as_posix())
        elif not stat.S_ISDIR(mode):
            raise ValueError("nonregular production source entry: "
                             + path.relative_to(root).as_posix())
    paths.extend(("Cargo.lock", "Cargo.toml"))
    files = {}
    for name in sorted(paths):
        raw, mode = _regular(root, name)
        files[name] = {"path": name, "git_blob": git_blob(raw), "bytes": len(raw), "mode": mode}
    return files


def inspect_target(root, inventory=None, target_root=None):
    root = root.resolve(strict=True)
    if inventory is None:
        inventory = _json(_regular(root, "native/migration.json")[0])
    snapshot, expected = read_snapshot(root, inventory)
    baseline = actual_sources(root)
    registered = inventory.get("legacy_tool_handlers")
    if not isinstance(registered, list):
        raise ValueError("missing historical handler inventory")
    old_names = [row["name"] for row in registered]
    if old_names != TOOL.findall(_regular(root, "src/mcp/server.rs")[0].decode()):
        raise ValueError("historical handler inventory differs from actual source")
    if (len(set(old_names)) != len(old_names)
            or any(row.get("status") != "not_ported" or row.get("native_owner") is not None
                   for row in registered)):
        raise ValueError("unqualified historical handler substitution")
    actual_target_verified = False
    if target_root is not None:
        target_root = target_root.resolve(strict=True)
        actual = actual_sources(target_root)
        if actual != expected:
            changed = sorted(name for name in actual.keys() & expected.keys()
                             if actual[name] != expected[name])
            raise ValueError("migration target checkout differs from pinned source: "
                             + json.dumps({"missing": sorted(expected.keys() - actual.keys()),
                                           "extra": sorted(actual.keys() - expected.keys()),
                                           "changed": changed}))
        names = TOOL.findall(_regular(target_root, "src/mcp/server.rs")[0].decode())
        if names != snapshot["tools"] or len(set(names)) != len(names):
            raise ValueError("target handler list differs from independently read server")
        actual_target_verified = True
    target_names = snapshot["tools"]
    old_set, target_set = set(old_names), set(target_names)
    family_by_name = {row["name"]: row["family"] for row in registered}
    for name in target_set - old_set:
        family_by_name[name] = ("weights" if name.startswith("weight_") else
                                "reverse_engineering" if name.startswith("rea_") else "unclassified")
    return {
        "schema": "hepta.runtime.hia-target-coverage.v1",
        "target_commit": snapshot["target_commit"],
        "target_tree": snapshot["target_tree"],
        "target_src_tree": snapshot["target_src_tree"],
        "historical_comparison_base": snapshot["historical_comparison_base"],
        "target_checkout_verified": actual_target_verified,
        "historical_handler_count": len(old_names),
        "target_handler_count": len(target_names),
        "native_production_handler_count": 0,
        "target_handlers_missing_from_historical_inventory": sorted(target_set - old_set),
        "historical_handlers_absent_from_target": sorted(old_set - target_set),
        "remaining_target_families": dict(sorted(Counter(family_by_name[name] for name in target_names).items())),
        "source_drift": {
            "target_only": sorted(expected.keys() - baseline.keys()),
            "historical_only": sorted(baseline.keys() - expected.keys()),
            "changed": sorted(name for name in expected.keys() & baseline.keys()
                              if expected[name] != baseline[name]),
        },
        "target_source_file_count": len(expected),
        "historical_source_file_count": len(baseline),
        "target_behavior_qualified": False,
        "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
        "production_activated": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--target-root", type=Path,
                        help="independent checkout of the target production source")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect_target(args.root, target_root=args.target_root)
        if args.require_complete:
            result["completion_check"] = "INCOMPLETE"
        raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(raw)
        print(raw, end="")
        return 2 if args.require_complete else 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print(json.dumps({"target_inventory_valid": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
