"""Check the source-owned HIA migration inventory without declaring API parity.

This inventory is a coverage boundary, not a behavioral test. Native executable
qualification is performed separately by qualify_hia_runtime_native.py.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import HEPTA_COMMIT, HEPTA_TREE

RUNTIME_BASE_COMMIT = "a0dcdda1991ec536d5e2d252c006a778993fa566"
RUNTIME_BASE_TREE = "98d96c88d54082637c27f1cbfae61a66d0dd81e7"
ORIGINAL_RUNTIME_BLOBS = {
    "src/utils/line_hash.rs": "0e521656ba24869dbc05afc51d62aa4af79b5e44",
    "src/utils/truncation.rs": "a14ad26adedbff7624c67f5b89672e54fe60918e",
    "src/mcp/fs/delta.rs": "76681c01b571536e80f5bd1b93d79053d9df8985",
    "src/mcp/runtime/config.rs": "e55d9f536c069b7612f7a7cf81e691fd2394439c",
    "src/mcp/runtime/execution.rs": "541d7bf2ee069ae082b01ac10e0b1ed215927683",
    "src/mcp/runtime/jobs.rs": "7b9ca9d1c00f31411265c1dc26a18ead79907ec9",
    "src/mcp/runtime/binary.rs": "7195d29297e018be1b640f6ad5caab02738a87a5",
    "src/mcp/runtime/binary_file.py": "e5dddd844cb9ab869f4784a93f228a8a5ac91a74",
    "src/mcp/runtime/file_metadata.py": "a289f7c52a554f0c299541b932fcf30fba9251f5",
    "src/mcp/runtime/inode_patch.py": "25bdc18a30bfe23e84f9b25a5e77dd761841d5cd",
}


def check_original_sources(root: Path) -> dict:
    """Bind copied oracle bodies to the exact original owner files, not an index flag."""
    result = {}
    for name, expected in ORIGINAL_RUNTIME_BLOBS.items():
        path = root / name
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise ValueError("original runtime reference must be a regular unsymlinked file: " + name)
        raw = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if blob != expected:
            raise ValueError("original runtime reference differs from pinned baseline: " + name)
        result[name] = {"git_blob": blob, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


def inspect(root: Path) -> dict:
    document = json.loads((root / "native/migration.json").read_bytes())
    if document.get("schema") != "hepta.runtime.hia-migration.v1":
        raise ValueError("unknown migration inventory schema")
    for field in ("runtime_base_commit", "runtime_base_tree", "compiler_commit", "compiler_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", document.get(field, "")):
            raise ValueError("missing full Git identity: " + field)
    if (document["compiler_commit"], document["compiler_tree"]) != (HEPTA_COMMIT, HEPTA_TREE):
        raise ValueError("inventory compiler identity differs from the actual build pin")
    if (document["runtime_base_commit"], document["runtime_base_tree"]) != (RUNTIME_BASE_COMMIT, RUNTIME_BASE_TREE):
        raise ValueError("inventory runtime baseline differs from the original reference pin")
    original_sources = check_original_sources(root)
    server = (root / "src/mcp/server.rs").read_text()
    declared = re.findall(r"#\[tool\(.*?\)\]\s*async fn (\w+)", server, re.S)
    rows = document["legacy_tool_handlers"]
    if [row["name"] for row in rows] != declared or len(set(declared)) != len(declared):
        raise ValueError("legacy MCP tool coverage differs from the actual server")
    # This initial native service has no production handler replacements. A future
    # integration must change this checker together with real call sites/tests;
    # changing a JSON flag alone cannot mark the migration finished.
    if any(row["status"] != "not_ported" or row["native_owner"] is not None for row in rows):
        raise ValueError("this native profile has no migrated production MCP handlers")
    for field in ("whole_runtime_replaced", "old_stack_removal_qualified", "production_activated"):
        if document.get(field) is not False:
            raise ValueError("unsupported complete-migration claim: " + field)
    native_sources = []
    seen = set()
    for component in document["native_components"]:
        name = component["source"]
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or relative.suffix != ".hepta"
                or relative.parts[0] != "native" or name in seen):
            raise ValueError("invalid or duplicate native source path")
        seen.add(name)
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing regular HIA source: " + name)
        raw = path.read_bytes()
        if not raw.startswith(b"hia-asm.v1 hepta.hia.program.v8 "):
            raise ValueError("source is not the declared HIA assembly profile: " + name)
        if component.get("legacy_call_sites_replaced") is not False:
            raise ValueError("unqualified production call-site substitution")
        native_sources.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    actual = {path.relative_to(root).as_posix() for path in (root / "native").rglob("*.hepta")}
    if actual != seen:
        raise ValueError("native source coverage differs from files in the tree")
    prohibited = [path for path in (root / "native").rglob("*")
                  if path.is_file() and path.suffix.lower() in {".hia", ".hiaasm", ".rs", ".py", ".c", ".cpp"}]
    if prohibited:
        raise ValueError("unexpected non-HIA implementation or obsolete suffix in native/")
    state = document["cleanup"]
    if not (state.get("legacy_implementation_retained") is True
            and state.get("historical_evidence_retained") is True
            and state.get("history_rewrite") is False):
        raise ValueError("cleanup state would remove owners before their replacement")
    return {
        "schema": "hepta.runtime.hia-source-inventory.v1",
        "inventory_valid": True,
        "runtime_base_commit": document["runtime_base_commit"],
        "runtime_base_tree": document["runtime_base_tree"],
        "compiler_commit": document["compiler_commit"],
        "compiler_tree": document["compiler_tree"],
        "original_sources": original_sources,
        "native_sources": native_sources,
        "legacy_tool_count": len(rows),
        "native_production_tool_count": 0,
        "remaining_tool_families": dict(sorted(Counter(row["family"] for row in rows).items())),
        "remaining_system_owners": [item["name"] for item in document["remaining_system_owners"]],
        "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
        "production_activated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-complete", action="store_true",
                        help="return 2 while any production tool/system owner remains unported")
    args = parser.parse_args()
    try:
        result = inspect(args.root.resolve(strict=True))
        if args.require_complete:
            result["completion_check"] = "INCOMPLETE"
        raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(raw)
        print(raw, end="")
        return 2 if args.require_complete else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"inventory_valid": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
