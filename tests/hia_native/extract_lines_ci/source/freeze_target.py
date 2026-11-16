#!/usr/bin/env python3
"""Freeze selected exact d3d75 production inputs without executing Rust."""
from pathlib import Path
import argparse
import hashlib
import json

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
FILES = (
    "Cargo.toml", "Cargo.lock", "src/mcp/mod.rs", "src/mcp/server.rs",
    "src/mcp/fs/core.rs", "src/mcp/fs/text_editing.rs", "src/mcp/fs/remote.rs",
    "src/mcp/fs/remote_unavailable.rs", "src/mcp/fs/delta.rs",
    "src/mcp/request_ctx.rs", "src/utils/line_hash.rs", "src/utils/truncation.rs",
)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def cut(raw, first, after, name):
    first, after = first.encode(), after.encode()
    assert raw.count(first) == 1, (name, "start marker")
    start = raw.index(first)
    end = raw.index(after, start + len(first))
    while end > start and raw[end - 1] in b"\r\n":
        end -= 1
    assert raw[end - 1:end] == b"}", (name, "item ending")
    return start, end + 1, raw[start:end + 1]


def freeze(original, migration, destination):
    index = json.loads(migration.read_bytes())
    assert (index["target_commit"], index["target_tree"]) == (TARGET, TREE)
    rows = {row["path"]: row for row in index["source_files"]}
    sources, identities = {}, {}
    for name in FILES:
        source = original / name
        assert source.is_file() and not source.is_symlink()
        raw = source.read_bytes()
        observed = pin(raw)
        expected = rows[name]
        assert expected["mode"] == "100644"
        assert (observed["bytes"], observed["git_blob"]) == (expected["bytes"], expected["git_blob"]), name
        sources[name] = raw
        identities[name] = observed
    specs = (
        ("extract_lines_params.rs", "src/mcp/server.rs",
         "#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ExtractLinesParams {",
         "#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ShellParams"),
        ("extract_lines_handler.rs", "src/mcp/server.rs", "\t#[tool(\n\t\ttitle = \"Extract Lines\",",
         "\t#[tool(\n\t\ttitle = \"Shell\","),
        ("execute_extract_lines.rs", "src/mcp/fs/core.rs", "pub async fn execute_extract_lines(",
         "// Execute batch_edit operations on a single file."),
        ("parse_optional_endpoint.rs", "src/mcp/fs/core.rs", "fn parse_optional_endpoint(",
         "/// Resolve one endpoint to a 1-indexed line for viewing."),
        ("resolve_path.rs", "src/mcp/fs/core.rs", "pub fn resolve_path(",
         "// Line-index resolution"),
        ("shift_note.rs", "src/mcp/fs/text_editing.rs", "pub(crate) fn shift_note(",
         "/// Atomic write:"),
        ("render_line.rs", "src/utils/truncation.rs", "fn render_line(",
         "/// Format content with composite line ids."),
    )
    excerpts = {}
    for name, source, first, after in specs:
        start, end, raw = cut(sources[source], first, after, name)
        excerpts[name] = {"source": source, "start": start, "end": end, **pin(raw)}
        sources["@" + name] = raw
    source = "src/utils/truncation.rs"
    raw = sources[source]
    first = b"pub fn format_extracted_content_smart("
    assert raw.count(first) == 1
    start = raw.index(first)
    complete = raw[start:]
    assert complete.endswith(b"}\n")
    name = "format_extracted_content_smart.rs"
    excerpts[name] = {"source": source, "start": start, "end": len(raw), **pin(complete)}
    sources["@" + name] = complete
    destination.mkdir(parents=True, exist_ok=False)
    for name, raw in sources.items():
        target = destination / ("excerpts" if name.startswith("@") else "target") / name.lstrip("@")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    document = {"schema": "hepta.runtime.extract-lines-target.v1", "repository": index["repository"],
        "target_commit": TARGET, "target_tree": TREE, "migration_manifest": pin(migration.read_bytes()),
        "files": identities, "excerpts": excerpts,
        "source_verified": True, "local_rust_executed": False,
        "native_implemented": False, "original_compared": False,
        "public_handler_qualified": False, "remote_qualified": False,
        "full_async_cancellation_qualified": False, "whole_runtime_replaced": False}
    (destination / "TARGET.json").write_bytes(encode(document))
    return document


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = freeze(args.original, args.migration, args.output)
    print(json.dumps({"status": "EXACT_TARGET_INPUTS_FROZEN", "target_commit": TARGET,
        "target_files": len(result["files"]), "exact_excerpts": len(result["excerpts"]),
        "source_bytes": sum(p["bytes"] for p in result["files"].values()),
        "native_implemented": False, "original_compared": False}, sort_keys=True))
