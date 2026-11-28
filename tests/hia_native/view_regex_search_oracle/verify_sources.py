"""Compose unchanged search bodies into the existing frozen actual-I/O harness.

Only test-owned modules are extended. The original search, caller, I/O, line
identifier, request-context and result-gate bodies remain byte-for-byte copies.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tomllib

ROOT = Path(__file__).resolve().parent
COMPANION = ROOT.parent / "view_call_oracle"
COMPANION_FILES = ("verify_sources.py", "source_manifest.json", "src/driver.rs")
EXTRA_FILES = ("src/mcp/fs/search.rs",)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def companion():
    manifest = json.loads((ROOT / "source_manifest.json").read_bytes())
    for name, expected in manifest["companion_inputs"].items():
        if pin((COMPANION / name).read_bytes()) != expected:
            raise AssertionError("frozen view oracle companion differs: " + name)
    spec = importlib.util.spec_from_file_location("_search_original_view_assembler",
                                                 COMPANION / "verify_sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise AssertionError("unambiguous test-harness extension required")
    return source.replace(old, new, 1)


def assemble(runtime_root):
    base = companion()
    source, old_manifest = base.check_sources(runtime_root)
    remote = (runtime_root / "src/mcp/fs/remote.rs").read_text()
    operations = (runtime_root / "src/mcp/fs/file_ops.rs").read_text()
    parts = {
        "io_read": base.function(remote, "io_read"),
        "view_file_with_content_search": base.function(operations, "view_file_with_content_search"),
        "search": (runtime_root / "src/mcp/fs/search.rs").read_text().split("#[cfg(test)]", 1)[0],
    }
    source = replace_once(source,
        "                pub async fn remote_read_to_string",
        "                pub async fn remote_read(_: &PathSource) -> anyhow::Result<Vec<u8>> { panic!(\"remote branch outside oracle domain\") }\n"
        "                pub async fn remote_read_to_string")
    original_string_read = base.function(remote, "io_read_to_string")
    source = replace_once(source, original_string_read,
                          parts["io_read"] + "\n" + original_string_read)
    raw_wrapper = r'''
            pub async fn io_read(source: &PathSource) -> Result<Vec<u8>> {
                let occurrence = crate::before("read").await;
                let result = original_io::io_read(source).await;
                crate::after("read", occurrence, match &result {
                    Ok(bytes) => serde_json::json!({"ok": true, "bytes": bytes.len(), "snapshot_blob": crate::trace_blob(bytes)}),
                    Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
                }).await;
                result
            }
'''
    source = replace_once(source,
        "            pub async fn io_read_to_string(source: &PathSource) -> Result<String> {",
        raw_wrapper + "            pub async fn io_read_to_string(source: &PathSource) -> Result<String> {")
    source = replace_once(source, "        pub mod file_ops {",
        "        pub mod search {\n" + parts["search"] + "\n}\n        pub mod file_ops {")
    source = replace_once(source,
        "            use super::remote::{io_exists, io_is_file, io_metadata, io_read_to_string, PathSource};",
        "            use super::remote::{io_exists, io_is_file, io_metadata, io_read_to_string, io_read, PathSource};\n"
        "            use super::search;\n"
        "            use crate::utils::line_hash::line_id_at;")
    source = replace_once(source, r'''            pub async fn view_file_with_content_search(_: &PathSource, _: &str, _: usize, _: bool) -> Result<String> {
                panic!("content search outside regular-file oracle domain")
            }''', parts["view_file_with_content_search"])
    for name, original in parts.items():
        if source.count(original) != 1:
            raise AssertionError("original search body must occur unchanged once: " + name)
    return source, parts, old_manifest


def check_dependency_subset(lock, original):
    reference = {(row["name"], row["version"], row.get("source")): row.get("checksum")
                 for row in tomllib.loads(original.decode())["package"]}
    count = 0
    for row in tomllib.loads(lock.decode())["package"]:
        if "source" not in row:
            if (row["name"], row["version"]) != ("hepta-view-regex-search-original-oracle", "0.1.0"):
                raise AssertionError("unexpected local reference dependency")
            continue
        key = row["name"], row["version"], row["source"]
        if key not in reference or reference[key] != row.get("checksum"):
            raise AssertionError("original dependency differs: " + repr(key))
        count += 1
    return count


def check_sources(runtime_root):
    manifest = json.loads((ROOT / "source_manifest.json").read_bytes())
    for name, expected in manifest["files"].items():
        if pin((runtime_root / name).read_bytes()) != expected:
            raise AssertionError("frozen original search source differs: " + name)
    source, parts, original = assemble(runtime_root)
    if {name: pin(text.encode()) for name, text in parts.items()} != manifest["extractions"]:
        raise AssertionError("original search body extraction differs")
    if original["commit"] != manifest["commit"]:
        raise AssertionError("base and search source commit differ")
    return source, manifest


def materialize(runtime_root, output):
    source, manifest = check_sources(runtime_root)
    dependency_count = check_dependency_subset((ROOT / "Cargo.lock").read_bytes(),
                                               (runtime_root / "Cargo.lock").read_bytes())
    output.mkdir(parents=True, exist_ok=False)
    (output / "src").mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(ROOT / name, output / name)
    (output / "src/main.rs").write_text(source)
    return dict(source_commit=manifest["commit"],
                original_source_files_match=True,
                extracted_original_bodies_unchanged=True,
                actual_tokio_filesystem_io=True,
                source=pin(source.encode()), registry_dependencies=dependency_count,
                unsupported_branches_abort=True,
                original_mcp_router_executed=False,
                whole_view_migrated=False, whole_runtime_replaced=False)
