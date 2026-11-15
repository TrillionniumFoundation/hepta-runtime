"""Freeze and materialize original Rust functions without editing their bodies."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tomllib

ROOT = Path(__file__).resolve().parent
SOURCE_FILES = [
    "Cargo.toml", "Cargo.lock", "src/mcp/fs/core.rs", "src/mcp/fs/file_ops.rs",
    "src/mcp/fs/delta.rs", "src/mcp/fs/remote.rs", "src/mcp/fs/text_editing.rs",
    "src/mcp/request_ctx.rs", "src/mcp/server.rs", "src/utils/line_hash.rs",
    "src/utils/truncation.rs",
]


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def function(text, name):
    start = text.index("fn " + name + "(")
    start = text.rfind("\n", 0, start) + 1
    at = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[start:at]


def original_parts(runtime_root):
    texts = {path: (runtime_root / path).read_text() for path in SOURCE_FILES}
    parts = {}
    groups = {
        "src/mcp/fs/core.rs": ["parse_optional_endpoint", "resolve_endpoint_to_line",
                               "resolve_view_range", "view_existing_path", "execute_view",
                               "render_view"],
        "src/mcp/fs/file_ops.rs": ["format_file_content_with_numbers", "view_file_spec"],
        "src/mcp/fs/remote.rs": ["io_read_to_string", "io_exists", "io_is_dir", "io_is_file", "io_metadata"],
        "src/mcp/fs/text_editing.rs": ["lock_key_for", "lock_key_for_source"],
        "src/mcp/server.rs": ["append_hints", "get_info", "supports_cache_hints",
                              "strip_null_variants", "strip_generator_noise"],
    }
    for path, names in groups.items():
        for name in names:
            parts[name] = function(texts[path], name)
    server = texts['src/mcp/server.rs']
    start = server.index('#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ViewParams')
    parts['ViewParams'] = server[start:server.index('/// JSON schema for a single line endpoint', start)]
    parts['line_endpoint_schema'] = function(server, 'line_endpoint_schema')
    listing = function(server, 'list_tools')
    tail = listing.index('\t\tlet result = ListToolsResult::with_all_items(tools);')
    parts['list_tools_header_tail'] = listing[tail:listing.rfind('\n\t}')]
    parts['claude_channel_constant'] = next(line for line in server.splitlines()
        if line.startswith('const CLAUDE_CHANNEL_CAPABILITY:'))
    remote = texts["src/mcp/fs/remote.rs"]
    parts["path_source"] = remote[remote.index("#[derive(Debug, Clone)]\npub enum PathSource"):
                                   remote.index("// ── SFTP connection pool")]
    start = remote.index("#[derive(Debug, Clone)]\npub struct IoMetadata")
    parts["io_metadata_type"] = remote[start:remote.index("\n}", start) + 2]
    for short, path in [("delta", "src/mcp/fs/delta.rs"),
                        ("line_hash", "src/utils/line_hash.rs"),
                        ("truncation", "src/utils/truncation.rs"),
                        ("request_context", "src/mcp/request_ctx.rs")]:
        parts[short] = texts[path].split("#[cfg(test)]", 1)[0]
    return texts, parts


def assemble(runtime_root):
    texts, p = original_parts(runtime_root)
    source = texts["src/mcp/fs/core.rs"].split("// Core functionality", 1)[0]
    source += '#![allow(dead_code)]\n'
    source += "mod utils { pub mod line_hash {\n" + p["line_hash"] + "\n}\n"
    source += "pub mod truncation {\n" + p["truncation"] + "\n}}\n"
    source += "mod mcp {\n" + r'''
    pub struct McpToolCall {
        pub parameters: serde_json::Value,
        pub workdir: std::path::PathBuf,
    }
    pub mod request_ctx {
''' + p["request_context"] + r'''
        pub fn inspect_hints() -> Vec<String> {
            CTX.try_with(|ctx| ctx.hints.borrow().clone()).unwrap_or_default()
        }
    }
    pub mod fs {
        pub use remote::PathSource;
        pub mod remote {
            use anyhow::Result;
            use std::path::{Path, PathBuf};
            use std::time::SystemTime;
''' + p["path_source"] + "\n" + p["io_metadata_type"] + r'''
            mod sftp {
                use super::{IoMetadata, PathSource};
                pub async fn remote_read_to_string(_: &PathSource) -> anyhow::Result<String> { panic!("remote branch outside oracle domain") }
                pub async fn remote_exists(_: &PathSource) -> anyhow::Result<bool> { panic!("remote branch outside oracle domain") }
                pub async fn remote_is_file(_: &PathSource) -> anyhow::Result<bool> { panic!("remote branch outside oracle domain") }
                pub async fn remote_metadata(_: &PathSource) -> anyhow::Result<IoMetadata> { panic!("remote branch outside oracle domain") }
            }
            mod original_io {
                use super::{PathSource, IoMetadata, sftp};
                use anyhow::{anyhow, Result};
''' + "\n".join(p[name] for name in ["io_read_to_string", "io_exists", "io_is_dir", "io_is_file", "io_metadata"]) + r'''
            }
            pub async fn io_read_to_string(source: &PathSource) -> Result<String> {
                let occurrence = crate::before("read").await;
                let result = original_io::io_read_to_string(source).await;
                crate::after("read", occurrence, match &result {
                    Ok(text) => serde_json::json!({"ok": true, "bytes": text.len(), "snapshot_blob": crate::trace_blob(text.as_bytes())}),
                    Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
                }).await;
                result
            }
            pub async fn io_metadata(source: &PathSource) -> Result<IoMetadata> {
                let occurrence = crate::before("metadata").await;
                let result = original_io::io_metadata(source).await;
                crate::after("metadata", occurrence, match &result {
                    Ok(meta) => serde_json::json!({"ok": true, "size": meta.size, "is_file": meta.is_file, "is_dir": meta.is_dir}),
                    Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
                }).await;
                result
            }
''' 
    for name, event in [("io_exists", "exists"), ("io_is_dir", "is_dir"), ("io_is_file", "is_file")]:
        source += f'''
            pub async fn {name}(source: &PathSource) -> Result<bool> {{
                let occurrence = crate::before("{event}").await;
                let result = original_io::{name}(source).await;
                crate::after("{event}", occurrence, match &result {{
                    Ok(value) => serde_json::json!({{"ok": true, "value": value}}),
                    Err(error) => serde_json::json!({{"ok": false, "error": error.to_string()}}),
                }}).await;
                result
            }}
'''
    source += "}\n        pub mod text_editing {\n use super::PathSource; use std::path::Path;\n"
    source += p["lock_key_for"] + "\n" + p["lock_key_for_source"] + "\n}\n"
    source += "pub mod delta {\n" + p["delta"] + r'''
            pub fn inspect(cache: &ViewCache, source: &super::PathSource) -> Option<String> {
                cache.get(&super::text_editing::lock_key_for_source(source))
            }
        }
        pub mod file_ops {
            use super::remote::{io_exists, io_is_file, io_metadata, io_read_to_string, PathSource};
            use anyhow::{anyhow, bail, Result};
            use crate::utils::truncation::format_content_with_line_numbers;
            pub(crate) const MAX_VIEW_FILE_BYTES: u64 = 5 * 1024 * 1024;
''' + p["format_file_content_with_numbers"] + "\n" + p["view_file_spec"] + r'''
            pub async fn view_file_with_content_search(_: &PathSource, _: &str, _: usize, _: bool) -> Result<String> {
                panic!("content search outside regular-file oracle domain")
            }
        }
        pub mod directory {
            pub async fn list_directory(_: &crate::mcp::McpToolCall, _: &str) -> anyhow::Result<String> {
                panic!("directory dispatch outside regular-file oracle domain")
            }
        }
        pub mod background {
            pub fn job_id_from_uri(path: &str) -> Option<&str> {
                assert!(!path.contains("://"), "background routing outside oracle domain"); None
            }
            pub fn resource_text(_: &str) -> Option<String> { unreachable!() }
        }
        pub mod core {
            use super::{file_ops, directory, background};
            use super::remote::{io_exists, io_is_dir, io_metadata, io_read_to_string, resolve_path_source, PathSource};
            use crate::mcp::McpToolCall;
            use crate::utils::line_hash::{self, Endpoint, resolve_line_index_clamped};
            use crate::utils::truncation::{MAX_RESULT_BYTES, format_megabytes};
            use anyhow::{anyhow, bail, Result};
            use serde_json::Value;
''' + "\n".join(p[name] for name in ["parse_optional_endpoint", "resolve_endpoint_to_line", "resolve_view_range", "view_existing_path", "execute_view"]) + r'''
            async fn search_path_alternatives(_: &McpToolCall, _: &str) -> Result<String> {
                panic!("alternative search outside oracle domain")
            }
            mod original_render {
                use super::*;
''' + p["render_view"] + r'''
                pub async fn run(call: &McpToolCall) -> Result<String> { render_view(call).await }
            }
            async fn render_view(call: &McpToolCall) -> Result<String> {
                let raw = crate::raw_path();
                let result = if let Some(path) = raw {
                    // Explicit private PathSource domain: JSON strings cannot carry invalid UTF-8.
                    let source = PathSource::Local(path);
                    let start = parse_optional_endpoint(call.parameters.get("start"), "start")?;
                    let end = parse_optional_endpoint(call.parameters.get("end"), "end")?;
                    let range = resolve_view_range(start, end, &source).await?;
                    file_ops::view_file_spec(&source, range, call.parameters.get("full").and_then(Value::as_bool).unwrap_or(false)).await
                } else {
                    original_render::run(call).await
                };
                crate::record_render(&result);
                result
            }
        }
    }
}
use mcp::request_ctx;
''' + p["append_hints"] + "\n" + (ROOT / "src/driver.rs").read_text()
    return source, p


def check_sources(runtime_root):
    manifest = json.loads((ROOT / "source_manifest.json").read_text())
    for path, identity in manifest["files"].items():
        if pin((runtime_root / path).read_bytes()) != identity:
            raise AssertionError("frozen original source differs: " + path)
    source, parts = assemble(runtime_root)
    if {name: pin(value.encode()) for name, value in parts.items()} != manifest["extractions"]:
        raise AssertionError("original extracted function bodies differ")
    return source, manifest


def check_dependency_subset(lock, original):
    reference = {(row["name"], row["version"], row.get("source")): row.get("checksum")
                 for row in tomllib.loads(original.decode())["package"]}
    count = 0
    for row in tomllib.loads(lock.decode())["package"]:
        if "source" not in row:
            if row["name"] != "hepta-view-call-original-oracle":
                raise AssertionError("unexpected local original dependency")
            continue
        key = (row["name"], row["version"], row["source"])
        if key not in reference or reference[key] != row.get("checksum"):
            raise AssertionError(f"original dependency differs: {key}")
        count += 1
    return count


def materialize(runtime_root, output):
    source, manifest = check_sources(runtime_root)
    dependency_count = check_dependency_subset((ROOT / "Cargo.lock").read_bytes(),
                                               (runtime_root / "Cargo.lock").read_bytes())
    output.mkdir(parents=True, exist_ok=False)
    (output / "src").mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(ROOT / name, output / name)
    (output / "src/main.rs").write_text(source)
    (output / 'src/bin').mkdir()
    _, parts = original_parts(runtime_root)
    sdk_source = (ROOT / 'src/sdk_driver.rs').read_text() + '\n' + parts['ViewParams'] + '\n' + parts['line_endpoint_schema']
    (output / 'src/bin/view_call_sdk.rs').write_text(sdk_source)
    additional_sources = {}
    for driver, binary in [('sdk_router_driver.rs', 'view_call_router_sdk'),
                           ('public_schema_driver.rs', 'view_call_public_schema'),
                           ('info_driver.rs', 'view_call_info_sdk')]:
        text = (ROOT / 'src' / driver).read_text()
        if driver == 'public_schema_driver.rs':
            for name in ('strip_null_variants', 'strip_generator_noise'):
                if function(text, name) != parts[name]:
                    raise AssertionError('schema driver changed an original function: ' + name)
        if driver == 'info_driver.rs':
            for name in ('get_info', 'supports_cache_hints', 'list_tools_header_tail', 'claude_channel_constant'):
                if text.count(parts[name]) != 1:
                    raise AssertionError('info driver changed an original fragment: ' + name)
        else:
            text += '\n' + parts['ViewParams'] + '\n' + parts['line_endpoint_schema']
        (output / 'src/bin' / (binary + '.rs')).write_text(text)
        additional_sources[binary] = pin(text.encode())
    return {"source_commit": manifest["commit"], "original_source_files_match": True,
            "extracted_original_bodies_unchanged": True, "actual_tokio_filesystem_io": True,
            "registry_dependencies": dependency_count, "source": pin(source.encode()),
            "sdk_source": pin(sdk_source.encode()),
            "additional_sources": additional_sources,
            "actual_sdk_parameters_adapter_fixture": True, "original_view_handler_body_executed": False,
            "actual_original_public_schema_functions": True, "actual_original_get_info": True,
            "original_full_tool_catalog_executed": False,
            "unsupported_branches_abort": True, "whole_view_migrated": False}
