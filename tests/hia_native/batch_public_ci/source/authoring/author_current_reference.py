#!/usr/bin/env python3
"""Extract exact current production items; add only a serial test transport.

The fifteen body fragments and two parameter fragments remain byte-for-byte
production sources. Cargo resolves a new fixture from the actual target lock
on CI; this author neither compiles Rust nor supplies semantic answers.
"""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PIN = lambda raw: {"bytes": len(raw), "sha256": SHA(raw)}


def cut(raw, first, last):
    assert raw.count(first) == 1, first
    begin = raw.index(first)
    return raw[begin:raw.index(last, begin)]


def files():
    root = ROOT / "reference"
    manifest = json.loads((root / "target-source.json").read_bytes())
    assert manifest["commit"] == "d3d75c30719db966b004756f610007a7c723729e"
    originals = {}
    for name, expected in manifest["files"].items():
        raw = (root / "target" / name).read_bytes()
        actual = dict(**PIN(raw), git_blob_sha=hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        assert actual == expected, name
        originals[name] = raw
    remote, core, delta = (originals["src/mcp/fs/" + name + ".rs"] for name in ("remote", "core", "delta"))
    fragments = {
        "path_source.rs": cut(remote, b"#[derive(Debug, Clone)]\npub enum PathSource {", "\n// ── SFTP connection pool".encode()),
        "remote_metadata.rs": cut(remote, b"#[derive(Debug, Clone)]\npub struct RemoteMetadata {", b'\n#[cfg(feature = "remote-fs")]\nmod sftp'),
        "io_metadata_type.rs": cut(remote, b"#[derive(Debug, Clone)]\npub struct IoMetadata {", b"\n/// Read a file as a string"),
        "io_read.rs": cut(remote, b"pub async fn io_read_to_string(", b"\n/// Read a file as raw bytes."),
        "io_write.rs": cut(remote, b"pub async fn io_write(", b"\n/// Check if a path exists."),
        "io_exists.rs": cut(remote, b"pub async fn io_exists(", b"\n/// Check if a path is a directory."),
        "io_metadata.rs": cut(remote, b"pub async fn io_metadata(", b"\n/// Create directories recursively."),
        "io_remove.rs": cut(remote, b"pub async fn io_remove_file(", b"\n/// Canonicalize a path."),
        "history.rs": cut(core, b"// Undo history:", b"// Main execution functions"),
        "view_cache.rs": cut(delta, b"/// Files above this size", b"\n/// Invalidate the directory"),
        "removed_marker.rs": cut(delta, b"pub fn removed_marker(", b"\n/// One step of a line diff;"),
        "mcp_call.rs": cut(originals["src/mcp/mod.rs"], b"#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct McpToolCall {", b"\nimpl McpToolCall"),
        "text_editing.rs": originals["src/mcp/fs/text_editing.rs"],
        "line_hash.rs": originals["src/utils/line_hash.rs"],
        "request_ctx.rs": originals["src/mcp/request_ctx.rs"],
    }
    assert len(fragments) == 15
    output = {"original/" + name: raw for name, raw in fragments.items()}
    retained = (root / "retained/original_batch_wrapper.rs").read_bytes()
    prefix = retained[:retained.index(b"fn send(")]
    for old, new in (
        (b"\nuse std::collections::HashMap;\n", b"\n"),
        (b"\nuse std::sync::atomic::{AtomicU64, Ordering};\n", b"\n"),
        (b"\nuse std::sync::{Arc, Mutex};\n", b"\nuse std::sync::Arc;\n"),
    ):
        assert prefix.count(old) == 1
        prefix = prefix.replace(old, new, 1)
    for original, observer in (("text_editing", "lock"), ("history", "history"), ("removed_marker", "cache")):
        old = ('include!("../original/' + original + '.rs");').encode()
        assert prefix.count(old) == 1
        prefix = prefix.replace(old, old + ('\n\t\t\tinclude!("' + observer + '_observer.rs");').encode(), 1)
    output["src/main.rs"] = prefix + (ROOT / "authoring/batch_reference_main.rs").read_bytes()
    for name in ("cache_observer.rs", "history_observer.rs", "lock_observer.rs"):
        output["src/" + name] = (root / "retained" / name).read_bytes()
    typed = (root / "retained/original_typed_items.rs").read_bytes()
    anchor = b'#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\n#[serde(rename_all = "snake_case")]\npub enum BatchEditOperationType'
    split = typed.index(anchor)
    first, second = typed[:split - 1], typed[split:]
    assert typed == first + b"\n" + second
    server = originals["src/mcp/server.rs"]
    assert server.count(first) == server.count(second) == 1
    assert PIN(first) == {"bytes": 454, "sha256": "e45764131117c074f1721d5569e489e52417ef06eac193c3a33bd2e42720e8dc"}
    assert PIN(second) == {"bytes": 3669, "sha256": "6c553193a4d93cd63254641dc80f0e7ba9f021a40dcc047fca1b9d6b3bae491d"}
    output["src/original.rs"] = typed
    output["src/params.rs"] = (root / "retained/original_typed_wrapper.rs").read_bytes()
    output["Cargo.toml"] = b'''[package]
name = "hepta-batch-public-original-oracle"
version = "0.1.0"
edition = "2021"
rust-version = "1.95"
publish = false

[[bin]]
name = "hepta-batch-body-original-oracle"
path = "src/main.rs"

[[bin]]
name = "hepta-batch-params-original-oracle"
path = "src/params.rs"

[dependencies]
anyhow = "=1.0.104"
rmcp = { version = "=3.9.0", default-features = false, features = ["server", "transport-async-rw"] }
schemars = "=1.2.2"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }
tokio = { version = "=1.53.3", features = ["rt-multi-thread", "macros", "sync", "time", "fs", "io-util"] }

[features]
remote-fs = []

[workspace]
'''
    proof = {"schema": "hepta.runtime.rebuilt-batch-current-original-extraction.v1",
        "target_commit": manifest["commit"], "target_files": manifest["files"],
        "body_fragments": {name: PIN(raw) for name, raw in fragments.items()},
        "parameter_fragments": {"line_endpoint_schema": PIN(first), "batch_types_and_deserializer": PIN(second)},
        "body_decoder_byte_exact": all(part in output["src/main.rs"] for part in (
            cut(retained, b"fn endpoint(", b"\nfn decode("),
            cut(retained, b"fn decode(", b"\nfn answer("),
            cut(retained, b"fn answer(", b"\nfn send("))),
        "parameter_fixture_byte_exact": output["src/params.rs"] == (root / "retained/original_typed_wrapper.rs").read_bytes(),
        "generated_files": {name: PIN(raw) for name, raw in output.items()},
        "fresh_rust_build": False, "fresh_rust_execution": False,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "remote_sftp_qualified": False, "whole_runtime_replaced": False}
    output["source-extraction.json"] = (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode()
    return output, proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result, proof = files()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, raw in result.items():
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    print(json.dumps({"status": "SOURCE_EXTRACTED", "body_fragments": len(proof["body_fragments"]),
        "parameter_fragments": len(proof["parameter_fragments"]), "fresh_rust_build": False}, sort_keys=True))
