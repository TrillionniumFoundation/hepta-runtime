"""Extract the unchanged current-target method and a separately marked observer."""
from pathlib import Path
import argparse
import hashlib
import json

TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_SHA = "1db8a3f4235339d8a7aef6e247ddc8f42f4791a26efe4dd298490421b8ca1d9a"
TARGET_BLOB = "ea360b7627695d212fd4fbe9f7e71d1dc8858591"
LOCK_SHA = "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()

PREFIX = b'''// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Private source-extracted comparison fixture. No runtime implementation.
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::io::{self, Read, Write};

'''

SUFFIX = br'''
fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at+8].try_into().unwrap())
}
fn number(raw: &mut Vec<u8>, value: u64) { raw.extend_from_slice(&value.to_le_bytes()); }
fn observed(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() >= 48 && raw.len() <= (8 << 20) + 48);
    assert_eq!(&raw[..8], b"HSCANQ01");
    assert_eq!(word(raw, 8), 1);
    assert!(word(raw, 16) <= 1 && word(raw, 24) <= 1);
    assert_eq!(word(raw, 32) as usize, raw.len() - 48);
    assert_eq!(word(raw, 40), 0);
    let text = std::str::from_utf8(&raw[48..]).unwrap().to_owned();
    let scope = OwnerScope { owner: String::new(), authenticated: word(raw, 16) == 1 };
    let search = word(raw, 24) == 1;
    // Primary execution: the entire original method above is unchanged.
    let primary = scope.annotate(text.clone(), search);
    // A second, explicitly separate source-prefix observer retains the full
    // actual constructor serialization even when the primary budget rejects.
    let prefix = scope.observe_serialized_prefix(text, search);
    let (kind, category, answer, annotation, wire) = match (primary, prefix) {
        (Ok(actual), Ok((annotation, wire))) => {
            assert_eq!(actual, annotation);
            assert!(wire.len() <= 65536);
            (0u64, 0u64, actual, annotation, wire)
        },
        (Err(error), Ok((annotation, wire))) => {
            let text = error.to_string();
            assert_eq!(text, "scoped metadata wire response exceeds 64 KiB; reduce result page limit");
            assert!(wire.len() > 65536);
            (1, 3, text, annotation, wire)
        },
        (Err(error), Err(prefix_error)) => {
            let text = error.to_string();
            assert_eq!(text, prefix_error.to_string());
            let category = if text == "metadata response unavailable" { 2 } else { 1 };
            (1, category, text, String::new(), Vec::new())
        },
        _ => panic!("unchanged primary and exact-prefix observer disagree"),
    };
    let mut response = b"HSCANR01".to_vec();
    for value in [kind, answer.len() as u64, wire.len() as u64, category, annotation.len() as u64, 0, 0] {
        number(&mut response, value);
    }
    response.extend_from_slice(answer.as_bytes());
    let mut result = b"HSCASR01".to_vec();
    for value in [response.len() as u64, annotation.len() as u64, wire.len() as u64] { number(&mut result, value); }
    result.extend(response);
    result.extend_from_slice(annotation.as_bytes());
    result.extend(wire);
    result
}

fn main() {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut head = [0u8; 8];
        let count = input.read(&mut head[..1]).unwrap();
        if count == 0 { break; }
        input.read_exact(&mut head[1..]).unwrap();
        let size = u64::from_le_bytes(head) as usize;
        assert!((48..=(8 << 20) + 48).contains(&size));
        let mut raw = vec![0u8; size];
        input.read_exact(&mut raw).unwrap();
        let result = observed(&raw);
        output.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&result).unwrap();
    }
    output.flush().unwrap();
}
'''

CARGO = b'''[package]
name = "scope-annotation-original"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "scope-annotation-original"
path = "main.rs"

[dependencies]
anyhow = "=1.0.104"
rmcp = { version = "=3.9.0", default-features = false, features = ["server"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }

[profile.dev]
opt-level = 1
debug = true
debug-assertions = true
overflow-checks = true
lto = false
codegen-units = 256
incremental = true
rpath = false
'''


def extract(raw):
    if SHA(raw) != TARGET_SHA or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != TARGET_BLOB:
        raise ValueError("current target source differs")
    pieces = {}
    struct_start = raw.index(b"#[derive(Clone, PartialEq, Eq)]\npub struct OwnerScope {")
    struct_end = raw.index(b"\n}\n", struct_start) + 3
    pieces["struct"] = (struct_start, struct_end)
    for key, marker in (("annotate", b"\tpub fn annotate("), ("kind", b"\tfn kind(")):
        start = raw.index(marker)
        end = raw.index(b"\n\t}\n", start) + 4
        pieces[key] = (start, end)
    declaration = raw[slice(*pieces["struct"])]
    annotate = raw[slice(*pieces["annotate"])]
    kind = raw[slice(*pieces["kind"])]
    signature = b"\tpub fn annotate(&self, text: String, search: bool) -> Result<String> {\n"
    assert annotate.startswith(signature)
    budget = annotate.index(b"\t\tif serde_json::to_vec(&wire)?.len() > 64 * 1024 {")
    prefix = annotate[len(signature):budget]
    observer = (b"\tfn observe_serialized_prefix(&self, text: String, search: bool) -> Result<(String, Vec<u8>)> {\n"
                + prefix + b"\t\tlet bytes = serde_json::to_vec(&wire)?;\n\t\tOk((text, bytes))\n\t}\n")
    source = PREFIX + declaration + b"impl OwnerScope {\n" + annotate + kind + observer + b"}\n" + SUFFIX
    records = {name: {"start": start, "end": end, "bytes": end-start, "sha256": SHA(raw[start:end])}
               for name, (start, end) in pieces.items()}
    records["observer_original_prefix"] = dict(start=pieces["annotate"][0]+len(signature),
        end=pieces["annotate"][0]+budget, bytes=len(prefix), sha256=SHA(prefix),
        unchanged_entire_method=False, exact_original_statements=True)
    return source, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = args.target.resolve(strict=True)
    raw = (target / "src/mcp/runtime/caller_scope.rs").read_bytes()
    lock = (target / "Cargo.lock").read_bytes()
    if SHA(lock) != LOCK_SHA:
        raise ValueError("target lock changed")
    source, records = extract(raw)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    (output / "main.rs").write_bytes(source)
    (output / "Cargo.toml").write_bytes(CARGO)
    receipt = dict(schema="hepta.scope-annotation.original-extraction.v1", target_commit=TARGET_COMMIT,
        target_file="src/mcp/runtime/caller_scope.rs", target_git_blob=TARGET_BLOB,
        target_sha256=TARGET_SHA, target_lock_sha256=LOCK_SHA, source_sha256=SHA(source),
        cargo_sha256=SHA(CARGO), extracted=records,
        primary_function_unchanged=True, prefix_observer_separate=True,
        original_execution_qualified=False, production_activated=False)
    (output / "extraction.json").write_text(json.dumps(receipt, sort_keys=True, indent=2)+"\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
