# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare exact original Rust tests with original and actual HIA backends."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import tomllib


def block(text, marker):
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 1
    at = opening + 1
    while depth:
        if text[at] == "{":
            depth += 1
        elif text[at] == "}":
            depth -= 1
        at += 1
    return text[start:at]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--native-driver", required=True, type=Path)
    ap.add_argument("--canonical-lock", type=Path,
                    default=Path(__file__).with_name("rea_asar_oracle.Cargo.lock"))
    args = ap.parse_args()
    source, out = args.source, args.output
    out.mkdir(mode=0o700, exist_ok=False)
    original = out / "original"
    paths = ["src/mcp/rea_asar.rs", "src/mcp/rea_asar_parser.rs",
             "src/mcp/rea_asar_parser_tests.rs", "src/mcp/rea_files.rs",
             "src/mcp/rea_evidence.rs", "Cargo.toml", "Cargo.lock"]
    pins = {}
    for name in paths:
        target = original / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, target)
        raw = target.read_bytes()
        assert raw == (source / name).read_bytes()
        pins[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    crate = out / "crate"
    (crate / "src/asar").mkdir(parents=True)
    parent = (original / paths[0]).read_text()
    original_parser = (original / paths[1]).read_text()
    files = (original / paths[3]).read_text()
    evidence = (original / paths[4]).read_text()
    unique_start = evidence.index("#[derive(Debug)]\nstruct UniqueJson")
    unique_function = block(evidence, "pub(super) fn parse_unique_json(")
    unique_end = evidence.index(unique_function) + len(unique_function)
    selected = {"hex": block(parent, "pub(super) fn hex("),
                "valid_digest": block(parent, "pub(super) fn valid_digest("),
                "observed_version": block(parent, "fn observed_version("),
                "ensure_unchanged": block(files, "pub(super) fn ensure_unchanged("),
                "Request": block(original_parser, "pub(super) enum Request"),
                "unique_json": evidence[unique_start:unique_end]}
    imports = "use anyhow::{anyhow,bail,Context,Result};\nuse serde::{Deserialize,Serialize};\nuse serde_json::{json,Map,Value};\nuse sha2::{Digest,Sha256};\nuse std::fmt::Write as _;\n"
    asar_source = imports + "const MAX_HEADER_BYTES:u64=16*1024*1024;\nconst MAX_SOURCE_BYTES:usize=1024*1024;\n"
    asar_source += selected["hex"] + "\n" + selected["valid_digest"] + "\n" + selected["observed_version"] + "\n"
    asar_source += '#[cfg(not(feature="native"))]\n#[path=' + json.dumps(str(original / paths[1])) + "]\nmod parser;\n"
    asar_source += '#[cfg(feature="native")]\n#[path="native_parser.rs"]\nmod parser;\n'
    asar_source += '''
pub fn inspect(request: &Value) -> Result<Value> {
    let path = request["path"].as_str().context("fixture path")?;
    let mut file = std::fs::File::open(path)?;
    let typed: parser::Request = serde_json::from_value(request["request"].clone())?;
    parser::inspect_file(&mut file, &typed)
}
'''
    (crate / "src/asar/mod.rs").write_text(asar_source)
    native = imports + "use super::{hex,MAX_HEADER_BYTES,MAX_SOURCE_BYTES};\nuse std::fs::File;\n"
    native += "pub(super) const MAX_ENTRIES:usize=50_000;\npub(super) const MAX_VERIFY_BYTES:u64=64*1024*1024;\n"
    native += '#[derive(Debug,Clone,Deserialize,Serialize)]\n#[serde(tag="operation",rename_all="snake_case",deny_unknown_fields)]\n' + selected["Request"] + "\n"
    native += '''
pub(super) fn inspect_file(file: &mut File, request: &Request) -> Result<Value> {
    match request {
        Request::Index { offset, limit } => crate::native_driver::inspect(file,1,*offset as u64,*limit,"",false),
        Request::Read { member, offset, length, require_complete } => crate::native_driver::inspect(file,2,*offset,*length,member,*require_complete)
    }
}
'''
    native += '#[cfg(test)]\n#[path=' + json.dumps(str(original / paths[2])) + "]\nmod tests;\n"
    (crate / "src/asar/native_parser.rs").write_text(native)
    (crate / "src/rea_files.rs").write_text("use anyhow::{bail,Result};\n" + selected["ensure_unchanged"] + "\n")
    evidence_imports = "use anyhow::{Context,Result};\nuse serde::de::{Error as DeError,MapAccess,SeqAccess,Visitor};\nuse serde::{Deserialize,Deserializer};\nuse serde_json::{json,Map,Number,Value};\nuse std::fmt;\n"
    (crate / "src/rea_evidence.rs").write_text(evidence_imports + selected["unique_json"] + "\n")
    (crate / "src/lib.rs").write_text('pub mod asar;\nmod rea_files;\nmod rea_evidence;\n#[cfg(feature="native")]\nmod native_driver;\n')
    shutil.copy2(args.native_driver, crate / "src/native_driver.rs")
    (crate / "src/main.rs").write_text('''
use std::io::{BufRead,Write};
use serde_json::{json,Value};
fn main()->anyhow::Result<()> {
    let stdin=std::io::stdin();
    let mut stdout=std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let request:Value=serde_json::from_str(&line?)?;
        let response=match hia_rea_asar_reference::asar::inspect(&request) {
            Ok(value)=>json!({"ok":true,"value":value}),
            Err(error)=>json!({"ok":false,"error":error.to_string()})
        };
        writeln!(stdout,"{}",serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }
    Ok(())
}
''')
    cargo = '''[package]
name = "hia-rea-asar-reference"
version = "0.0.0"
edition = "2021"
publish = false

[features]
native = []

[dependencies]
anyhow = "=1.0.104"
libc = "=0.2.189"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }
sha2 = "=0.11.0"
tempfile = "=3.27.0"
'''
    (crate / "Cargo.toml").write_text(cargo)
    old_lock = (original / "Cargo.lock").read_text()
    parsed = tomllib.loads(old_lock)
    by_name = {}
    by_id = {}
    for package in parsed["package"]:
        key = (package["name"], package["version"])
        by_id[key] = package
        by_name.setdefault(package["name"], []).append(key)
    direct = ["anyhow", "libc", "serde", "serde_json", "sha2", "tempfile"]
    pending = [by_name[name][0] for name in direct]
    assert all(len(by_name[name]) == 1 for name in direct)
    closed = set()
    while pending:
        key = pending.pop()
        if key in closed:
            continue
        closed.add(key)
        for dependency in by_id[key].get("dependencies", []):
            parts = dependency.split()
            target = (parts[0], parts[1]) if len(parts) > 1 else by_name[parts[0]][0]
            if len(parts) == 1:
                assert len(by_name[parts[0]]) == 1, dependency
            assert target in by_id, dependency
            pending.append(target)
    root_entry = '\n[[package]]\nname = "hia-rea-asar-reference"\nversion = "0.0.0"\ndependencies = [\n' + ''.join(' "' + name + '",\n' for name in direct) + ']\n'
    lock = '# Exact subset of the original Runtime Cargo.lock.\nversion = 4\n' + root_entry
    for raw in old_lock.split("[[package]]")[1:]:
        value = tomllib.loads("[[package]]" + raw)["package"][0]
        if (value["name"], value["version"]) in closed:
            lock += "\n[[package]]" + raw.rstrip() + "\n"
    canonical = args.canonical_lock.read_bytes()
    canonical_packages = tomllib.loads(canonical.decode())["package"]
    admitted = {(p["name"], p["version"]): p for p in canonical_packages
                if p["name"] != "hia-rea-asar-reference"}
    assert set(admitted) <= closed, "canonical lock adds a non-original package"
    assert all(by_name[name][0] in admitted for name in direct)
    for key, package in admitted.items():
        old = by_id[key]
        assert package.get("source") == old.get("source"), key
        assert package.get("checksum") == old.get("checksum"), key
        for dependency in package.get("dependencies", []):
            parts = dependency.split()
            targets = [p for p in admitted if p[0] == parts[0]
                       and (len(parts) == 1 or p[1] == parts[1])]
            assert len(targets) == 1, dependency
    (out / "unformatted-original-subset.Cargo.lock").write_text(lock)
    (crate / "Cargo.lock").write_bytes(canonical)
    proof = {"schema":"hepta.runtime.rea-asar-original-method-binding.v1",
        "original_sources":pins,"unchanged_original_test_methods":9,
        "original_tests_sha256":pins[paths[2]]["sha256"],
        "all_original_assertions_and_fixture_bytes_preserved":True,
        "retained_parent_bodies":{name:hashlib.sha256(body.encode()).hexdigest() for name,body in selected.items()},
        "exact_original_dependency_packages":len(admitted),
        "complete_upstream_unified_feature_closure":len(closed),
        "unused_optional_upstream_packages":sorted(closed-set(admitted)),
        "canonical_lock_sha256":hashlib.sha256(canonical).hexdigest(),
        "helper_binding":"Original Request and all nine test methods are unchanged; inspect_file is bound to actual native HIA, including native JSON parsing, validation, hashing and member decisions",
        "product_or_test_execution_done":False}
    (out / "preparation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"crate":str(crate),"original_tests":9,"dependency_packages":len(admitted)},sort_keys=True))


if __name__ == "__main__":
    main()
