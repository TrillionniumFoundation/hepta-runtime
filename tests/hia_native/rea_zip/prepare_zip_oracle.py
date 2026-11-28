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
                    default=Path(__file__).with_name("rea_zip_oracle.Cargo.lock"))
    args = ap.parse_args()
    source, out = args.source, args.output
    out.mkdir(mode=0o700, exist_ok=False)
    original = out / "original"
    paths = ["src/mcp/rea_artifact_zip.rs", "src/mcp/rea_artifact_zip_parser.rs",
             "src/mcp/rea_artifact_zip_parser_tests.rs", "src/mcp/rea_files.rs",
             "tests/fixtures/rea_artifact_sample.apk", "tests/fixtures/rea_artifact_sample.jar",
             "tests/fixtures/rea_artifact_sample.zip", "tests/fixtures/rea_application/owned-aapt2.apk",
             "Cargo.toml", "Cargo.lock"]
    pins = {}
    for name in paths:
        target = original / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, target)
        raw = target.read_bytes()
        assert raw == (source / name).read_bytes()
        pins[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    crate = out / "crate"
    (crate / "src/zip").mkdir(parents=True)
    parent = (original / paths[0]).read_text()
    original_parser = (original / paths[1]).read_text()
    files = (original / paths[3]).read_text()
    selected = {"ArchiveFilter": block(parent, "pub enum ArchiveFilter"),
                "matches": block(parent, "impl ArchiveFilter"),
                "hex": block(parent, "fn hex("),
                "observed_version": block(parent, "fn observed_version("),
                "ensure_unchanged": block(files, "pub(super) fn ensure_unchanged("),
                "Request": block(original_parser, "pub(super) struct Request")}
    imports = "use anyhow::{anyhow,bail,Context,Result};\nuse serde::{Deserialize,Serialize};\nuse serde_json::{json,Value};\nuse sha2::{Digest,Sha256};\nuse std::fmt::Write as _;\n"
    zip_source = imports + "const MAX_DIRECTORY_BYTES:u64=16*1024*1024;\n"
    zip_source += '#[derive(Debug,Clone,Copy,Default,Deserialize,Serialize)]\n#[serde(rename_all="snake_case")]\n'
    zip_source += selected["ArchiveFilter"] + "\n" + selected["matches"] + "\n"
    zip_source += selected["hex"] + "\n" + selected["observed_version"] + "\n"
    zip_source += '#[cfg(not(feature="native"))]\n#[path=' + json.dumps(str(original / paths[1])) + "]\nmod parser;\n"
    zip_source += '#[cfg(feature="native")]\n#[path="native_parser.rs"]\nmod parser;\n'
    zip_source += '''
pub fn inspect(request: &Value) -> Result<Value> {
    let path = request["path"].as_str().context("fixture path")?;
    let mut file = std::fs::File::open(path)?;
    let typed: parser::Request = serde_json::from_value(json!({
        "filter":request.get("filter").cloned().unwrap_or(json!("all")),
        "offset":request.get("offset").cloned().unwrap_or(json!(0)),
        "limit":request.get("limit").cloned().unwrap_or(json!(64))
    }))?;
    parser::inspect_file(&mut file, &typed)
}
'''
    (crate / "src/zip/mod.rs").write_text(zip_source)
    native = imports + "use super::{ArchiveFilter,MAX_DIRECTORY_BYTES};\nuse std::fs::File;\nuse std::io::{Read,Seek,SeekFrom};\n"
    native += '#[derive(Debug,Clone,Deserialize,Serialize)]\n#[serde(deny_unknown_fields)]\n' + selected["Request"] + "\n"
    native += '''
pub(super) fn inspect_file(file: &mut File, request: &Request) -> Result<Value> {
    let filter = match request.filter {
        ArchiveFilter::All=>0,ArchiveFilter::Manifest=>1,ArchiveFilter::Dex=>2,
        ArchiveFilter::NativeLibrary=>3,ArchiveFilter::Resource=>4,
        ArchiveFilter::JavaClass=>5,ArchiveFilter::SignatureMarker=>6
    };
    crate::native_driver::inspect(file,filter,request.offset,request.limit)
}
fn extra_fields(bytes:&[u8])->Result<Vec<u16>> {
    serde_json::from_value(crate::native_driver::field(1,bytes,0,0,0)?)
        .context("typed native extra-field list")
}
fn member_name(bytes:&[u8],flags:u16)->Result<(String,&'static str)> {
    let value=crate::native_driver::field(2,bytes,flags,0,0)?;
    let name=value[0].as_str().context("native member name")?.to_owned();
    let encoding=match value[1].as_str() {
        Some("ascii")=>"ascii",Some("utf8")=>"utf8",_=>bail!("native encoding differs")
    };
    Ok((name,encoding))
}
fn validate_local_extra(bytes:&[u8],method:u16,flags:u16,payload_offset:u64)->Result<()> {
    let value=crate::native_driver::field(3,bytes,flags,method,payload_offset)?;
    if !value.is_null(){bail!("native local-extra result differs");}
    Ok(())
}
'''
    native += '#[cfg(test)]\n#[path=' + json.dumps(str(original / paths[2])) + "]\nmod rea_artifact_zip_parser_tests;\n"
    (crate / "src/zip/native_parser.rs").write_text(native)
    (crate / "src/rea_files.rs").write_text("use anyhow::{bail,Result};\n" + selected["ensure_unchanged"] + "\n")
    (crate / "src/lib.rs").write_text('pub mod zip;\nmod rea_files;\n#[cfg(feature="native")]\nmod native_driver;\n')
    shutil.copy2(args.native_driver, crate / "src/native_driver.rs")
    (crate / "src/main.rs").write_text('''
use std::io::{BufRead,Write};
use serde_json::{json,Value};
fn main()->anyhow::Result<()> {
    let stdin=std::io::stdin();
    let mut stdout=std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let request:Value=serde_json::from_str(&line?)?;
        let response=match hia_rea_zip_reference::zip::inspect(&request) {
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
name = "hia-rea-zip-reference"
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
    root_entry = '\n[[package]]\nname = "hia-rea-zip-reference"\nversion = "0.0.0"\ndependencies = [\n' + ''.join(' "' + name + '",\n' for name in direct) + ']\n'
    lock = '# Exact subset of the original Runtime Cargo.lock.\nversion = 4\n' + root_entry
    for raw in old_lock.split("[[package]]")[1:]:
        value = tomllib.loads("[[package]]" + raw)["package"][0]
        if (value["name"], value["version"]) in closed:
            lock += "\n[[package]]" + raw.rstrip() + "\n"
    canonical = args.canonical_lock.read_bytes()
    canonical_packages = tomllib.loads(canonical.decode())["package"]
    admitted = {(p["name"], p["version"]): p for p in canonical_packages
                if p["name"] != "hia-rea-zip-reference"}
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
    proof = {"schema":"hepta.runtime.rea-zip-original-method-binding.v1",
        "original_sources":pins,"unchanged_original_test_methods":8,
        "original_tests_sha256":pins[paths[2]]["sha256"],
        "all_original_assertions_and_fixture_bytes_preserved":True,
        "retained_parent_bodies":{name:hashlib.sha256(body.encode()).hexdigest() for name,body in selected.items()},
        "exact_original_dependency_packages":len(admitted),
        "complete_upstream_unified_feature_closure":len(closed),
        "unused_optional_upstream_packages":sorted(closed-set(admitted)),
        "canonical_lock_sha256":hashlib.sha256(canonical).hexdigest(),
        "helper_binding":"Original Request and test bytes; native backend binds inspect_file, extra_fields, member_name and validate_local_extra to actual HIA entry",
        "product_or_test_execution_done":False}
    (out / "preparation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"crate":str(crate),"original_tests":8,"dependency_packages":len(admitted)},sort_keys=True))


if __name__ == "__main__":
    main()
