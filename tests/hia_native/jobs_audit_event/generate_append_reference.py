#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Capture the complete unchanged original append and namespace implementations."""
from pathlib import Path
import hashlib
import json
import re
import tomllib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent / "append_reference"
HEADER = """// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original jobs audit append reference, isolated from runtime installation.
"""


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    source = (ROOT / "src/mcp/runtime/jobs.rs").read_bytes()
    start = source.index(b"struct PreparedAudit {")
    end = source.index(b"fn observation_audit_unavailable()", start)
    clock_start = source.index(b"fn now_ms() -> u128 {")
    clock_end = source.index(b"\n}\n", clock_start) + 3
    block, clock = source[start:end], source[clock_start:clock_end]
    namespace = (ROOT / "src/mcp/runtime/namespace_version.rs").read_bytes()
    (HERE / "src").mkdir(parents=True, exist_ok=True)
    wrapper = """
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{fs::{File, OpenOptions}, io::Write, path::{Path, PathBuf},
          sync::{Mutex, OnceLock}, time::{SystemTime, UNIX_EPOCH}};
static AUDIT_LOCK: OnceLock<Mutex<Option<AuditReadiness>>> = OnceLock::new();
struct AuditConfig { state_dir: PathBuf }
fn runtime_config() -> Result<AuditConfig> {
    bail!("configuration installation is outside this isolated original reference")
}
"""
    capture = """
pub fn capture(root: &Path, host: &str, subject: &str, fail_sync: &str) -> Value {
    let prepared = prepare_audit_at(root.join("audit/events.jsonl"),
        "native_binary_write", host, subject, &json!({"op":"write"}));
    let prepared = match prepared {
        Ok(value) => value,
        Err(error) => return json!({"error":error.to_string()}),
    };
    let event = String::from_utf8(prepared.line.clone()).unwrap();
    let preparation = prepared.path.parent().map_or(Ok(()), |parent| {
        std::fs::create_dir_all(parent).map_err(anyhow::Error::from)
    });
    let mut readiness = AUDIT_LOCK.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let mut file_syncs = 0;
    let mut directories = Vec::new();
    let result = append_audit_prepared_with(prepared, &mut readiness, preparation,
        |file| {
            file_syncs += 1;
            if fail_sync == "file" { return Err(std::io::Error::from_raw_os_error(5).into()); }
            file.sync_data()?;
            Ok(())
        },
        |directory| {
            use std::os::unix::fs::MetadataExt;
            let metadata = directory.metadata()?;
            directories.push((metadata.dev(), metadata.ino()));
            if fail_sync == format!("directory:{}", directories.len()-1) {
                return Err(std::io::Error::from_raw_os_error(5).into());
            }
            directory.sync_all()?;
            Ok(())
        });
    json!({"ok":result.is_ok(), "error":result.err().map(|e|e.to_string()),
           "event":event,"file_syncs":file_syncs,"directories":directories,
           "ready":readiness.is_some()})
}
pub fn reset() { *AUDIT_LOCK.get_or_init(|| Mutex::new(None)).lock().unwrap() = None; }
"""
    raw = HEADER.encode() + b"#![allow(dead_code)]\n" + wrapper.encode() + clock + block + capture.encode()
    (HERE / "src/original.rs").write_bytes(raw)
    (HERE / "src/namespace_version.rs").write_bytes(namespace)
    main_rs = HEADER + """
use std::{io::{self, BufRead}, path::Path};
use serde_json::{Value, json};
mod original;
mod namespace_version;
fn main() -> anyhow::Result<()> {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let result = if value["reset"].as_bool() == Some(true) {
            original::reset(); json!({"reset":true})
        } else {
            original::capture(Path::new(value["root"].as_str().unwrap()),
                value["host"].as_str().unwrap(), value["subject"].as_str().unwrap(),
                value["fail_sync"].as_str().unwrap_or(""))
        };
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}
"""
    (HERE / "src/main.rs").write_text(main_rs)
    lock = (ROOT / "Cargo.lock").read_text()
    packages = tomllib.loads(lock)["package"]
    names = ("anyhow", "serde", "serde_json", "libc", "sha2")
    selected = {name: next(p for p in packages if p["name"] == name) for name in names}
    manifest = '[package]\nname = "jobs-audit-append-original"\nversion = "0.1.0"\nedition = "2024"\n\n[workspace]\n\n[dependencies]\n'
    for name, value in selected.items():
        features = ', features = ["derive"]' if name == "serde" else ', features = ["float_roundtrip", "raw_value"]' if name == "serde_json" else ''
        manifest += f'{name} = {{ version = "={value["version"]}"{features} }}\n'
    (HERE / "Cargo.toml").write_text(manifest)
    ledger = dict(schema="hepta.runtime.jobs-audit-append.original-source.v1",
                  jobs_source=pin(source), namespace_source=pin(namespace),
                  source_lock=pin(lock.encode()), selected_direct_dependencies=selected,
                  exact_blocks=[dict(name="complete audit implementation",start=start,end=end,**pin(block)),
                                dict(name="now_ms",start=clock_start,end=clock_end,**pin(clock))],
                  wrapper_scope="Unchanged prepare_audit_at and append_audit_prepared_with, unchanged namespace implementation; test-only typed input/configuration replacement and actual synchronization counters.",
                  public_runtime_configuration_qualified=False,
                  files={str(p.relative_to(HERE)):pin(p.read_bytes()) for p in sorted(HERE.rglob('*')) if p.is_file() and p.name != 'SOURCE.json'})
    if (HERE / "Cargo.lock").exists():
        expected = {(p["name"], p["version"]): p.get("checksum") for p in packages}
        used = tomllib.loads((HERE / "Cargo.lock").read_text())["package"]
        used = [p for p in used if p.get("source")]
        for p in used:
            if expected.get((p["name"], p["version"])) != p.get("checksum"):
                raise ValueError("reference dependency differs from original lock: " + p["name"])
        ledger["locked_dependencies"] = [{k:p[k] for k in ("name", "version", "source", "checksum")} for p in used]
        ledger["lock_scope"] = "Original package versions and checksums; feature dependency edges projected for this isolated original reference."
    (HERE / "SOURCE.json").write_text(json.dumps(ledger,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"directory":str(HERE),"original_blocks":ledger["exact_blocks"],"namespace":pin(namespace)}))


if __name__ == "__main__":
    main()
