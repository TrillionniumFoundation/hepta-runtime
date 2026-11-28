#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare an isolated observer retaining the original four multi-file tests."""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import tomllib
from pathlib import Path
SHA = lambda value: hashlib.sha256(value).hexdigest()
SOURCE_SHA = "c0728d40232f18ce6783098cff5a1897f78a4b22f5be0f3c6fec40916455deea"
TESTS_SHA = "40c22e63eeaca9456ffe71051548e82ff26a57d9e2c9a097f0cd441a3a720d03"

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    r=args.runtime.resolve(strict=True)
    raw=(r/"src/mcp/runtime/multi_read.rs").read_bytes()
    tests=(r/"src/mcp/runtime/multi_read_tests.rs").read_bytes()
    if SHA(raw)!=SOURCE_SHA or SHA(tests)!=TESTS_SHA:
        raise ValueError("Original multi-file source or four-test authority differs")
    source=raw.decode()
    start=source.index("const MAX_FILE_BYTES:")
    end=source.index("\npub async fn read(")
    fragment=source[start:end]
    original_lock=(r/"Cargo.lock").read_bytes()
    lock=tomllib.loads(original_lock.decode())
    dependencies={p["name"]:p for p in lock["package"] if p["name"] in
        {"anyhow","rmcp","schemars","serde","serde_json"}}
    expected={"anyhow":"1.0.104","rmcp":"3.9.0","schemars":"1.2.2",
        "serde":"1.0.229","serde_json":"1.0.151"}
    if {k:v["version"] for k,v in dependencies.items()}!=expected:
        raise ValueError("Current production dependency versions differ")
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/"src").mkdir()
    (args.output/"src/original.rs").write_text(fragment)
    (args.output/"src/original_tests.rs").write_bytes(tests)
    shutil.copyfile(Path(__file__).with_name("reference_main.rs"),args.output/"src/main.rs")
    (args.output/"Cargo.lock").write_bytes(original_lock)
    (args.output/"Cargo.toml").write_text('''[package]
name = "hepta-public-multi-read-original"
version = "0.1.0"
edition = "2021"
rust-version = "1.95"

[dependencies]
anyhow = "=1.0.104"
rmcp = { version = "=3.9.0", features = ["server", "macros", "transport-io", "transport-streamable-http-server"] }
schemars = "=1.2.2"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }

[workspace]
''')
    report={"schema":"hepta.runtime.public-multi-original-source.v1",
        "source_sha256":SOURCE_SHA,"original_tests_sha256":TESTS_SHA,
        "source_fragment_bytes":len(fragment.encode()),"source_fragment_sha256":SHA(fragment.encode()),
        "original_test_count":4,"production_dependencies":dependencies,
        "original_cargo_lock_sha256":SHA(original_lock),
        "all_original_test_bodies_unchanged":True,"source_fragment_bytes_unchanged":True,
        "runtime_replaced":False}
    (args.output/"SOURCE.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
