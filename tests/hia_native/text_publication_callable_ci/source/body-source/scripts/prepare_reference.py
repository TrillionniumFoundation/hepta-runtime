#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Verify verbatim original spans and create an exact-version Cargo seed."""
from pathlib import Path
import hashlib
import re
import shutil
import tomllib
from common import canonical, decode, owned, require, sha, source_evidence

def verify_reference(source):
    source=Path(source);origin=decode(owned(source,"reference/ORIGIN.json").read_bytes())
    original=owned(source,"target/text_file_write.rs").read_bytes()
    output=owned(source,"reference/src/publication.rs").read_bytes()
    require(sha(original)==origin["original"]["sha256"] and len(original)==origin["original"]["bytes"],"original publication changed")
    require(sha(output)==origin["output"]["sha256"] and len(output)==origin["output"]["bytes"],"body reference changed")
    for span in origin["spans"]:
        raw=original[span["start"]:span["end"]]
        require(len(raw)==span["bytes"] and sha(raw)==span["sha256"] and output.count(raw)==1,"verbatim original span changed")
    tests=owned(source,"target/text_file_write_tests.rs").read_bytes()
    require(tests==owned(source,"reference/src/text_file_write_tests.rs").read_bytes()
        and sha(tests)==origin["original_tests"]["sha256"],"original eight tests changed")
    require(tests.count(b"#[test]")==8,"original tests omitted")
    return origin

def prepare(source,output):
    source=Path(source);output=Path(output)
    verify_reference(source)
    shutil.copytree(source/"reference",output/"reference")
    raw=owned(source,"target/Cargo.lock").read_text()
    blocks=raw.split("[[package]]")
    registry=[]
    for body in blocks[1:]:
        value=tomllib.loads("[[package]]"+body)["package"][0]
        if value.get("source"):registry.append("[[package]]"+body)
    root='[[package]]\nname = "hepta-text-publication-body-original"\nversion = "0.0.0"\ndependencies = [\n "anyhow",\n "libc",\n "serde_json",\n "sha2",\n "tempfile",\n]\n\n'
    seed="# Exact target package seed; Cargo may only remove unused target entries.\nversion = 4\n\n"+root+"".join(registry)
    (output/"reference/Cargo.lock").write_text(seed)
    (output/"reference-seed.lock").write_text(seed)
