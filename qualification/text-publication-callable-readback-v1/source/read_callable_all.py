#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact retained original/native callable comparison; imports perform no native execution."""
from pathlib import Path
import re
from callable_common import decode,encoded,owned,pin,require,sources,SCOPE
from read_callable_build import verify as read_build
from read_callable_physical import physical
from prepare_reference import verify_reference
from registry_evidence import inventory as registry_inventory
from read_body import lane_rows
from common import source_evidence
MANIFEST=dict(bytes=15480,sha256="982cb3ad3fe24da3019ebc9b3cdd847b34b78877a65e3a1cbb94f69b9b657226")
ELF=dict(bytes=565248,sha256="97360b798ed61b8095dd391aa8945ec9df011ce166f4b438805558db1829efcb")
NAMES=("rust-version","cargo-fetch-seed","cargo-metadata","cargo-build","cargo-test","original","native")

def commands(origin):
    top=Path(origin["output"]);source=top/"source";body=top/"body";rust=Path(origin["rust_bin"])
    py=[origin["python"],"-I","-S","-B"]
    result={
        "rust-version":[str(rust/"rustc"),"--version","--verbose"],
        "cargo-fetch-seed":[str(rust/"cargo"),"fetch","--manifest-path",str(body/"reference/Cargo.toml")],
        "cargo-metadata":[str(rust/"cargo"),"metadata","--offline","--format-version","1","--manifest-path",str(body/"reference/Cargo.toml")],
        "cargo-build":[str(rust/"cargo"),"build","--locked","--offline","--manifest-path",str(body/"reference/Cargo.toml")],
        "cargo-test":[str(rust/"cargo"),"test","--locked","--offline","--manifest-path",str(body/"reference/Cargo.toml"),"--","--test-threads=1"],
        "original":py+[str(body/"source/scripts/capture_body.py"),"--role","original","--qualification",str(body),
            "--output",str(body/"original"),"--fixture",str(body/"fixtures")],
        "native":py+[str(source/"scripts/capture_callable.py"),"--source",str(source),"--build",str(top/"native-build"),
            "--output",str(body/"native"),"--fixture",str(body/"fixtures")]}
    build=py+[str(source/"scripts/build_callable.py"),"build","--source",str(source),"--hepta",origin["hepta"],"--output",str(top/"native-build")]
    return result,build

def process(root,name,argv,cwd,selected):
    record=decode(owned(root,"processes/"+name+".json").read_bytes())
    require(record["argv"]==argv and record["cwd"]==cwd and record["selected_env"]==selected,
        "actual retained process command/environment differs: "+name)
    require(record["returncode"]==0 and record["timed_out"] is False and record["limit_seconds"]==180
        and type(record["elapsed_ns"]) is int and 0<=record["elapsed_ns"]<181_000_000_000
        and type(record["pid"]) is int and record["pid"]>0,"actual process/deadline differs: "+name)
    for suffix in ("stdin","stdout","stderr"):
        require(record["streams"][suffix]==pin(owned(root,"processes/"+name+"."+suffix)),"complete process stream differs: "+name)
    require(owned(root,"processes/"+name+".stdin").read_bytes()==b"","retained subprocess input differs")
    return record

def read_all(root):
    root=Path(root);source=root/"source";body=root/"body";body_source=source/"body-source"
    require(pin(owned(source,"SOURCE_MANIFEST.json"))==MANIFEST,"captured source manifest changed")
    identity=sources(source);require(identity["files"]==60,"captured source closure differs")
    require(source_evidence(body/"source")==source_evidence(body_source),"original observer source changed")
    build=read_build(source,root/"native-build")
    require(build["executable"]==ELF and decode(owned(root,"BUILD_READBACK.json").read_bytes())==build,
        "retained full fresh build readback differs")
    original=verify_reference(body_source)
    for file in (body_source/"reference").rglob("*"):
        if file.is_file():require(file.read_bytes()==owned(body/"reference",file.relative_to(body_source/"reference").as_posix()).read_bytes(),
            "actual original fixture file changed")
    origin=decode(owned(root,"ORIGIN.json").read_bytes());body_origin=decode(owned(body,"ORIGIN.json").read_bytes())
    require(origin["source"]==str(Path(origin["output"])/"source")
        and body_origin==dict(output=str(Path(origin["output"])/"body"),source=str(Path(origin["output"])/"body/source"),
            hepta=origin["hepta"],rust_bin=origin["rust_bin"],python=origin["python"]),"retained path relocation origin differs")
    table,build_argv=commands(origin)
    require(decode(owned(root,"COMMANDS.json").read_bytes())==table,"actual command table differs")
    process(root,"native-build",build_argv,origin["output"],{})
    require(owned(root,"processes/native-build.stderr").read_bytes()==b"","native build stderr differs")
    build_stdout=decode(owned(root,"processes/native-build.stdout").read_bytes())
    require(build_stdout==decode(owned(root,"native-build/BUILD.json").read_bytes()),"actual build stdout differs")
    old_body=Path(body_origin["output"])
    selected=dict(CARGO_HOME=str(old_body/"cargo-home"),CARGO_TARGET_DIR=str(old_body/"rust-target"),
        RUSTC=str(Path(origin["rust_bin"])/"rustc"),RUSTUP_TOOLCHAIN="1.95.0")
    for name in NAMES:process(body,name,table[name],str(old_body),selected)
    require(owned(body,"processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "),"Rust compiler changed")
    for role in ("original","native"):
        require(owned(body,"processes/"+role+".stderr").read_bytes()==b""
            and decode(owned(body,"processes/"+role+".stdout").read_bytes())==decode(owned(body,role+"/capture.json").read_bytes()),
            "complete capture process stdout/stderr differs")
    tests=owned(body,"processes/cargo-test.stdout").read_text()
    names=re.findall(r"\n\s*fn ([A-Za-z0-9_]+)\(\)",owned(body_source,"target/text_file_write_tests.rs").read_text())
    require(len(names)==8 and "test result: ok. 8 passed; 0 failed;" in tests
        and all("test publication::tests::linux::"+name+" ... ok" in tests for name in names),"eight exact original tests differ")
    require(pin(owned(body,"reference/Cargo.lock"))==decode(owned(body,"LOCK.json").read_bytes())
        and pin(owned(body,"rust-target/debug/hepta-text-publication-body-original"))==decode(owned(body,"ORIGINAL_BINARY.json").read_bytes()),
        "original actual executable or retained lock differs")
    registry=registry_inventory(body_source,body)
    require(registry==decode(owned(body,"REGISTRY.json").read_bytes()) and registry["used_registry_packages"]==33,
        "complete actual original crate/source closure differs")
    native=lane_rows(body_source,body,"native");old=lane_rows(body_source,body,"original")
    require(native[4]==old[4],"full original/native wire or filesystem differs")
    require(native[1]["callable_source"]==identity and native[1]["callable_build"]==pin(root/"native-build/BUILD.json")
        and native[1]["scope"]==dict(private_synchronous_callable=True,public_route=False,configured_path_authority=False,
            scope_cache_forget=False,async_task_lifecycle=False),"actual callable source/scope differs")
    evidence=physical(native[0],native[1],native[2],native[3],root/"native-build")
    original_buffers=old[3].finish()
    require(original_buffers["complete_images"]==old[1]["complete_buffer_images"]
        and original_buffers["logical_buffer_bytes"]==old[1]["logical_buffer_bytes"],"original full buffer accounting differs")
    retained=decode(owned(root,"CAPTURE_RESULT.json").read_bytes())
    expected=dict(status="DEVELOPMENT_COMPLETE_CALLABLE_CAPTURE",cases=82,private_controls=30,original_tests=8,
        registry_packages=33,executable=ELF,source=identity,full_wire_and_filesystem_equal=True,
        strict_journal_qualification_complete=False,scope=SCOPE)
    require(retained==expected,"retained development status changed")
    require(not (body/"fixtures").exists(),"completed owned fixture was not retired")
    return dict(status="COMPLETE_PRIVATE_CALLABLE_ORIGINAL_FILES_JOURNAL_PASS",cases=len(native[2]),
        original_tests=8,registry_packages=33,source=identity,build=build,physical=evidence,
        original_buffers=original_buffers,original_source=original,
        full_wire_and_filesystem_equal=True,version_normalization="only after all seven actual stat fields verified",
        workspace_observation="complete final context/workspace/output/input for every body invocation and complete old/new workspace at growth",
        per_body_call_workspace_before_after_captured=False,scope=SCOPE)
