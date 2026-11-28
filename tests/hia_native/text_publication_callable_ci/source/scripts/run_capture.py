#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh private callable capture; final qualification additionally requires the strict journal reader."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import encoded,decode,pin,require,sources,syntax,SCOPE
from read_callable_build import verify as read_build

def run(source,hepta,rust_bin,output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","semantic execution restricted to CI")
    require(not output.exists(),"fresh qualification required");output.mkdir(parents=True)
    identity=syntax(source);shutil.copytree(source,output/"source");source=output/"source"
    body=source/"body-source";sys.path.insert(0,str(body/"scripts"))
    from run_ci import run_process
    from prepare_reference import prepare,verify_reference
    from registry_evidence import inventory
    from common import source_evidence
    ref=output/"body";ref.mkdir();shutil.copytree(body,ref/"source")
    origin=dict(output=str(ref),source=str(ref/"source"),hepta=str(hepta),rust_bin=str(rust_bin),python=sys.executable)
    (ref/"ORIGIN.json").write_bytes(encoded(origin))
    top=dict(output=str(output),source=str(source),hepta=str(hepta),rust_bin=str(rust_bin),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(encoded(top))
    py=[sys.executable,"-I","-S","-B"]
    run_process(output,"native-build",py+[str(source/"scripts/build_callable.py"),"build","--source",str(source),
        "--hepta",str(hepta),"--output",str(output/"native-build")])
    (output/"BUILD_READBACK.json").write_bytes(encoded(read_build(source,output/"native-build")))
    prepare(body,ref)
    env=dict(os.environ);env.update(CARGO_HOME=str(ref/"cargo-home"),CARGO_TARGET_DIR=str(ref/"rust-target"),
        RUSTC=str(rust_bin/"rustc"),RUSTUP_TOOLCHAIN="1.95.0",PATH=str(rust_bin)+os.pathsep+env.get("PATH",""))
    commands={
        "rust-version":[str(rust_bin/"rustc"),"--version","--verbose"],
        "cargo-fetch-seed":[str(rust_bin/"cargo"),"fetch","--manifest-path",str(ref/"reference/Cargo.toml")],
        "cargo-metadata":[str(rust_bin/"cargo"),"metadata","--offline","--format-version","1","--manifest-path",str(ref/"reference/Cargo.toml")],
        "cargo-build":[str(rust_bin/"cargo"),"build","--locked","--offline","--manifest-path",str(ref/"reference/Cargo.toml")],
        "cargo-test":[str(rust_bin/"cargo"),"test","--locked","--offline","--manifest-path",str(ref/"reference/Cargo.toml"),"--","--test-threads=1"],
        "original":py+[str(ref/"source/scripts/capture_body.py"),"--role","original","--qualification",str(ref),
            "--output",str(ref/"original"),"--fixture",str(ref/"fixtures")],
        "native":py+[str(source/"scripts/capture_callable.py"),"--source",str(source),"--build",str(output/"native-build"),
            "--output",str(ref/"native"),"--fixture",str(ref/"fixtures")]}
    (output/"COMMANDS.json").write_bytes(encoded(commands))
    for name in ("rust-version","cargo-fetch-seed","cargo-metadata"):run_process(ref,name,commands[name],env=env)
    require((ref/"processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "),"wrong Rust")
    (ref/"REGISTRY.json").write_bytes(encoded(inventory(body,ref,capture=True)))
    (ref/"LOCK.json").write_bytes(encoded(pin(ref/"reference/Cargo.lock")))
    for name in ("cargo-build","cargo-test"):run_process(ref,name,commands[name],env=env)
    require(pin(ref/"reference/Cargo.lock")==decode((ref/"LOCK.json").read_bytes()),"locked closure changed")
    (ref/"ORIGINAL_BINARY.json").write_bytes(encoded(pin(ref/"rust-target/debug/hepta-text-publication-body-original")))
    for role in ("original","native"):run_process(ref,role,commands[role],env=env)
    fixture=ref/"fixtures"
    if fixture.exists():require(not list(fixture.iterdir()),"fixture remains");fixture.rmdir()
    from read_body import lane_rows
    native=lane_rows(body,ref,"native");original=lane_rows(body,ref,"original")
    require(native[4]==original[4],"complete current original body wire/filesystem differs")
    require("test result: ok. 8 passed; 0 failed;" in (ref/"processes/cargo-test.stdout").read_text(),"original eight tests failed")
    result=dict(status="DEVELOPMENT_COMPLETE_CALLABLE_CAPTURE",cases=len(native[2]),private_controls=native[1]["private_controls"],
        original_tests=8,registry_packages=inventory(body,ref)["used_registry_packages"],executable=pin(output/"native-build/text-publication-callable.elf"),
        source=sources(source),full_wire_and_filesystem_equal=True,strict_journal_qualification_complete=False,scope=SCOPE)
    (output/"CAPTURE_RESULT.json").write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("check","run"))
    p.add_argument("--source",type=Path,required=True)
    for name in ("output","hepta","rust-bin"):p.add_argument("--"+name,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":print(json.dumps(syntax(source),sort_keys=True))
    else:run(source,a.hepta.resolve(strict=True),a.rust_bin.resolve(strict=True),a.output.absolute())
if __name__=="__main__":main()
