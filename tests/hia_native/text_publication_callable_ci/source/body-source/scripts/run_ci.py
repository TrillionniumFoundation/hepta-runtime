#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh CI-only body qualification with exact original, full buffers and guarded reading."""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence,SCOPE
from check_source import check
from prepare_reference import prepare,verify_reference

PROCESS_NAMES=("author","native-build","rust-version","cargo-fetch-seed","cargo-metadata",
    "cargo-build","cargo-test","original","native")

def run_process(output,name,argv,env=None,limit=180):
    folder=output/"processes";folder.mkdir(exist_ok=True)
    require(not (folder/(name+".json")).exists(),"process label reused")
    receipt=dict(argv=[str(x) for x in argv],cwd=str(output),limit_seconds=limit,
        started_ns=time.monotonic_ns(),timed_out=False,
        selected_env={key:env[key] for key in ("CARGO_HOME","CARGO_TARGET_DIR","RUSTC","RUSTUP_TOOLCHAIN") if env and key in env})
    (folder/(name+".stdin")).write_bytes(b"")
    with (folder/(name+".stdout")).open("xb") as out,(folder/(name+".stderr")).open("xb") as err:
        child=subprocess.Popen(receipt["argv"],cwd=output,env=env,stdin=subprocess.DEVNULL,
            stdout=out,stderr=err,start_new_session=True)
        receipt["pid"]=child.pid
        try:receipt["returncode"]=child.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            receipt["timed_out"]=True;os.killpg(child.pid,signal.SIGKILL);receipt["returncode"]=child.wait()
    receipt["elapsed_ns"]=time.monotonic_ns()-receipt["started_ns"]
    receipt["streams"]={suffix:pin(folder/(name+"."+suffix)) for suffix in ("stdin","stdout","stderr")}
    (folder/(name+".json")).write_bytes(canonical(receipt))
    require(receipt["returncode"]==0 and not receipt["timed_out"],"actual process failed: "+name)
    return receipt

def argv_table(origin):
    root=Path(origin["output"]);source=root/"source";rust=Path(origin["rust_bin"])
    py=[origin["python"],"-I","-S","-B"]
    return {
      "author":py+[str(source/"authoring/author_publication.py"),"--source",str(source),"--hepta",origin["hepta"],"--output",str(root/"generated")],
      "native-build":py+[str(source/"scripts/build_body.py"),"build","--source",str(source),"--hepta",origin["hepta"],"--output",str(root)],
      "rust-version":[str(rust/"rustc"),"--version","--verbose"],
      "cargo-fetch-seed":[str(rust/"cargo"),"fetch","--manifest-path",str(root/"reference/Cargo.toml")],
      "cargo-metadata":[str(rust/"cargo"),"metadata","--offline","--format-version","1","--manifest-path",str(root/"reference/Cargo.toml")],
      "cargo-build":[str(rust/"cargo"),"build","--locked","--offline","--manifest-path",str(root/"reference/Cargo.toml")],
      "cargo-test":[str(rust/"cargo"),"test","--locked","--offline","--manifest-path",str(root/"reference/Cargo.toml"),"--","--test-threads=1"],
      **{role:py+[str(source/"scripts/capture_body.py"),"--role",role,"--qualification",str(root),"--output",str(root/role),"--fixture",str(root/"fixtures")]
        for role in ("original","native")}
    }

def read_processes(output):
    origin=decode((output/"ORIGIN.json").read_bytes());expected=argv_table(origin)
    results={}
    for name in PROCESS_NAMES:
        record=decode((output/"processes"/(name+".json")).read_bytes())
        require(record["argv"]==expected[name] and record["cwd"]==origin["output"],"process command/source changed: "+name)
        require(record["returncode"]==0 and record["timed_out"] is False and record["limit_seconds"]==180
            and 0<=record["elapsed_ns"]<181_000_000_000 and type(record["pid"]) is int and record["pid"]>0,
            "actual process failed or deadline changed: "+name)
        for suffix in ("stdin","stdout","stderr"):
            require(record["streams"][suffix]==pin(output/"processes"/(name+"."+suffix)),"complete process stream changed")
        results[name]=record
    require((output/"processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "),"actual Rust differs")
    for role in ("original","native"):
        require((output/"processes"/(role+".stderr")).read_bytes()==b"","body capture stderr")
        require(decode((output/"processes"/(role+".stdout")).read_bytes())==decode((output/role/"capture.json").read_bytes()),
            "actual capture stdout differs")
    tests=(output/"processes/cargo-test.stdout").read_text()
    require("test result: ok. 8 passed; 0 failed;" in tests,"eight original tests not all completed")
    names=re.findall(r"\n\s*fn ([A-Za-z0-9_]+)\(\)",(output/"source/target/text_file_write_tests.rs").read_text())
    require(len(names)==8 and all("test publication::tests::linux::"+name+" ... ok" in tests for name in names),"original test names changed")
    return results

def read_all(source,output):
    from read_body import compare
    from registry_evidence import inventory
    source=Path(source);output=Path(output)
    identity=source_evidence(source)
    require(source_evidence(output/"source")==identity,"retained source differs")
    original=verify_reference(source)
    for path in (source/"reference").rglob("*"):
        if path.is_file():
            require(path.read_bytes()==(output/"reference"/path.relative_to(source/"reference")).read_bytes(),"original fixture source changed")
    process=read_processes(output)
    lock=pin(output/"reference/Cargo.lock")
    require(lock==decode((output/"LOCK.json").read_bytes()),"fresh locked closure changed")
    require(pin(output/"rust-target/debug/hepta-text-publication-body-original")==decode((output/"ORIGINAL_BINARY.json").read_bytes()),"original binary changed")
    registry=inventory(source,output)
    require(registry==decode((output/"REGISTRY.json").read_bytes()),"complete registry custody changed")
    result=compare(source,output)
    result["registry_packages"]=registry["used_registry_packages"]
    result["original_tests"]=8;result["original_source"]=original
    result["scope"]=SCOPE
    return result

def bounded(operation):
    def expired(signum,frame):raise TimeoutError("complete reader/control boundary exceeded 180 seconds")
    old=signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    try:return operation()
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,old)

def execute(source,hepta,rust_bin,output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","Rust/HIA execution restricted to CI")
    require(not output.exists(),"qualification output must be fresh");output.mkdir(parents=True)
    check(source);shutil.copytree(source,output/"source");source=output/"source"
    origin=dict(output=str(output),source=str(source),hepta=str(hepta),rust_bin=str(rust_bin),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin));commands=argv_table(origin)
    run_process(output,"author",commands["author"])
    run_process(output,"native-build",commands["native-build"])
    prepare(source,output)
    env=dict(os.environ);env.update(CARGO_HOME=str(output/"cargo-home"),CARGO_TARGET_DIR=str(output/"rust-target"),
        RUSTC=str(rust_bin/"rustc"),RUSTUP_TOOLCHAIN="1.95.0",PATH=str(rust_bin)+os.pathsep+env.get("PATH",""))
    for name in ("rust-version","cargo-fetch-seed","cargo-metadata"):
        run_process(output,name,commands[name],env=env)
    from registry_evidence import inventory
    (output/"REGISTRY.json").write_bytes(canonical(inventory(source,output,capture=True)))
    (output/"LOCK.json").write_bytes(canonical(pin(output/"reference/Cargo.lock")))
    for name in ("cargo-build","cargo-test"):run_process(output,name,commands[name],env=env)
    require(pin(output/"reference/Cargo.lock")==decode((output/"LOCK.json").read_bytes()),"locked build changed closure")
    (output/"ORIGINAL_BINARY.json").write_bytes(canonical(pin(output/"rust-target/debug/hepta-text-publication-body-original")))
    for role in ("original","native"):run_process(output,role,commands[role],env=env)
    fixture=output/"fixtures"
    if fixture.exists():
        require(not list(fixture.iterdir()),"completed fixture remained");fixture.rmdir()
    evidence=bounded(lambda:read_all(source,output))
    (output/"COMPARISON.json").write_bytes(canonical(evidence))
    from reader_controls import create,verify
    controls=output.parent/(output.name+"-reader-controls")
    bounded(lambda:create(source,output,controls))
    from readonly import guarded
    def operation():
        value=read_all(source,output);value["physical_controls"]=verify(source,output,controls);return value
    proof=bounded(lambda:guarded(operation,roots=[output,controls]))
    (output.parent/(output.name+"-readonly.json")).write_bytes(canonical(proof))
    print(json.dumps(dict(status=proof["evidence"]["status"],cases=proof["evidence"]["cases"],
        guards=len(proof["probes"]),original_tests=8,scope=SCOPE),sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("check","run","verify"))
    p.add_argument("--source",type=Path,required=True)
    for name in ("output","hepta","rust-bin"):p.add_argument("--"+name,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":print(json.dumps(check(source),sort_keys=True));return
    output=a.output.absolute()
    if a.mode=="run":execute(source,a.hepta.resolve(strict=True),a.rust_bin.resolve(strict=True),output)
    else:
        # Preload all reader modules before audit activation, without loading native code.
        from read_body import compare
        from registry_evidence import inventory
        from reader_controls import verify
        from readonly import guarded
        controls=output.parent/(output.name+"-reader-controls")
        def operation():
            value=read_all(source,output);value["physical_controls"]=verify(source,output,controls);return value
        proof=bounded(lambda:guarded(operation,roots=[source,output,controls]))
        print(json.dumps(proof,sort_keys=True))

if __name__=="__main__":main()
