#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Run the exact target direct-SSH test modules in their original Rust hierarchy."""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, time, tomllib
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence

HEADER="// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n"
def process(output,name,argv,env,limit=180):
    start=time.monotonic_ns(); child=None; timed=False; cleanup=[]
    row=dict(argv=[str(x) for x in argv],limit_seconds=limit,started_ns=start,
        environment={k:env[k] for k in ("CARGO_HOME","CARGO_TARGET_DIR","RUSTC","RUSTDOC") if k in env})
    try:
        with (output/(name+".stdout")).open("xb") as out,(output/(name+".stderr")).open("xb") as err:
            child=subprocess.Popen(row["argv"],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                env=env,start_new_session=True)
            row["pid"]=child.pid;row["pgid"]=child.pid
            try:child.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed=True
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait()
            row["returncode"]=child.returncode
    finally:
        if child is not None and child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait()
            cleanup.append("owned process group killed and waited")
        row.update(elapsed_ns=time.monotonic_ns()-start,timed_out=timed,cleanup=cleanup)
        row["streams"]={s:pin(output/(name+"."+s)) for s in ("stdout","stderr") if (output/(name+"."+s)).exists()}
        (output/(name+".json")).write_bytes(canonical(row))
    require(not timed and row.get("returncode")==0,"original process failed: "+name)
    return row

def main():
    parser=argparse.ArgumentParser()
    for name in ("source","target","toolchain","output"):parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args();source=a.source.resolve();target=a.target.resolve();toolchain=a.toolchain.resolve();output=a.output.absolute()
    require(os.environ.get("GITHUB_ACTIONS")=="true","Rust reference restricted to CI")
    require(not output.exists(),"fresh output");output.mkdir(parents=True)
    binding=source_evidence(source);shutil.copytree(source,output/"recipe-source")
    for f in source.rglob("*.py"):compile(f.read_bytes(),str(f),"exec")
    exact={"ssh_direct.rs":"src/mcp/runtime/ssh_direct.rs","ssh_direct_tests.rs":"src/mcp/runtime/ssh_direct_tests.rs",
        "ssh_direct_entry_tests.rs":"src/mcp/runtime/ssh_direct_entry_tests.rs","ssh.rs":"src/mcp/runtime/ssh.rs",
        "target-Cargo.toml":"Cargo.toml","target-Cargo.lock":"Cargo.lock"}
    originals={}
    for local,remote in exact.items():
        raw=(source/"reference"/local).read_bytes()
        require(raw==(target/remote).read_bytes(),"unchanged target differs: "+remote)
        originals[remote]=pin(source/"reference"/local)
    target_head=subprocess.run(["git","-C",str(target),"rev-parse","HEAD"],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30).stdout.strip().decode()
    require(target_head=="d3d75c30719db966b004756f610007a7c723729e","target HEAD differs")
    crate=output/"reference";module=crate/"src/mcp/runtime/ssh";module.mkdir(parents=True)
    wrappers={"src/lib.rs":HEADER+"//! Exact target direct-SSH original test reference.\npub mod mcp;\n",
        "src/mcp/mod.rs":HEADER+"//! Original module hierarchy for the unchanged parent-death test.\npub mod runtime;\n",
        "src/mcp/runtime/mod.rs":HEADER+"//! Runtime transport reference only.\npub mod ssh;\n"}
    text=(source/"reference/ssh.rs").read_text()
    begin=text.index("async fn read_bounded(");end=text.index("\npub async fn run_capture(",begin)
    bounded=text[begin:end]
    wrappers["src/mcp/runtime/ssh/mod.rs"]=HEADER+"""//! Unchanged bounded stream reader surrounding the complete direct owner.
use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt};
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
#[path = "ssh_direct.rs"]
mod direct;
"""+bounded
    for path,raw in wrappers.items():
        destination=crate/path;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(raw)
    for name in ("ssh_direct.rs","ssh_direct_tests.rs","ssh_direct_entry_tests.rs"):
        shutil.copyfile(source/"reference"/name,module/name)
    target_lock=tomllib.loads((source/"reference/target-Cargo.lock").read_text())
    all_packages=target_lock["package"]
    def version(name):
        rows=[p["version"] for p in all_packages if p["name"]==name and p.get("source","").startswith("registry+")]
        require(len(rows)==1,"ambiguous exact direct dependency "+name)
        return rows[0]
    dependencies={name:version(name) for name in ("anyhow","tokio","tokio-util","serde_json","libc","tempfile")}
    cargo="""[package]
name = "hepta-ssh-direct-original-reference"
version = "0.1.0"
edition = "2021"
rust-version = "1.95"
license = "Apache-2.0"
[dependencies]
anyhow = "={anyhow}"
tokio = {{ version = "={tokio}", features = ["rt-multi-thread", "macros", "process", "fs", "sync", "signal", "io-std", "io-util", "net", "time"] }}
tokio-util = {{ version = "={tokio-util}", features = ["codec"] }}
serde_json = {{ version = "={serde_json}", features = ["float_roundtrip", "raw_value"] }}
libc = "={libc}"
[dev-dependencies]
tempfile = "={tempfile}"
[profile.dev]
opt-level = 1
debug = true
overflow-checks = true
""".format(**dependencies)
    (crate/"Cargo.toml").write_text(cargo)
    shutil.copyfile(source/"reference/target-Cargo.lock",crate/"Cargo.lock")
    environment=dict(os.environ);environment.update(CARGO_HOME=str(output/"cargo"),CARGO_TARGET_DIR=str(output/"target"),
        RUSTC=str(toolchain/"rustc"),RUSTDOC=str(toolchain/"rustdoc"),
        PATH=str(toolchain)+os.pathsep+environment.get("PATH",""),CARGO_BUILD_JOBS="2")
    logs=output/"processes";logs.mkdir()
    process(logs,"rustc",[toolchain/"rustc","--version","--verbose"],environment,30)
    require((logs/"rustc.stdout").read_text().startswith("rustc 1.95.0 "),"exact Rust 1.95.0 required")
    # Cargo derives a minimal lock from the complete original lock. It is retained
    # as a new lock, then every registry identity must match the original.
    process(logs,"fetch",[toolchain/"cargo","fetch","--manifest-path",crate/"Cargo.toml"],environment)
    derived=tomllib.loads((crate/"Cargo.lock").read_text())
    registered={(p["name"],p["version"],p.get("source"),p.get("checksum")) for p in all_packages if p.get("source")}
    resolved=[]
    for package in derived["package"]:
        if package.get("source"):
            key=(package["name"],package["version"],package["source"],package.get("checksum"))
            require(key in registered,"derived lock left exact target registry: "+repr(key))
            resolved.append(dict(name=key[0],version=key[1],source=key[2],checksum=key[3]))
        else:require(package["name"]=="hepta-ssh-direct-original-reference","unexpected local package")
    process(logs,"build",[toolchain/"cargo","test","--offline","--locked","--manifest-path",crate/"Cargo.toml",
        "--no-run","--message-format=json"],environment)
    executables=[]
    for line in (logs/"build.stdout").read_text().splitlines():
        value=json.loads(line)
        if value.get("reason")=="compiler-artifact" and value.get("profile",{}).get("test") and value.get("executable"):
            executables.append(Path(value["executable"]))
    require(len(executables)==1,"exact original test executable")
    executable=executables[0];require(executable.is_file(),"test executable missing")
    process(logs,"list",[executable,"--list"],environment,30)
    listed=[line[:-6] for line in (logs/"list.stdout").read_text().splitlines() if line.endswith(": test")]
    expected=[]
    for name,prefix in (("ssh_direct_tests.rs","mcp::runtime::ssh::direct::tests::"),
        ("ssh_direct_entry_tests.rs","mcp::runtime::ssh::direct::tests::entry_tests::")):
        for test in re.findall(r"#\[(?:tokio::)?test\]\s*(?:async\s+)?fn\s+(\w+)\(",(source/"reference"/name).read_text()):
            expected.append(prefix+test)
    require(sorted(listed)==sorted(expected) and len(set(listed))==len(listed),"complete unchanged test set")
    (output/"REFERENCE.json").write_bytes(canonical(dict(target=target_head,original_files=originals,
        unchanged_direct_owner=True,unchanged_original_tests=True,exact_bounded_reader=pin(module/"mod.rs"),
        bounded_original_bytes=len(bounded.encode()),bounded_original_sha256=hashlib.sha256(bounded.encode()).hexdigest(),
        wrappers={path:pin(crate/path) for path in wrappers},direct_dependencies=dependencies,
        derived_lock=pin(crate/"Cargo.lock"),registry=resolved,tests=sorted(listed),executable=pin(executable),
        test_executable_path=executable.relative_to(output).as_posix())))
    process(logs,"original-tests",[executable,"--test-threads=1","--nocapture"],environment)
    raw=(logs/"original-tests.stdout").read_text()
    require(("test result: ok. "+str(len(expected))+" passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;") in raw,
        "complete original suite summary")
    require(source_evidence(source)==binding,"source changed")
    result=dict(status="COMPLETE_UNCHANGED_DIRECT_SSH_TESTS_PASS",source=binding,original_tests=len(expected),
        process_receipts={p.name:pin(p) for p in sorted(logs.glob("*.json"))},
        reference=pin(output/"REFERENCE.json"),hia_executed=False,native_actor_qualified=False,
        public_ssh_qualified=False,old_stack_removed=False)
    (output/"RESULT.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
