#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""CI-only actual installed binary root qualification."""
from __future__ import annotations
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import B3,HEPTA,SCOPE,canonical,decode,owned,pin,require,source_evidence
import root_cases
def run_process(output, name, argv, *, data=b"", env=None, cwd=None, limit=60):
    folder = output / "processes"; folder.mkdir(exist_ok=True)
    require(not (folder / (name + ".json")).exists(), "process label reused")
    stdin = folder / (name + ".stdin"); stdin.write_bytes(data)
    receipt = dict(argv=[str(x) for x in argv], cwd=str(cwd or output), limit_seconds=limit,
                   started_ns=time.monotonic_ns(), timed_out=False,
                   selected_env={key: env[key] for key in ("CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC", "RUSTUP_TOOLCHAIN") if env and key in env})
    with stdin.open("rb") as inp, (folder / (name + ".stdout")).open("xb") as out, (folder / (name + ".stderr")).open("xb") as err:
        child = subprocess.Popen(receipt["argv"], cwd=receipt["cwd"], env=env, stdin=inp, stdout=out, stderr=err, start_new_session=True)
        receipt["pid"] = child.pid
        try:
            receipt["returncode"] = child.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            receipt["timed_out"] = True
            os.killpg(child.pid, signal.SIGKILL)
            receipt["returncode"] = child.wait()
    receipt["elapsed_ns"] = time.monotonic_ns() - receipt["started_ns"]
    receipt["streams"] = {suffix: pin(folder / (name + "." + suffix)) for suffix in ("stdin", "stdout", "stderr")}
    (folder / (name + ".json")).write_bytes(canonical(receipt))
    require(receipt["returncode"] == 0 and not receipt["timed_out"], "process failed: " + name)
    return receipt


def build(source,hepta,output):
    from hia_native_config_span_build import build_config_span
    source_evidence(source)
    result=build_config_span(hepta,output/"build",source_root=source)
    bootstrap=decode((output/"build/build/bootstrap/bootstrap.json").read_bytes())
    dep=output/"compiler-source";dep.mkdir()
    for name in bootstrap["dependency"]["files"]:
        path=dep/name;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(hepta/name,path)
    require(bootstrap["generation_sha256"]==B3,"native compiler changed")
    return dict(status="NATIVE_INSTALLED_BUILD_PASS",result=pin(result))
def check_processes(output):
    origin=decode(owned(output,"ORIGIN.json").read_bytes());at=Path(origin["output"]);source=at/"source";rust=Path(origin["rust_bin"])
    py=[origin["python"],"-I","-S","-B"]
    expected={
        "author":py+[str(source/"authoring/author_binary_root.py"),"--source",str(source),"--hepta",origin["hepta"],"--output",str(at/"authored")],
        "native-build":py+[str(source/"scripts/run_ci.py"),"build","--source",str(source),"--hepta",origin["hepta"],"--output",str(at)],
        "rust-version":[str(rust/"rustc"),"--version","--verbose"],
        "cargo-fetch":[str(rust/"cargo"),"fetch","--locked","--manifest-path",str(at/"reference/Cargo.toml")],
        "cargo-metadata":[str(rust/"cargo"),"metadata","--locked","--offline","--format-version","1","--manifest-path",str(at/"reference/Cargo.toml")],
        "cargo-build":[str(rust/"cargo"),"build","--locked","--offline","--manifest-path",str(at/"reference/Cargo.toml")],
    }
    for group in root_cases.groups():
        name=group["name"]
        expected["original-"+name]=[str(at/"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-root-original-oracle")]
        expected["native-"+name]=py+[str(source/"scripts/native_capture.py"),"--qualification",str(at),"--group",name]
    expected["native-controls"]=py+[str(source/"scripts/native_capture.py"),"--qualification",str(at),"--controls"]
    found={p.stem for p in(output/"processes").glob("*.json")}
    require(found==set(expected),"actual process set changed")
    rows={}
    for name,argv in expected.items():
        row=decode(owned(output,"processes/"+name+".json").read_bytes())
        budget=900 if name in("native-build","cargo-fetch","cargo-build")else 60
        require(row["argv"]==argv and row["cwd"]==str(at)and row["returncode"]==0 and row["timed_out"]is False
            and row["limit_seconds"]==budget and 0<=row["elapsed_ns"]<(budget+1)*1000000000
            and type(row["pid"])is int and row["pid"]>0,"actual process command/result/budget changed: "+name)
        for suffix,want in row["streams"].items():require(pin(owned(output,"processes/"+name+"."+suffix))==want,"complete actual process stream changed")
        require(set(row["streams"])=={"stdin","stdout","stderr"},"process stream omitted")
        if name.startswith(("original-","native-")):
            require(owned(output,"processes/"+name+".stderr").read_bytes()==b"","semantic producer stderr differs")
        rows[name]=row
    require(owned(output,"processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "),"actual Rust compiler differs")
    return rows
def read_all(source,output):
    from read_root import build_evidence,read_group,read_controls
    from registry_evidence import inventory
    source,output=Path(source),Path(output)
    src=source_evidence(source)
    require(source_evidence(output/"source")==src,"retained source differs")
    processes=check_processes(output)
    for name in("config_binary_root_span.hepta","config_binary_root_span_composition.json"):
        destination="native/config_directory_owner_span.hepta"if name.endswith(".hepta")else"native/"+name
        require(owned(output,"authored/"+name).read_bytes()==owned(source,destination).read_bytes(),"author did not reproduce frozen native source")
    for path in(source/"reference").rglob("*"):
        if path.is_file():require(path.read_bytes()==owned(output,"reference/"+path.relative_to(source/"reference").as_posix()).read_bytes(),"original oracle source changed")
    registry=inventory(source,output)
    require(registry==decode(owned(output,"registry-evidence.json").read_bytes()),"used original registry closure changed")
    binary=owned(output,"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-root-original-oracle")
    require(pin(binary)==decode(owned(output,"original-binary.json").read_bytes()),"actual original binary changed")
    built=build_evidence(source,output)
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    groups=root_cases.materialized(Path(origin["output"])/"native")
    require(len(groups)==10 and sum(len(g["queries"])for g in groups)==135,"frozen complete input domain changed")
    native={}
    for group in groups:
        name=group["name"]
        summary=decode(owned(output,"native/"+name+"/PROCESS.json").read_bytes())
        result=read_group(source,output,group,summary)
        expected=decode(owned(output,"processes/native-"+name+".stdout").read_bytes())
        require(expected==dict(status="PASS",group=name,semantic_queries=result["cases"],
            private_wire_controls=result["wire_controls"],full_native_buffer_record_bytes=result["full_record_bytes"]),"native producer stdout changed")
        native[name]=result
    operator=next(g for g in groups if g["name"]=="operator")
    candidates=[i for i,q in enumerate(operator["queries"])if q["host"]=="h"and q["path"]=="/data"and q["mode"]=="rpc"and not q["write"]]
    require(len(candidates)==1,"physical reference query ambiguous")
    reference=decode(owned(output,"processes/original-operator.stdout").read_bytes())[candidates[0]]
    controls=read_controls(source,output,reference)
    actual=decode(owned(output,"processes/native-controls.stdout").read_bytes())
    require(actual==decode(owned(output,"controls/RESULT.json").read_bytes()),"physical control stdout differs")
    native_summary=dict(original_cases=135,wire_controls=12,capacity_controls=14,
        native_calls=sum(v["native_calls"]for v in native.values())+controls["native_calls"],
        complete_buffer_bytes=sum(v["full_record_bytes"]for v in native.values())+controls["full_record_bytes"],
        output_growths=sum(v["output_growths"]for v in native.values()),actual_configured_processes=9,actual_absent_processes=1)
    return dict(status="COMPLETE_BINARY_ROOT_COMPARISON_PASS",source=src,build=built,native=native_summary,
        groups=native,controls=controls,registry_packages=registry["used_registry_packages"],scope=SCOPE)
def execute(source,hepta,rust_bin,output):
    require(not output.exists(),"actual qualification output must be fresh")
    output.mkdir(parents=True)
    origin=dict(source=str(source),hepta=str(hepta),rust_bin=str(rust_bin),output=str(output),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin))
    source_evidence(source);shutil.copytree(source,output/"source")
    for path in(output/"source").rglob("*"):
        if path.is_file():path.chmod(0o644)
    source=output/"source";py=[sys.executable,"-I","-S","-B"]
    run_process(output,"author",py+[source/"authoring/author_binary_root.py","--source",source,"--hepta",hepta,"--output",output/"authored"])
    for name in("config_binary_root_span.hepta","config_binary_root_span_composition.json"):
        destination="native/config_directory_owner_span.hepta"if name.endswith(".hepta")else"native/"+name
        require((output/"authored"/name).read_bytes()==(source/destination).read_bytes(),"fresh author source differs")
    run_process(output,"native-build",py+[source/"scripts/run_ci.py","build","--source",source,"--hepta",hepta,"--output",output],limit=900)
    shutil.copytree(source/"reference",output/"reference")
    from process import environment
    env,binding=environment(os.environ,rust_bin=rust_bin,target=output/"rust-target")
    env["CARGO_HOME"]=str(output/"cargo-home")
    (output/"ENVIRONMENT.json").write_bytes(canonical(binding))
    run_process(output,"rust-version",[rust_bin/"rustc","--version","--verbose"],env=env)
    manifest=output/"reference/Cargo.toml"
    for name,args,budget in(
        ("cargo-fetch",["fetch","--locked","--manifest-path",manifest],900),
        ("cargo-metadata",["metadata","--locked","--offline","--format-version","1","--manifest-path",manifest],60),
        ("cargo-build",["build","--locked","--offline","--manifest-path",manifest],900)):
        run_process(output,name,[rust_bin/"cargo",*args],env=env,limit=budget)
    from registry_evidence import inventory
    (output/"registry-evidence.json").write_bytes(canonical(inventory(source,output)))
    binary=output/"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-root-original-oracle"
    (output/"original-binary.json").write_bytes(canonical(pin(binary)))
    (output/"native").mkdir(mode=0o700)
    groups=root_cases.materialized(output/"native")
    require(len(groups)==10 and sum(len(g["queries"])for g in groups)==135,"frozen input cases changed")
    for group in groups:
        folder=output/"native"/group["name"];folder.mkdir(mode=0o700)
        (folder/"INPUT.json").write_bytes(canonical(group))
        run_process(output,"original-"+group["name"],[binary],data=root_cases.encoded(group),env=env)
        run_process(output,"native-"+group["name"],py+[source/"scripts/native_capture.py","--qualification",output,"--group",group["name"]],env=env)
    run_process(output,"native-controls",py+[source/"scripts/native_capture.py","--qualification",output,"--controls"],env=env)
    return dict(status="ACTUAL_BINARY_ROOT_PRODUCERS_COMPLETE",original_cases=135,
        private_wire_controls=12,physical_capacity_controls=14,source=source_evidence(source),scope=SCOPE)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","build","run","verify","controls","verify-controls"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--hepta",type=Path);p.add_argument("--rust-bin",type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);output=a.output.absolute()if a.output else None
    if a.stage=="check":
        value=source_evidence(source)
        for path in source.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
        require(len(root_cases.groups())==10 and sum(len(g["queries"])for g in root_cases.groups())==135
            and len(root_cases.controls())==12,"frozen domain declarations changed")
        result=dict(status="SOURCE_ONLY_PASS",source=value,native_or_rust_executions=0)
    elif a.stage=="build":result=build(source,a.hepta.resolve(strict=True),output)
    elif a.stage=="run":result=execute(source,a.hepta.resolve(strict=True),a.rust_bin.resolve(strict=True),output)
    elif a.stage=="verify":
        import read_root,registry_evidence
        from readonly import guarded
        result=guarded(lambda:read_all(source,output),roots=[source,output])
    elif a.stage=="controls":
        import reader_controls
        result=reader_controls.produce(source,output)
    else:
        import reader_controls
        from readonly import guarded
        result=guarded(lambda:reader_controls.verify(source,output),roots=[source,output,output.parent/"physical-controls"])
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
