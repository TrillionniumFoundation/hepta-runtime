#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh CI-only current typed owner build, original comparison and byte custody."""
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

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import B3, HEPTA, SCOPE, canonical, decode, owned, pin, require, source_evidence


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


def build(source, hepta, output):
    from hia_native_build import NativeBuild
    source_evidence(source)
    builder = NativeBuild(hepta, output / "build")
    members = {}
    from params_cases import schemas
    for name in ["serde_json_span"] + [row["name"] + "_params" for row in schemas()] + ["binary_call_plan"]:
        manifest = builder.compile(name.replace("_", "-"), source / "native" / (name + ".hepta"), standalone=None, buffer_profile="history.v1")
        meta = decode(manifest.read_bytes())
        members[name] = dict(manifest=manifest.relative_to(output).as_posix(), manifest_sha256=pin(manifest)["sha256"],
            source_sha256=meta["source_sha256"], image_sha256=meta["image_sha256"])
    dep = output / "compiler-source"; dep.mkdir()
    for name in builder.identity["files"]:
        target = dep / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(hepta / name, target)
    receipt = dict(schema="hepta.runtime.binary-call-plan.build.v1", members=members,
        compiler_commit=HEPTA, compiler_sha256=B3, compiler_cold_qualified=False)
    (output / "build/call-plan.json").write_bytes(canonical(receipt))
    return receipt



def command_specs(origin):
    at=Path(origin["output"]);source=at/"source";rust=Path(origin["rust_bin"])
    py=[origin["python"],"-I","-S","-B"]
    exe=at/"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-call-plan-original-oracle"
    rows={
        "root-fetch":(py+[str(source/"scripts/root_archive.py"),"fetch","--work",str(at/"root-reuse")],60),
        "root-unpack":(py+[str(source/"scripts/root_archive.py"),"unpack","--work",str(at/"root-reuse")],180),
        "root-build-read":(py+[str(source/"scripts/root_archive.py"),"verify","--work",str(at/"root-reuse")],180),
        "author":(py+[str(source/"authoring/author_binary_call_plan.py"),"--source",str(source),
            "--hepta",origin["hepta"],"--output",str(at/"authored")],60),
        "native-build":(py+[str(source/"scripts/run_ci.py"),"build","--source",str(source),
            "--hepta",origin["hepta"],"--output",str(at)],900),
        "rust-version":([str(rust/"rustc"),"--version","--verbose"],60),
        "cargo-fetch":([str(rust/"cargo"),"fetch","--locked","--manifest-path",str(at/"reference/Cargo.toml")],900),
        "cargo-metadata":([str(rust/"cargo"),"metadata","--locked","--offline","--format-version","1",
            "--manifest-path",str(at/"reference/Cargo.toml")],60),
        "cargo-build":([str(rust/"cargo"),"build","--locked","--offline","--manifest-path",str(at/"reference/Cargo.toml")],900),
        "original-tests":([str(rust/"cargo"),"test","--locked","--offline","--manifest-path",
            str(at/"reference/Cargo.toml"),"--","--nocapture"],60)}
    import plan_cases
    for group in plan_cases.groups(at/"native"):
        name=group["name"]
        rows["original-"+name]=([str(exe)],60)
        rows["native-"+name]=(py+[str(source/"scripts/native_capture.py"),"--qualification",str(at),"--group",name],60)
    return rows

def check_processes(output):
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    expected=command_specs(origin);result={}
    actual={p.stem for p in(output/"processes").glob("*.json")}
    require(actual==set(expected),"actual producer process set changed")
    for name,(argv,limit)in expected.items():
        receipt=decode(owned(output,"processes/"+name+".json").read_bytes())
        require(receipt["argv"]==argv and receipt["cwd"]==origin["output"]
            and receipt["returncode"]==0 and receipt["timed_out"]is False and receipt["limit_seconds"]==limit
            and 0<=receipt["elapsed_ns"]<(limit+1)*1_000_000_000
            and type(receipt["pid"])is int and receipt["pid"]>0,"actual process command/status/budget differs: "+name)
        require(set(receipt["streams"])=={"stdin","stdout","stderr"},"actual process omitted streams")
        for suffix in("stdin","stdout","stderr"):
            require(receipt["streams"][suffix]==pin(owned(output,"processes/"+name+"."+suffix)),
                "complete process stream changed: "+name)
        if name.startswith(("original-","native-"))and name!="original-tests":
            require(owned(output,"processes/"+name+".stderr").read_bytes()==b"","semantic process stderr")
        result[name]=receipt
    require(owned(output,"processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "),
        "wrong actual original compiler")
    require("test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"in
        owned(output,"processes/original-tests.stdout").read_text(),"unchanged original four tests failed")
    return result

def read_all(source,output):
    import plan_cases
    from read_plan import build_evidence,read_native_group
    from registry_evidence import inventory
    import root_archive
    source,output=Path(source),Path(output)
    src=source_evidence(source)
    require(source_evidence(output/"source")==src,"retained whole source differs")
    processes=check_processes(output)
    for name in("binary_call_plan.hepta","binary_call_plan_composition.json"):
        require(owned(output,"authored/"+name).read_bytes()==owned(source,"native/"+name).read_bytes(),
            "pure author did not reproduce exact frozen HIA")
    require(owned(output,"authored/binary_call_plan.pseudo").read_bytes()==
        owned(source,"authoring/binary_call_plan.expanded.pseudo").read_bytes(),"expanded author source differs")
    for path in(source/"reference").rglob("*"):
        if path.is_file():
            require(path.read_bytes()==owned(output,"reference/"+path.relative_to(source/"reference").as_posix()).read_bytes(),
                "original compiled fixture source differs")
    registry=inventory(source,output)
    require(registry==decode(owned(output,"registry-evidence.json").read_bytes()),"complete original crate closure differs")
    binary=owned(output,"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-call-plan-original-oracle")
    require(pin(binary)==decode(owned(output,"original-binary.json").read_bytes()),"actual original binary changed")
    binding=decode(owned(source,"ROOT_BINDING.json").read_bytes())
    reused=root_archive.verify(output/"root-reuse",binding)
    require(reused==decode(owned(output,"processes/root-build-read.stdout").read_bytes()),
        "actual reused config source/build evidence differs")
    artifacts=build_evidence(source,output)
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    groups=plan_cases.groups(Path(origin["output"])/"native")
    domain=decode(owned(source,"DOMAIN.json").read_bytes())
    require(domain["cases"]==433 and domain["group_count"]==24 and len(groups)==24
        and sum(len(g["cases"])for g in groups)==433,"frozen pipeline domain changed")
    reports=[]
    for group in groups:
        name=group["name"]
        require(owned(output,"processes/original-"+name+".stdin").read_bytes()==plan_cases.encoded(group),
            "actual original input domain differs")
        report=read_native_group(source,output,group,artifacts);reports.append(dict(name=name,**report))
        captured=decode(owned(output,"processes/native-"+name+".stdout").read_bytes())
        require(captured==dict(status="PASS",group=name,cases=report["cases"],native_calls=report["calls"],
            controls=report["controls"]),"actual native stdout differs from complete capture")
    native=dict(cases=sum(r["cases"]for r in reports),calls=sum(r["calls"]for r in reports),
        controls=sum(r["controls"]for r in reports),full_record_bytes=sum(r["full_record_bytes"]for r in reports),
        config_calls=sum(r["root"]["native_calls"]for r in reports),
        config_record_bytes=sum(r["root"]["full_record_bytes"]for r in reports),
        ready_plans=sum(r["original"]["ready_plans"]for r in reports),
        typed_errors=sum(r["original"]["typed_errors"]for r in reports),
        body_errors=sum(r["original"]["body_errors"]for r in reports))
    require(native["cases"]==433 and native["controls"]==28 and
        native["ready_plans"]+native["typed_errors"]+native["body_errors"]==433,"actual caller partition incomplete")
    return dict(status="COMPLETE_CALL_PLAN_COMPARISON_PASS",source=src,native=native,groups=reports,
        reused_config=reused,registry_packages=registry["used_registry_packages"],scope=SCOPE)

def execute(source,hepta,rust_bin,output):
    require(not output.exists(),"qualification output must be fresh")
    output.mkdir(parents=True)
    origin=dict(source=str(source),hepta=str(hepta),rust_bin=str(rust_bin),output=str(output),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin));source_evidence(source)
    shutil.copytree(source,output/"source")
    for path in(output/"source").rglob("*"):
        if path.is_file():path.chmod(0o644)
    source=output/"source";specs=command_specs(origin)
    for name in("root-fetch","root-unpack","root-build-read","author","native-build"):
        argv,limit=specs[name];run_process(output,name,argv,limit=limit)
    for name in("binary_call_plan.hepta","binary_call_plan_composition.json"):
        require((output/"authored"/name).read_bytes()==(source/"native"/name).read_bytes(),"authored source changed")
    shutil.copytree(source/"reference",output/"reference")
    env=dict(os.environ)
    env.update(CARGO_HOME=str(output/"cargo-home"),CARGO_TARGET_DIR=str(output/"rust-target"),
        RUSTC=str(rust_bin/"rustc"),RUSTUP_TOOLCHAIN="1.95.0",PATH=str(rust_bin)+os.pathsep+env.get("PATH",""))
    for name in("rust-version","cargo-fetch","cargo-metadata","cargo-build","original-tests"):
        argv,limit=specs[name];run_process(output,name,argv,env=env,limit=limit)
    from registry_evidence import inventory
    (output/"registry-evidence.json").write_bytes(canonical(inventory(source,output,capture=True)))
    binary=output/"rust-target/x86_64-unknown-linux-gnu/debug/hepta-binary-call-plan-original-oracle"
    (output/"original-binary.json").write_bytes(canonical(pin(binary)))
    import plan_cases
    groups=plan_cases.groups(output/"native");(output/"native").mkdir()
    for group in groups:
        name=group["name"];folder=output/"native"/name;folder.mkdir()
        (folder/"INPUT.json").write_bytes(plan_cases.encoded(group))
        argv,limit=specs["original-"+name]
        run_process(output,"original-"+name,argv,data=plan_cases.encoded(group),env=env,limit=limit)
        argv,limit=specs["native-"+name]
        run_process(output,"native-"+name,argv,limit=limit)
    print(json.dumps(dict(status="ACTUAL_CALL_PLAN_PRODUCERS_COMPLETE",cases=433,groups=24,original_tests=4),sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("check","build","run","verify","controls","verify-controls"))
    p.add_argument("--source",required=True,type=Path);p.add_argument("--hepta",type=Path)
    p.add_argument("--rust-bin",type=Path);p.add_argument("--output",type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":
        evidence=source_evidence(source)
        for path in source.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
        import plan_cases
        domain=decode(owned(source,"DOMAIN.json").read_bytes());groups=plan_cases.groups(Path("/frozen")/"native")
        cases=[c for g in groups for c in g["cases"]]
        require(len(cases)==domain["cases"]==433 and len(groups)==domain["group_count"]==24
            and {str(k):sum(c["kind"]==k for c in cases)for k in range(1,6)}==domain["by_kind"],"input-only source domain changed")
        require([c["case_id"]for c in cases]==list(range(1,434)),"frozen case identities/order changed")
        print(json.dumps(dict(status="SOURCE_ONLY_PASS",files=len(evidence["files"]),cases=433,groups=24),sort_keys=True))
    elif a.mode=="build":
        print(json.dumps(build(source,a.hepta.resolve(strict=True),a.output.resolve(strict=True)),sort_keys=True))
    elif a.mode=="run":
        execute(source,a.hepta.resolve(strict=True),a.rust_bin.resolve(strict=True),a.output.absolute())
    else:
        import read_plan,root_archive,root_state,registry_evidence,plan_cases
        from readonly import guarded
        from reader_controls import create,verify
        output=a.output.resolve(strict=True);controls=output.parent/(output.name+"-reader-controls")
        if a.mode=="controls":
            print(json.dumps(create(source,output,controls),sort_keys=True))
        elif a.mode=="verify":
            print(json.dumps(guarded(lambda:read_all(source,output),roots=[source,output]),sort_keys=True))
        else:
            def full():
                result=read_all(source,output);result["physical_controls"]=verify(source,output,controls);return result
            print(json.dumps(guarded(full,roots=[source,output,controls]),sort_keys=True))
if __name__=="__main__":main()
