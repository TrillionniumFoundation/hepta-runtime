#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Two original-limit native lanes against complete immutable completed SDK captures."""
from pathlib import Path
import argparse,json,os,shutil,signal,subprocess,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,pin,require
import check_current,current_dependencies,recover_public
def process(command,stem,*,pure):
    start=time.monotonic();timed=False
    with Path(str(stem)+".stdout").open("xb") as so,Path(str(stem)+".stderr").open("xb") as se:
        proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=pure)
        if pure:
            try:proc.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        else:
            # The unchanged native capture owns its child, process-group cleanup,
            # 60-second exchange and 180-second process limit. No false outer
            # timeout attempts to kill a separately session-owned application.
            proc.wait()
    row=dict(command=command,exit_code=proc.returncode,timed_out=timed,elapsed_seconds=time.monotonic()-start,
        stdout=pin(Path(str(stem)+".stdout")),stderr=pin(Path(str(stem)+".stderr")),
        outer_timeout_seconds=180 if pure else None,application_process_limit_seconds=None if pure else 180,
        application_exchange_limit_seconds=None if pure else 60,original_executed=False,
        application_kind=None if pure else "new-current124-native-only")
    Path(str(stem)+".json").write_bytes(canonical(row))
    sys.stdout.buffer.write(Path(str(stem)+".stdout").read_bytes());sys.stdout.flush()
    if proc.returncode or timed:sys.stderr.buffer.write(Path(str(stem)+".stderr").read_bytes());sys.stderr.flush()
    return row
def main():
    p=argparse.ArgumentParser()
    for name in ("output","stage","build-recipe","public-reader"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    require(os.environ.get("GITHUB_ACTIONS")=="true","application capture is CI only")
    require(not a.output.exists() and not a.stage.exists(),"fresh complete qualification roots")
    a.output.mkdir(parents=True);a.stage.mkdir(parents=True)
    check=check_current.check();(a.output/"SOURCE_CHECK.json").write_bytes(canonical(check))
    inputs=decode((ROOT/"CURRENT_INPUTS.json").read_bytes())
    rows=[r for r in decode((ROOT/"RECOVERY_INPUTS.json").read_bytes())
        if r.get("mode","")+"_"+r.get("profile","")==a.group]
    require(len(rows)==2 and {r["era"] for r in rows}=={"legacy","modern"},"complete declared two-era group")
    rows=sorted(rows,key=lambda r:r["era"])
    wrapper=a.public_reader/"timed_build_read.py"
    require(pin(wrapper)==inputs["build_wrapper"],"exact retained complete graph restoration observer")
    buildroot=a.stage/"graph"
    g=inputs["graph"]
    command=[sys.executable,"-I","-S","-B",str(wrapper),"--build-recipe",str(a.build_recipe),
        "--output",str(buildroot),"--artifact",str(g["artifact"]),"--bytes",str(g["zip"]["bytes"]),
        "--sha256",g["zip"]["sha256"]]
    record=process(command,a.output/"graph-process",pure=True)
    require(record["exit_code"]==0 and not record["timed_out"],"complete actual124 graph source/compiler/pack read")
    proof=decode((buildroot/"READ_ONLY.json").read_bytes());current_dependencies.verify_guard(proof)
    graph=proof["evidence"]["current"]
    depdir=a.output/"dependencies";depdir.mkdir()
    shutil.copy2(buildroot/"READ_ONLY.json",depdir/"GRAPH_READ.json")
    for name in ("READ.json","FILES.json","ARCHIVE.json","SUMMARY.json"):
        shutil.copy2(buildroot/name,depdir/name)
    require(decode((depdir/"READ.json").read_bytes())["archive"]==g["archive"],"fixed full original graph TAR")
    for entry,name in (("production","runtime-mcp.elf"),("instances","filesystem.elf")):
        binary=Path(graph["entries"][entry]["elf"]["path"])
        require(binary.resolve().is_relative_to((buildroot/"extracted").resolve())
            and pin(binary)==inputs["binaries"][entry],"actual full graph executable source")
        shutil.copy2(binary,depdir/name)
        require(pin(depdir/name)==inputs["binaries"][entry] and (depdir/name).stat().st_mode&0o111,
            "whole independent actual executable copy")
    (a.output/"processes").mkdir();(a.output/"lanes").mkdir()
    results=[]
    for item in rows:
        key=item["key"];retained,archive=recover_public.restore(item,a.output/"retained"/key)
        old=retained/"capture";olddeps=decode((old/"DEPENDENCIES.json").read_bytes())
        before=recover_public.inventory(retained)
        actual_root=Path(decode((old/"RETIRED_FIXTURE.json").read_bytes())["root"])
        actual=actual_root.parent
        temp=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        require(actual_root.name=="fixtures-root" and actual.is_absolute()
            and actual.is_relative_to(temp) and actual!=temp and not actual.exists()
            and not a.output.is_relative_to(actual) and not a.stage.is_relative_to(actual)
            and not actual.is_relative_to(a.output) and not actual.is_relative_to(a.stage),
            "fresh exact previously declared owned fixture path, disjoint from retained evidence")
        deps=dict(schema="hepta.runtime.publication124.retained-original.dependencies.v1",
            graph_identity=g,production=inputs["production"],graph_review=graph,
            complete_graph_proof=pin(depdir/"GRAPH_READ.json"),
            filesystem_binary=str((depdir/"filesystem.elf").resolve()),
            public_binary=str((depdir/"runtime-mcp.elf").resolve()),
            carrier_binary_pin=inputs["binaries"]["instances"],stdio_binary_pin=inputs["binaries"]["production"],
            original_binary=olddeps["original_binary"],original_binary_pin=olddeps["original_binary_pin"],
            retained_original_dependencies=olddeps,original_replayed=False,graph_rebuilt=False)
        current_dependencies.verify_receipt(deps)
        declared=a.output/"processes"/(key+".dependencies.json");declared.write_bytes(canonical(deps))
        lane=a.output/"lanes"/key;lane.mkdir()
        command=[sys.executable,"-I","-S","-B",str(ROOT/"recipe/capture_native.py"),
            "--dependencies",str(declared),"--output",str(actual),"--profile",item["profile"],
            "--era",item["era"],"--mode",item["mode"]]
        try:record=process(command,a.output/"processes"/key,pure=False)
        finally:
            if actual.exists():
                require(actual.is_dir() and not actual.is_symlink() and not (lane/"capture").exists(),
                    "only this owned actual application directory is sealed")
                actual.rename(lane/"capture")
        require(record["exit_code"]==0 and not record["timed_out"],"new current native complete actual process")
        capture=lane/"capture"
        native=decode((capture/"native/CAPTURE.json").read_bytes())
        require(native["capture_completed"] is True and native["completed"]==native["total"]
            and native["source_dependencies"]==deps,"complete native role and dependency identity")
        shutil.copytree(old/"original",capture/"original",copy_function=shutil.copy2)
        original_files=recover_public.inventory(old/"original")
        require(recover_public.inventory(capture/"original")==original_files,"every original role byte and mode unchanged")
        custody=dict(key=key,artifact=item,archive=archive,original_files=original_files,
            native_executions=1,original_executions=0,original_role_retained=True)
        (capture/"ORIGINAL_CUSTODY.json").write_bytes(canonical(custody))
        meta=decode((capture/"CAPTURE.json").read_bytes())
        require(meta["roles"]==[native],"one actually executed native role")
        meta["roles"].append(decode((old/"original/CAPTURE.json").read_bytes()))
        meta.update(original_replayed=False,retained_original_artifact=item["artifact"],native_executions=1)
        (capture/"CAPTURE.json").write_bytes(canonical(meta))
        command=[sys.executable,"-I","-S","-B",str(ROOT/"recipe/qualify_current.py"),
            "--capture",str(capture),"--retained",str(old),"--graph-proof",str(depdir/"GRAPH_READ.json"),
            "--output",str(lane/"READONLY.json")]
        checked=process(command,a.output/"processes"/(key+"-read"),pure=True)
        require(checked["exit_code"]==0 and not checked["timed_out"],"whole actual current/original reader")
        require(recover_public.inventory(retained)==before,"immutable original full capture remained byte and mode equal")
        result=decode((lane/"READONLY.json").read_bytes());e=result["proof"]["evidence"]
        results.append(dict(key=key,cases=e["current"]["cases"],mode=item["mode"],profile=item["profile"],era=item["era"],
            result=e,proof=pin(lane/"READONLY.json"),guards=len(result["proof"]["probes"]),
            application=record,reader=checked,native_executions=1,original_executions=0))
        (a.output/"RESULTS.json").write_bytes(canonical(results))
        print("CURRENT124_ORDINARY "+json.dumps(dict(key=key,cases=e["current"]["cases"],
            guards=len(result["proof"]["probes"]),status=e["status"]),sort_keys=True),flush=True)
    require(len(results)==2,"complete original-limit two-era domain")
    summary=dict(status="COMPLETE_CURRENT124_TWO_ERA_ORDINARY_PASS",group=a.group,roles=results,
        cases=sum(r["cases"] for r in results),native_processes=2,original_processes=0,
        source=check["source"],production=inputs["production"],runtime_hia_images=124,physical_images=117,
        dependency_applications=0,all_136_handlers=False,production_installed=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
