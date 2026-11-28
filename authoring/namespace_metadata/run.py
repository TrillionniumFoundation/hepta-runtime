#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build and independently qualify the native HIA metadata component."""
from __future__ import annotations
import argparse,hashlib,json,platform,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def pin(path):
    raw=Path(path).read_bytes();return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def require(value,message):
    if not value:raise ValueError(message)
def process(folder,name,argv,timeout=180):
    before=time.monotonic()
    with (folder/(name+".stdout")).open("xb") as stdout,(folder/(name+".stderr")).open("xb") as stderr:
        result=subprocess.run([str(x) for x in argv],stdout=stdout,stderr=stderr,timeout=timeout)
    row={"argv":[str(x) for x in argv],"returncode":result.returncode,"seconds":time.monotonic()-before,
        "stdout":pin(folder/(name+".stdout")),"stderr":pin(folder/(name+".stderr"))}
    (folder/(name+".json")).write_bytes(encoded(row));print(json.dumps(row),flush=True)
    require(result.returncode==0,name+" failed; retain complete stdout/stderr")
    return row
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","hepta","rustc","output"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--bootstrap",type=Path)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),"fresh qualification output required");out.mkdir(parents=True)
    source_paths=("authoring/namespace_metadata/run.py","authoring/namespace_metadata/qualify.py",
        "authoring/namespace_metadata/reference/actual.rs","authoring/namespace_metadata/ABI.md")
    sources={name:pin(root/name) for name in source_paths}
    version=subprocess.run([str(a.rustc),"--version","--verbose"],capture_output=True,check=True,timeout=10).stdout.decode()
    require("rustc 1.95.0 (59807616e " in version and "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860" in version,
        "original Rust 1.95 compiler differs")
    sysroot=Path(subprocess.run([str(a.rustc),"--print","sysroot"],capture_output=True,check=True,timeout=10).stdout.decode().strip()).resolve(strict=True)
    libraries=sorted((sysroot/"lib/rustlib/x86_64-unknown-linux-gnu/lib").glob("*.rlib"))
    require(libraries,"complete standard library rlibs missing")
    toolchain={"version":version,"rustc":pin(a.rustc.resolve(strict=True)),"sysroot":str(sysroot),
        "standard_libraries":{str(p.relative_to(sysroot)):pin(p) for p in libraries}}
    libc_paths=sorted({Path(line.split()[-1]).resolve(strict=True) for line in Path("/proc/self/maps").read_text().splitlines()
        if line.split()[-1].endswith("/libc.so.6")})
    require(len(libc_paths)==1,"actual GNU libc mapping differs")
    host={"platform":platform.platform(),"machine":platform.machine(),"libc":platform.libc_ver(),
        "actual_libc_path":str(libc_paths[0]),"actual_libc":pin(libc_paths[0])}
    (out/"TOOLCHAIN.json").write_bytes(encoded(toolchain));(out/"HOST.json").write_bytes(encoded(host))
    bootstrap=a.bootstrap;processes=[]
    if bootstrap is None:
        processes.append(process(out,"bootstrap",[sys.executable,"-I","-B",root/"scripts/hia_native_build.py",
            "--hepta",hepta,"--build-root",out/"bootstrap-build"],180))
        bootstrap=out/"bootstrap-build/bootstrap"
    processes.append(process(out,"build",[sys.executable,"-I","-B",root/"scripts/hia_native_namespace_metadata.py",
        "--source",root,"--hepta",hepta,"--bootstrap",bootstrap,"--output",out/"native"],180))
    reference=out/"reference";reference.mkdir()
    argv=[a.rustc,"--edition=2021","-C","opt-level=1","-o",reference/"actual",root/"authoring/namespace_metadata/reference/actual.rs"]
    compiled=process(reference,"compile",argv,60);processes.append(compiled)
    reference_report={**compiled,"source":sources["authoring/namespace_metadata/reference/actual.rs"],
        "rustc_version":version,"binary":pin(reference/"actual"),"complete_toolchain":pin(out/"TOOLCHAIN.json")}
    (reference/"COMPILE.json").write_bytes(encoded(reference_report))
    processes.append(process(out,"actual",[sys.executable,"-I","-B",root/"authoring/namespace_metadata/qualify.py",
        "--source",root,"--build",out/"native","--reference",reference,"--output",out/"actual"],180))
    result=json.loads((out/"actual/RESULT.json").read_bytes())
    require(result["status"]=="PASS" and result["paired_process_groups"]==24 and result["paired_requests"]==122 and len(result["abi_controls"])==21,
        "complete fixed metadata domain differs")
    require(sources=={name:pin(root/name) for name in source_paths},"qualification source changed")
    require(toolchain["rustc"]==pin(a.rustc.resolve(strict=True)) and
        toolchain["standard_libraries"]=={str(p.relative_to(sysroot)):pin(p) for p in libraries},"actual original compiler/library bytes changed")
    require(host["actual_libc"]==pin(libc_paths[0]),"actual GNU libc changed")
    gate={"schema":"hepta.runtime.namespace-metadata-gate.v1","status":"PASS","sources":sources,
        "build":pin(out/"native/BUILD.json"),"actual":pin(out/"actual/RESULT.json"),
        "toolchain":pin(out/"TOOLCHAIN.json"),"host":pin(out/"HOST.json"),"processes":processes,
        "paired_process_groups":24,"paired_requests":122,"abi_controls":21,
        "image":result["image"],"whole_namespace_qualified":False,"whole_runtime_replaced":False}
    (out/"GATE.json").write_bytes(encoded(gate));print(json.dumps(gate),flush=True)
if __name__=="__main__":main()
