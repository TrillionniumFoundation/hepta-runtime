#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bound build-only native work and complete pure admission, with no application invocation."""
from pathlib import Path
import argparse
import json
import sys
import traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from callable_common import encoded,decode,pin,require,sources
from process import Recorder
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen build source differs")
    return sources(ROOT)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("stage",choices=["build","read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--hepta",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();identity=check(a.source_manifest_sha256);work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    if a.stage=="read":
        import read_callable_build
        from readonly import guarded
        result=guarded(lambda:read_callable_build.verify(ROOT,work/"build"),roots=[ROOT,work/"build"])
        print(encoded(result).decode(),end="")
        return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh export directory required")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",process=row,archive=result,source=identity,
            application_hia_executions=0,rust_executions=0)))
        print(json.dumps(result,sort_keys=True));return
    rec=Recorder(ROOT,work/"processes")
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/build_callable.py","check",
            "--source",ROOT],timeout=60)
        require(decode(raw)["status"]=="SOURCE_ONLY_PASS","source check failed")
        raw,row=rec.run("native-build",[sys.executable,"-I","-S","-B",ROOT/"scripts/build_callable.py","build",
            "--source",ROOT,"--hepta",a.hepta.resolve(strict=True),"--output",work/"build"],timeout=900)
        build=decode(raw)
        raw,row=rec.run("read-build",[sys.executable,"-I","-S","-B",Path(__file__).resolve(),"read",
            "--work",work,"--source-manifest-sha256",a.source_manifest_sha256],timeout=180)
        result=decode(raw)
        require(result["before"]==result["after"] and len(result["probes"])==11,"pure build read custody failed")
        (work/"READONLY.json").write_bytes(encoded(result))
        gate=dict(status="PASS",stage="complete",source=identity,build=build,build_read=result["evidence"],
            processes=rec.records,guard_probes=11,unchanged_entries=result["entries"],
            application_hia_executions=0,rust_executions=0,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(gate))
        require(check(a.source_manifest_sha256)==identity,"source changed during build")
        print(json.dumps(dict(status="BUILD_ONLY_PASS",executable=build["executable"],runtime_images=3,
            native_compiles=5,guard_probes=11,unchanged_entries=result["entries"],
            application_hia_executions=0,rust_executions=0),sort_keys=True))
    except BaseException as exc:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=rec.records,
            error_type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc(),
            application_hia_executions=0,rust_executions=0)))
        if rec.records:
            print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
