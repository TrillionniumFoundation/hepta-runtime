#!/usr/bin/env python3
"""Bound one copied-B3 JSON decoder build and complete pure read, zero applications."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from process import Recorder
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen literal build source")
    return source_evidence(ROOT)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["build","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--hepta",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();identity=check(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh full build export")
        a.output.mkdir();recorder=Recorder(ROOT,a.output/"processes")
        raw,process=recorder.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        value=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",source=identity,
            process=process,archive=value,new_application_calls=0)))
        print(canonical(value).decode(),end="");return
    require(a.hepta is not None and not work.exists(),"fresh fixed source compile workspace")
    work.mkdir();recorder=Recorder(ROOT,work/"processes")
    try:
        raw,process=recorder.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/build.py","check"],timeout=60)
        checked=decode(raw);require(checked["status"]=="PYTHON_JSON_VALUE_SOURCE_PASS","exact author and production source")
        (work/"SOURCE_CHECK.json").write_bytes(raw)
        raw,process=recorder.run("native-build",[sys.executable,"-I","-S","-B",ROOT/"scripts/build.py","build",
            "--hepta",a.hepta.resolve(strict=True),"--output",work/"artifact"],timeout=900)
        build=decode(raw)
        raw,process=recorder.run("read-build",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_build.py",
            "--source",ROOT,"--build",work/"artifact"],timeout=180)
        value=decode(raw);require(value["before"]==value["after"]and len(value["probes"])==11,"complete pure guarded build")
        (work/"READONLY.json").write_bytes(raw)
        gate=dict(status="PASS",schema="hepta.runtime.python-json-value.build-gate.v1",source=identity,
            source_check=checked,build=build,read=value["evidence"],processes=recorder.records,
            guard_probes=11,unchanged_entries=value["entries"],hia_compiles=1,
            new_seed_executions=0,new_bootstrap_generations=0,application_hia_executions=0,original_applications=0,
            whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(canonical(gate))
        require(check(a.source_manifest_sha256)==identity,"source changed during compile or pure read")
        print(canonical(dict(status="PYTHON_JSON_VALUE_BUILD_ONLY_PASS",image=build["image"],hia_compiles=1,
            unchanged_entries=value["entries"],guard_probes=11,new_seed_executions=0,
            new_bootstrap_generations=0,application_hia_executions=0,original_applications=0)).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",source=identity,processes=recorder.records,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            application_hia_executions=0,original_applications=0)))
        if recorder.records:print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
