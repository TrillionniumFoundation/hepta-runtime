#!/usr/bin/env python3
"""Bounded actual original depth profiling; native applications remain zero."""
from pathlib import Path
import argparse,ast,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence
from process import Recorder
import cases
def py(script,*args):return[sys.executable,"-I","-S","-B",script,*args]
def checked(group):
    source=source_evidence(ROOT)
    for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    domain=cases.domain();require(domain["calls"]==27468,"exact frozen original profile case count")
    planned=next(r["cases"]for r in domain["groups"]if r["group"]==int(group))
    return dict(status="ORIGINAL_JSON_PROFILE_SOURCE_PASS",source=source,domain=domain,group=str(group),
        planned_original_calls=planned,native_applications=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen original profile source")
    identity=source_evidence(ROOT);work=a.work.absolute()
    if a.stage=="check":print(canonical(checked(a.group)).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh full original profile archive");a.output.mkdir()
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,"--archive",a.output/"evidence.tar.gz"),timeout=180)
        value=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",process=row,archive=value)))
        print(canonical(value).decode(),end="");return
    require(not work.exists(),"fresh original-only profile workspace");work.mkdir();rec=Recorder(ROOT,work/"processes")
    (work/"ORIGIN.json").write_bytes(canonical(dict(source=str(ROOT),work=str(work),python=sys.executable,group=a.group)))
    stage="source-check"
    try:
        raw,row=rec.run(stage,py(ROOT/"scripts/driver.py","check","--work",work,"--group",a.group,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=60)
        source_check=decode(raw);(work/"SOURCE_CHECK.json").write_bytes(raw)
        stage="runtime-source"
        raw,row=rec.run(stage,py(ROOT/"scripts/runtime.py","--output",work/"runtime"),timeout=60);runtime=decode(raw)
        stage="original-profile"
        raw,row=rec.run(stage,py(ROOT/"scripts/original_capture.py","--group",a.group,
            "--runtime",work/"runtime","--output",work/"capture"),timeout=60);actual=decode(raw)
        require(actual["status"]=="PASS"and actual["cases"]==source_check["planned_original_calls"],"every frozen original operation completed once")
        admission=work/"admission";admission.mkdir();shutil.copy2(work/"ORIGIN.json",admission/"ORIGIN.json")
        shutil.copytree(work/"processes",admission/"processes",copy_function=shutil.copy2)
        for path in(work/"processes").iterdir():
            require(pin(path)==pin(admission/"processes"/path.name)and path.stat().st_mode&0o777==
                (admission/"processes"/path.name).stat().st_mode&0o777,"entire immutable pre-read process custody")
        stage="full-read"
        raw,row=rec.run(stage,py(ROOT/"scripts/read_profile.py","--source",ROOT,"--work",work,"--group",a.group),timeout=180)
        guard=decode(raw);require(guard["status"]=="READONLY_PASS"and guard["evidence"]["actual_calls"]==actual["cases"],"complete original-only pure profile read")
        (work/"READONLY.json").write_bytes(raw)
        result=dict(schema="hepta.runtime.python-json-value.original-profile-gate.v1",status="PASS",group=a.group,source=identity,
            source_check=source_check,runtime=runtime,actual=actual,read=guard["evidence"],processes=rec.records,
            original_calls=actual["cases"],native_applications=0,application_replays=0)
        require(source_evidence(ROOT)==identity,"frozen original profile source unchanged")
        (work/"GATE.json").write_bytes(canonical(result))
        print(canonical(dict(status="ORIGINAL_JSON_DEPTH_PROFILE_CAPTURE_PASS",group=a.group,
            original_calls=actual["cases"],native_applications=0,full_bytes=guard["evidence"]["full_original_bytes"],
            profiles=guard["evidence"]["profiles"],guard_probes=len(guard["probes"]),entries=guard["entries"])).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="UNKNOWN"if rec.records and rec.records[-1]["timed_out"]else"FAIL",
            group=a.group,stage=stage,source=identity,processes=rec.records,error_type=type(error).__name__,
            message=str(error),traceback=traceback.format_exc(),native_applications=0,application_replays=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
