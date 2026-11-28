#!/usr/bin/env python3
"""Frozen single-shot actual write qualification and pure complete evidence admission."""
from pathlib import Path
import argparse,ast,os,platform,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder,environment
def checked(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen actual write source identity")
    return source_evidence(ROOT)
def runtime_value(path):
    value=decode((path/"RUNTIME.json").read_bytes())
    require(value["status"]=="SOURCE_AND_RUNTIME_ONLY_PASS"and value["source"]==source_evidence(ROOT)
        and value["python_version"]==[3,12,3]and value["signal_profile"]=={"13":1,"25":1}
        and value["original_write_application_calls"]==value["native_write_application_calls"]==0,
        "fixed original runtime input")
    require({p.name for p in path.iterdir()}=={"RUNTIME.json"}|{r["copy"]for r in value["modules"].values()},
        "complete actual runtime module set")
    for row in value["modules"].values():
        require(pin(path/row["copy"])=={k:row[k]for k in("bytes","sha256")},"complete runtime module bytes")
    return value
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["source","run","read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--group",type=int);p.add_argument("--case",type=int);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity=checked(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="read":
        from read_capture import verify
        from readonly import guarded
        result=guarded(lambda:verify(ROOT,work/"cases"/str(a.case),a.case,runtime_value(work/"runtime")),
            roots=[ROOT,work/"runtime",work/"cases"/str(a.case)])
        print(encoded(result).decode(),end="");return
    work.mkdir(parents=True,exist_ok=True)
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete actual archive output")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,process=row,archive=decode(raw))))
        print(raw.decode(),end="");return
    env,binding=environment(os.environ);rec=Recorder(ROOT,work/"processes",env)
    applications=[];reads=[];failures=[];domain=decode((ROOT/"DOMAIN.json").read_bytes())
    def command(name,argv,timeout=180):
        raw,row=rec.run(name,[sys.executable,"-I","-S","-B",*argv],timeout=timeout);return raw,row
    try:
        raw,row=command("runtime-source",[ROOT/"scripts/runtime_preflight.py","--source",ROOT,"--output",work/"runtime"])
        if a.stage=="source":
            result=dict(status="FROZEN_SOURCE_ONLY_PASS",source=identity,runtime=decode(raw),process=row,application_calls=0)
            (work/"GATE.json").write_bytes(encoded(result));print(encoded(result).decode(),end="");return
        group=next(g for g in domain["groups"]if g["id"]==a.group)
        for stage in("fetch","unpack","read"):
            raw,row=command("build-"+stage,[ROOT/"scripts/build_reuse.py",stage,"--source",ROOT,"--work",work])
            (work/("BUILD_"+stage.upper()+".json")).write_bytes(raw)
        raw,row=command("archive-equality-retire",[ROOT/"scripts/retire_build.py","--source",ROOT,"--work",work])
        (work/"BUILD_RETIREMENT.json").write_bytes(raw)
        for case_id in group["cases"]:
            for role in("original","native"):
                name="capture-"+str(case_id)+"-"+role
                argv=[ROOT/"scripts/capture.py","--role",role,"--case",str(case_id),
                    "--output",work/"cases"/str(case_id)/role,"--build",work/"production"]
                try:
                    raw,row=command(name,argv,timeout=60)
                    applications.append(dict(case=case_id,role=role,status="PASS",process=row,capture=decode(raw)))
                except BaseException as e:
                    row=rec.records[-1]if rec.records else None
                    status="UNKNOWN"if row is None or row["timed_out"]or not row["completed"]else"FAIL"
                    applications.append(dict(case=case_id,role=role,status=status,process=row,error_type=type(e).__name__,message=str(e)))
                    failures.append(dict(stage=name,status=status,message=str(e)))
            # Every application in the frozen group is captured before any reader can fail.
        for case_id in group["cases"]:
            if any(r["status"]!="PASS"for r in applications if r["case"]==case_id):continue
            name="pure-read-"+str(case_id)
            try:
                raw,row=command(name,[Path(__file__).resolve(),"read","--work",work,"--case",str(case_id),
                    "--source-manifest-sha256",a.source_manifest_sha256])
                result=decode(raw);require(result["status"]=="READONLY_PASS"and result["before"]==result["after"]
                    and len(result["probes"])==11 and result["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_WRITE_PASS",
                    "full pure actual comparison custody")
                reads.append(dict(case=case_id,status="PASS",process=row,result=result))
                (work/("READ_"+str(case_id)+".json")).write_bytes(raw)
            except BaseException as e:
                failures.append(dict(stage=name,status="FAIL",message=str(e)))
        controls=None
        if a.group==0 and any(r["case"]==0 and r["status"]=="PASS"for r in reads):
            try:
                raw,row=command("physical-controls",[ROOT/"scripts/physical_controls.py","run","--source",ROOT,
                    "--data",work/"cases/0","--runtime",work/"runtime","--output",work/"controls"])
                controls=decode(raw);require(controls["status"]=="PHYSICAL_CONTROLS_PASS"and controls["application_calls"]==0,
                    "physical reader controls are pure")
            except BaseException as e:failures.append(dict(stage="physical-controls",status="FAIL",message=str(e)))
        require(checked(a.source_manifest_sha256)==identity,"frozen source changed during actual qualification")
        status="PASS"if not failures and len(reads)==len(group["cases"])and(a.group!=0 or controls)else"FAIL"
        result=dict(status=status,group=a.group,source=identity,domain=pin(ROOT/"DOMAIN.json"),applications=applications,
            reads=reads,controls=controls,failures=failures,processes=rec.records,environment=binding,
            application_replays=0,prior_completed_applications_replayed=0,full_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(result))
        print(encoded(dict(status=status,group=a.group,cases=group["cases"],
            applications=[{k:r[k]for k in("case","role","status")}for r in applications],
            read_cases=[r["case"]for r in reads],failures=failures,
            observed=[r["result"]["evidence"]for r in reads],physical_refusals=controls["refusals"]if controls else 0,
            physical_relocations=controls["admissions"]if controls else 0)).decode(),end="")
        if failures:
            for failure in failures:
                path=rec.directory/(failure["stage"]+".stderr")
                if path.exists():print(path.read_text(),file=sys.stderr)
        require(status=="PASS","frozen actual write qualification did not close")
    except BaseException as e:
        if not(work/"GATE.json").exists():
            (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,error_type=type(e).__name__,
                message=str(e),traceback=traceback.format_exc(),processes=rec.records,applications=applications,
                replay_permitted=False)))
            if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
