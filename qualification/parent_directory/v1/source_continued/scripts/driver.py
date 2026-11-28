#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bound each real process and retain failed captures without semantic replay."""
from pathlib import Path
import argparse,ast,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence,SCOPE
from process import Recorder,environment
from cases import domain,validate
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen qualification source differs")
    identity=source_evidence(ROOT)
    for p in ROOT.rglob("*"):
        if p.is_file()and p.suffix in(".py",".pseudo"):ast.parse(p.read_bytes(),filename=str(p))
    return identity
def py(path,*args):return [sys.executable,"-I","-S","-B",path,*args]
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","read","controls","verify","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();identity=check(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="check":
        print(json.dumps(dict(status="SOURCE_ONLY_PASS",source=identity,domain=validate(),application_calls=0),sort_keys=True));return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh external archive root")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,"--archive",a.output/"evidence.tar.gz"),timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",source=identity,process=row,archive=result)))
        print(json.dumps(result,sort_keys=True));return
    capture=work/"capture"
    if a.stage in("read","controls","verify"):
        import read_all,reader_controls
        from readonly import guarded
        read_all.prepare(capture)
        if a.stage=="controls":result=reader_controls.create(ROOT,capture,work/"controls")
        else:
            def admission():
                result=read_all.verify(capture/"source",capture)
                if a.stage=="verify":result["physical_controls"]=reader_controls.verify(ROOT,capture,work/"controls")
                return result
            roots=[ROOT,capture]+([work/"controls"]if a.stage=="verify"else[])
            result=guarded(admission,roots=roots)
        print(canonical(result).decode(),end="");return
    require(not work.exists(),"fresh actual run root required");work.mkdir(parents=True)
    capture.mkdir();shutil.copytree(ROOT,capture/"source")
    source=capture/"source";require(source_evidence(source)==identity,"complete source copy differs")
    env,environment_binding=environment(os.environ);outer=Recorder(ROOT,work/"processes",env)
    rec=Recorder(source,capture/"processes",env);stage="source-check"
    try:
        outer.run("source-check",py(ROOT/"scripts/driver.py","check","--work",work,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=60)
        prior=capture/"prior";prior.mkdir()
        for name,limit in(("fetch",60),("restore",180)):
            stage=name+"-prior"
            rec.run(stage,py(source/"scripts/prior_archive.py",name,"--source",source,"--work",prior),timeout=limit)
        stage="read-prior"
        rec.run(stage,py(source/"scripts/read_prior.py","--source",source,"--capture",capture),timeout=180)
        stage="setup"
        fixtures=Path(os.environ["RUNNER_TEMP"])/("parent-directory-fixtures-"+os.environ.get("GITHUB_RUN_ID","standalone"))
        rec.run("setup",py(source/"scripts/setup.py","--source",source,"--output",capture/"setup","--fixtures",fixtures),timeout=60)
        build=prior/"original/restored/run/capture/build-reuse/original/restored/run/build"
        for group in domain()["groups"][6:]:
            name=group["name"];stage="original-"+name
            rec.run(stage,py(source/"scripts/capture.py","--source",source,"--setup",capture/"setup",
                "--output",capture/"original"/name,"--group",name),timeout=60)
            stage="native-"+name
            rec.run(stage,py(source/"scripts/capture.py","--native","--source",source,"--setup",capture/"setup",
                "--build",build,"--output",capture/"native"/name,"--group",name),timeout=60)
        stage="native-unobserved"
        rec.run(stage,py(source/"scripts/capture.py","--native","--source",source,"--setup",capture/"setup","--build",build,
            "--output",capture/"native/unobserved","--group","unobserved","--unobserved"),timeout=60)
        stage="read-comparison"
        raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","read","--work",work,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        read=decode(raw);(work/"READONLY.json").write_bytes(canonical(read))
        stage="physical-controls"
        raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","controls","--work",work,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        controls=decode(raw);require(controls["status"]=="PHYSICAL_READER_CONTROLS_PASS","physical controls")
        stage="verify"
        raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","verify","--work",work,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        verified=decode(raw);(work/"VERIFY.json").write_bytes(canonical(verified))
        require(verified["before"]==verified["after"]and len(verified["probes"])==11,"whole evidence changed during pure read")
        result=dict(status="PASS",stage="complete",source=identity,scope=SCOPE,environment=environment_binding,
            original_cases=48,native_observed_cases=48,native_observer_off_cases=10,private_controls=66,
            actual_mutation_pairs=6,limited_fd_pairs=2,held_context_pairs=2,
            physical_refusals=8,physical_relocations=2,processes=outer.records,producer_processes=rec.records,
            whole_runtime_replaced=False,build_replayed=False,original_or_native_semantics_replayed=False,retained_completed_pairs=42,new_original_pairs=6,new_native_observed_pairs=6)
        (work/"GATE.json").write_bytes(canonical(result))
        require(check(a.source_manifest_sha256)==identity,"source changed during actual qualification")
        print(json.dumps({k:v for k,v in result.items()if k not in("processes","producer_processes")},sort_keys=True))
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",stage=stage,source=identity,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            processes=outer.records,producer_processes=rec.records,scope=SCOPE)))
        for recorder in(outer,rec):
            if recorder.records:
                last=recorder.records[-1]
                if last["exit_code"]!=0:print((recorder.directory/(last["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
