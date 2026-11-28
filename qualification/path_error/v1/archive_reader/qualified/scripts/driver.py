#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""CI-only bounded source/build/reference/native and immutable evidence gates."""
from pathlib import Path
import argparse,ast,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence,SCOPE
from process import Recorder,environment
import cases
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen source manifest changed")
    identity=source_evidence(ROOT)
    for path in ROOT.rglob("*"):
        if path.is_file()and path.suffix in(".py",".pseudo"):ast.parse(path.read_bytes(),filename=str(path))
    cases.validate();return identity
def py(path,*args):return [sys.executable,"-I","-S","-B",path,*args]
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","read","controls","verify","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--hepta",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();identity=check(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="check":
        print(canonical(dict(status="SOURCE_ONLY_PASS",source=identity,domain=cases.validate(),application_calls=0)).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh external archive output")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,
            "--archive",a.output/"evidence.tar.gz"),timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",process=row,archive=result)))
        print(canonical(result).decode(),end="");return
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
            result=guarded(admission,roots=[ROOT,capture]+([work/"controls"]if a.stage=="verify"else[]))
        print(canonical(result).decode(),end="");return
    require(a.hepta is not None and not work.exists(),"fresh CI run and pinned compiler required")
    work.mkdir(parents=True);capture.mkdir();shutil.copytree(ROOT,capture/"source")
    source=capture/"source";hepta=a.hepta.resolve(strict=True)
    require(source_evidence(source)==identity,"complete retained source differs")
    (capture/"ORIGIN.json").write_bytes(canonical(dict(capture=str(capture),source=str(source),
        python=sys.executable,hepta=str(hepta))))
    env,binding=environment(os.environ);env["LC_ALL"]="C.UTF-8"
    outer=Recorder(ROOT,work/"processes",env);rec=Recorder(source,capture/"processes",env)
    stage="author"
    try:
        rec.run("author",py(source/"authoring/author_path_error.py","--source",source,
            "--hepta",hepta,"--output",capture/"authored"),timeout=60)
        for name in("path_error.hepta","path_error.pseudo","path_error_composition.json","platform_data.json"):
            require((capture/"authored"/name).read_bytes()==(source/"native"/name).read_bytes(),"fresh author does not reproduce frozen bytes")
        stage="native-build";rec.run(stage,py(source/"scripts/build.py","--hepta",hepta,"--capture",capture),timeout=900)
        for group in cases.domain()["groups"]:
            name=group["name"];stage="original-"+name
            rec.run(stage,py(source/"scripts/original.py","--group",name,"--output",capture/"original"/name),timeout=60)
            stage="native-"+name
            rec.run(stage,py(source/"scripts/native_capture.py","--group",name,"--capture",capture,
                "--output",capture/"native"/name),timeout=60)
        stage="native-controls"
        rec.run(stage,py(source/"scripts/native_capture.py","--group","controls","--capture",capture,
            "--output",capture/"native/controls"),timeout=60)
        for name in("read","controls","verify"):
            stage=name;raw,row=outer.run(name,py(ROOT/"scripts/driver.py",name,"--work",work,
                "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
            result=decode(raw);(work/(name.upper()+".json")).write_bytes(canonical(result))
            require(result["status"]==("PHYSICAL_READER_CONTROLS_PASS"if name=="controls"else"READONLY_PASS"),
                "pure gate returned wrong status")
            print(canonical(dict(stage=name,status=result["status"],elapsed_seconds=row["elapsed_seconds"],
                entries=result.get("entries"),guards=len(result.get("probes",[])))).decode(),end="",flush=True)
        require(check(a.source_manifest_sha256)==identity,"source changed during qualification")
        result=dict(status="PASS",stage="complete",schema="hepta.runtime.path-error.gate.v1",
            source=identity,scope=SCOPE,environment=binding,domain=cases.validate(),
            producer_processes=len(rec.records),original_or_native_replayed=False,
            physical_refusals=9,physical_relocations=2)
        (work/"GATE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",stage=stage,source=identity,scope=SCOPE,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            processes=outer.records,producer_processes=rec.records,original_or_native_replayed=False)))
        for recorder in(outer,rec):
            if recorder.records and recorder.records[-1]["exit_code"]!=0:
                print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
