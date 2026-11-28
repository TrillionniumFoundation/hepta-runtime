#!/usr/bin/env python3
"""Bound first actual captures and retain every failure; never replay successful calls."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence,SCOPE
from process import Recorder,environment
from cases import group,validate
from check_source import verify as source_check
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"complete frozen source manifest")
    return source_check(ROOT)
def py(path,*args):return[sys.executable,"-I","-S","-B",path,*args]
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","read","controls","verify","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();checked=check(a.source_manifest_sha256);identity=checked["source"];work=a.work.absolute();name=a.group
    require(len(group(name))==2,"fixed two-input role group")
    if a.stage=="check":print(canonical(checked).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete export");a.output.mkdir(parents=True)
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,"--archive",a.output/"evidence.tar.gz"),timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",source=identity,process=row,archive=result)))
        print(canonical(result).decode(),end="");return
    capture=work/"capture"
    if a.stage in("read","controls","verify"):
        import read_all,reader_controls
        from readonly import guarded
        read_all.prepare(capture)
        if a.stage=="controls":result=reader_controls.create(ROOT,capture,work/"controls",name)
        else:
            def admission():
                result=read_all.verify(ROOT,capture,name)
                if a.stage=="verify":result["physical_controls"]=reader_controls.verify(ROOT,capture,work/"controls",name)
                return result
            result=guarded(admission,roots=[ROOT,capture]+([work/"controls"]if a.stage=="verify"else[]))
        print(canonical(result).decode(),end="");return
    require(not work.exists(),"fresh actual work root");work.mkdir(parents=True);capture.mkdir();shutil.copytree(ROOT,capture/"source")
    source=capture/"source";require(source_evidence(source)==identity,"entire actual source copy")
    (capture/"ORIGIN.json").write_bytes(canonical(dict(capture=str(capture),python=str(Path(sys.executable).resolve(strict=True)),group=name)))
    env,env_binding=environment(os.environ);outer=Recorder(ROOT,work/"processes",env);rec=Recorder(source,capture/"processes",env);stage="source-check"
    try:
        outer.run(stage,py(ROOT/"scripts/driver.py","check","--work",work,"--group",name,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=60)
        reuse=capture/"build-reuse";reuse.mkdir()
        for mode,stage,limit in(("fetch","fetch-build",60),("unpack","restore-build",180)):
            rec.run(stage,py(source/"scripts/build_reuse.py",mode,"--source",source,"--work",reuse),timeout=limit)
        stage="read-build";raw,_=rec.run(stage,py(source/"scripts/read_upstream.py","--source",source,"--work",reuse),timeout=180)
        (capture/"BUILD_ADMISSION.json").write_bytes(raw)
        fixtures=Path(os.environ["RUNNER_TEMP"])/("stdio-r67-"+os.environ["GITHUB_RUN_ID"]+"-"+os.environ.get("GITHUB_RUN_ATTEMPT","1")+"-"+name)
        stage="setup";rec.run(stage,py(source/"scripts/setup.py","--source",source,"--output",capture/"setup","--fixtures",fixtures,"--group",name),timeout=60)
        build=reuse/"original/restored/run/build"
        for role in("original","production","observed"):
            stage=role+"-"+name
            rec.run(stage,py(source/"scripts/capture.py","--source",source,"--setup",capture/"setup",
                "--build",build,"--output",capture/role/name,"--group",name,"--role",role),timeout=180)
        stage="read-comparison";raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","read","--work",work,"--group",name,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        read=decode(raw);(work/"READONLY.json").write_bytes(raw)
        stage="physical-controls";raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","controls","--work",work,"--group",name,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        controls=decode(raw);require(controls["status"]=="PHYSICAL_STDIO_READ67_CONTROLS_PASS","all complete physical controls")
        stage="verify";raw,_=outer.run(stage,py(ROOT/"scripts/driver.py","verify","--work",work,"--group",name,
            "--source-manifest-sha256",a.source_manifest_sha256),timeout=180)
        verified=decode(raw);(work/"VERIFY.json").write_bytes(raw)
        require(verified["before"]==verified["after"]and len(verified["probes"])==11,"complete final read guard")
        result=dict(status="PASS",stage="complete",group=name,source=identity,scope=SCOPE,environment=env_binding,
            actual=read["evidence"]["comparison"],controls=controls,processes=outer.records,producer_processes=rec.records,
            new_compiler_calls=0,application_calls_replayed=0,build_replayed=False,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(canonical(result));require(check(a.source_manifest_sha256)==checked,"source changed")
        print(canonical({k:v for k,v in result.items()if k not in("processes","producer_processes","controls")}).decode(),end="")
    except BaseException as e:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",stage=stage,group=name,source=identity,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),processes=outer.records,
            producer_processes=rec.records,scope=SCOPE,build_replayed=False)))
        for recorder in(outer,rec):
            if recorder.records and recorder.records[-1]["exit_code"]!=0:
                print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
