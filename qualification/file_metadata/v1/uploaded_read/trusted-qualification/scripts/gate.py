#!/usr/bin/env python3
"""Bounded actual metadata comparison; preserve every initial failure."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["qualify","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--output",type=Path);p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen qualification source")
    identity=source_evidence(ROOT);work=a.work.absolute();capture=work/"capture"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh full archive")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        report=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=report,process=row)))
        print(encoded(report).decode(),end="");return
    require(not work.exists(),"fresh actual domain only");work.mkdir(parents=True);capture.mkdir()
    environment_value,environment_record=environment(os.environ)
    (capture/"ENVIRONMENT.json").write_bytes(encoded(environment_record))
    rec=Recorder(ROOT,capture/"processes",env=environment_value);reuse=work/"build-reuse";reuse.mkdir()
    completed=[]
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        require(decode(raw)["status"]=="METADATA_SOURCE_AND_INPUT_ONLY_PASS","source/input gate")
        (capture/"INPUT_DOMAIN.json").write_bytes(raw)
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run("build-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,"--source",ROOT,"--work",reuse],timeout=limit)
            require(decode(raw)["status"]=="PASS","complete qualified build "+stage)
        raw,row=rec.run("build-admission",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_uploaded_build.py",
            "--source",ROOT,"--work",reuse],timeout=180)
        guard=decode(raw);require(guard["evidence"]["status"]=="COMPLETE_UPLOADED_METADATA_BUILD_AND_SEVEN_GUARDS_PASS","complete qualified build admission")
        (capture/"BUILD_ADMISSION.json").write_bytes(raw)
        data=capture/"application";data.mkdir();production=data/"production";production.mkdir()
        src=reuse/"original/restored/run/build/file-metadata-callable.elf";dst=production/src.name
        shutil.copy2(src,dst);require(pin(src)==pin(dst)==decode((ROOT/"BUILD_REUSE.json").read_bytes())["elf"],"exact qualified ELF copy")
        for role in("original","native"):
            argv=[sys.executable,"-I","-S","-B",ROOT/"scripts/capture.py","--role",role,"--group",a.group,"--output",data/role]
            if role=="native":argv+=["--build",production]
            raw,row=rec.run("capture-"+role,argv,timeout=180);report=decode(raw);require(report["status"]=="PASS","actual "+role+" capture")
            completed.append(dict(role=role,report=report));(capture/"COMPLETED.json").write_bytes(encoded(completed))
        raw,row=rec.run("full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_main.py","--source",ROOT,"--data",data,"--group",a.group],timeout=180)
        guard=decode(raw);require(guard["before"]==guard["after"]and len(guard["probes"])==11 and guard["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_METADATA_PASS","complete actual original/native read")
        (capture/"READONLY.json").write_bytes(raw)
        raw,row=rec.run("physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/physical_controls.py",
            "--source",ROOT,"--data",data,"--group",a.group,"--output",capture/"controls","--baseline",capture/"READONLY.json"],timeout=180)
        controls=decode(raw);require(controls["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS","physical complete controls")
        result=dict(status="PASS",group=a.group,source=identity,original_native=guard["evidence"],controls=controls,processes=rec.records,
            compiled_build_reused=True,compiler_or_rust_executions=0,complete_upstream_build=decode((ROOT/"BUILD_REUSE.json").read_bytes()),
            upstream_archive_excluded_from_duplicate_semantic_archive=True,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(result))
        require(source_evidence(ROOT)==identity,"source changed during qualification")
        print(encoded(dict(status="METADATA_ACTUAL_COMPLETE_PASS",group=a.group,evidence=guard["evidence"],controls=controls["status"],
            guard_probes=11+controls["guard_probes"])).decode(),end="")
    except BaseException as e:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,completed=completed,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),compiler_or_rust_executions=0,whole_runtime_replaced=False)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
