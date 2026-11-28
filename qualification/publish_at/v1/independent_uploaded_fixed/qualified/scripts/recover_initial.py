#!/usr/bin/env python3
"""Recover the two initial complete captures without application execution."""
from pathlib import Path
import argparse,sys,os,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["recover","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--output",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen recovery source")
    identity=source_evidence(ROOT);work=a.work.absolute();capture=work/"capture"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh recovery archive");a.output.mkdir(parents=True)
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=decode(raw),process=row)))
        print(raw.decode(),end="");return
    require(a.group in decode((ROOT/"PRESERVED_INITIAL.json").read_bytes())["groups"],"only completed original capture may recover")
    require(not work.exists(),"fresh pure recovery");work.mkdir(parents=True);capture.mkdir()
    env,env_record=environment(os.environ);(capture/"ENVIRONMENT.json").write_bytes(encoded(env_record))
    rec=Recorder(ROOT,capture/"processes",env=env);reuse=work/"build-reuse";reuse.mkdir()
    retained=capture/"retained-initial";retained.mkdir()
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        require(decode(raw)["status"]=="PUBLISH_SOURCE_AND_INPUT_ONLY_PASS","complete narrow reader fix source")
        (capture/"INPUT_DOMAIN.json").write_bytes(raw)
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run("build-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,
                "--source",ROOT,"--work",reuse],timeout=limit);require(decode(raw)["status"]=="PASS","original complete build "+stage)
        raw,row=rec.run("build-admission",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_uploaded_build.py","--source",ROOT,"--work",reuse],timeout=180)
        require(decode(raw)["evidence"]["status"]=="COMPLETE_UPLOADED_PUBLISH_BUILD_AND_SEVEN_GUARDS_PASS","complete unchanged build evidence")
        (capture/"BUILD_ADMISSION.json").write_bytes(raw)
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run("initial-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/capture_reuse.py",stage,
                "--source",ROOT,"--work",retained,"--group",a.group],timeout=limit)
            require(decode(raw)["status"]=="PASS","full retained initial capture "+stage)
        raw,row=rec.run("read-retained-initial",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_initial.py",
            "--source",ROOT,"--retained",retained,"--build-work",reuse,"--group",a.group],timeout=180)
        guard=decode(raw);require(guard["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_PUBLISH_PASS"and guard["application_executions"]==0,"complete retained comparison")
        (capture/"READONLY.json").write_bytes(raw)
        old=retained/"original/restored";original_source=old/"source";data=old/"run/application"
        raw,row=rec.run("physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/physical_controls.py",
            "--source",original_source,"--data",data,"--group",a.group,"--output",capture/"controls","--baseline",capture/"READONLY.json"],timeout=180)
        controls=decode(raw);require(controls["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS","complete fixed-reader physical domain")
        require(source_evidence(ROOT)==identity,"source unchanged by recovery")
        result=dict(status="PASS",group=a.group,source=identity,processes=rec.records,original_native=guard["evidence"],controls=controls,
            retained_initial=decode((ROOT/"PRESERVED_INITIAL.json").read_bytes())["groups"][a.group],pure_recovery=True,
            new_application_executions=0,compiler_or_rust_executions=0,complete_upstream_build=decode((ROOT/"BUILD_REUSE.json").read_bytes()),
            upstream_archive_excluded_from_duplicate_semantic_archive=True,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(result))
        print(encoded(dict(status="PUBLISH_RETAINED_INITIAL_RECOVERY_PASS",group=a.group,evidence=guard["evidence"],
            controls=controls["status"],new_application_executions=0,guard_probes=132)).decode(),end="")
    except BaseException as e:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,error_type=type(e).__name__,
            message=str(e),traceback=traceback.format_exc(),new_application_executions=0,compiler_or_rust_executions=0,whole_runtime_replaced=False)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
