#!/usr/bin/env python3
"""Pure retained filesystem recovery. No original application, compiler or native image is run."""
from pathlib import Path
import argparse,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["recover","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--output",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen pure source manifest")
    identity=source_evidence(ROOT);work=a.work.absolute();capture=work/"capture"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh full pure archive")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        report=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=report,process=row)))
        print(encoded(report).decode(),end="");return
    require(not work.exists(),"fresh pure recovery");work.mkdir(parents=True);capture.mkdir()
    env,env_record=environment(os.environ);(capture/"ENVIRONMENT.json").write_bytes(encoded(env_record))
    rec=Recorder(ROOT,capture/"processes",env=env)
    semantic=work/"semantic";semantic.mkdir();reuse=work/"build-reuse";reuse.mkdir()
    frozen=capture/"frozen";frozen.mkdir()
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_recovery_source.py"],timeout=60)
        require(decode(raw)["status"]=="PURE_FILESYSTEM_RECOVERY_SOURCE_PASS","pure source admission")
        for stage,limit in (("fetch",60),("unpack",180)):
            raw,row=rec.run("semantic-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/retained_archive.py",stage,
                "--source",ROOT,"--work",semantic,"--group",a.group],timeout=limit)
            require(decode(raw)["status"]=="PASS","complete original archive "+stage)
        for stage,limit in (("fetch",60),("unpack",180)):
            raw,row=rec.run("build-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,
                "--source",ROOT,"--work",reuse],timeout=limit)
            require(decode(raw)["status"]=="PASS","complete original native build "+stage)
        original_source=semantic/"original/restored/source";data=semantic/"original/restored/run/application"
        raw,row=rec.run("origin-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_origin_main.py",
            "--reader",ROOT,"--semantic",semantic,"--reuse",reuse,"--group",a.group],timeout=180)
        require(decode(raw)["evidence"]["status"]=="ORIGINAL_COMPLETE_FILESYSTEM_CAPTURE_AND_PACKING_FAILURE_PRESERVED",
            "original completed applications and first failure preserved")
        raw,row=rec.run("full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_main.py",
            "--source",original_source,"--data",data,"--group",a.group],timeout=180)
        primary=decode(raw);require(primary["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_MULTI_FILESYSTEM_PASS",
            "all complete retained physical buffers")
        (frozen/"READONLY.json").write_bytes(raw)
        raw,row=rec.run("physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/physical_controls.py",
            "--source",original_source,"--data",data,"--group",a.group,"--output",frozen/"controls",
            "--baseline",frozen/"READONLY.json"],timeout=180)
        require(decode(raw)["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS","all physical controls")
        proof=frozen/"proof_inputs";proof.mkdir();shutil.copytree(capture/"processes",proof/"processes")
        shutil.copy2(capture/"ENVIRONMENT.json",proof/"ENVIRONMENT.json")
        for path in (capture/"processes").iterdir():
            copied=proof/"processes"/path.name
            require(path.read_bytes()==copied.read_bytes() and path.stat().st_mode&0o777==copied.stat().st_mode&0o777,
                "complete immutable pre-final process prefix")
        raw,row=rec.run("final-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_recovery_main.py","final",
            "--reader",ROOT,"--semantic",semantic,"--reuse",reuse,"--frozen",frozen,"--group",a.group],timeout=180)
        final=decode(raw);require(final["evidence"]["status"]=="COMPLETE_SAME_CAPTURE_FILESYSTEM_RECOVERY_PASS",
            "full same-capture recovery final reader")
        (capture/"FINAL_READONLY.json").write_bytes(raw)
        result=dict(status="PASS",group=a.group,source=identity,processes=rec.records,evidence=final["evidence"],
            original_failure_preserved=True,new_original_or_native_applications=0,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(result))
        require(source_evidence(ROOT)==identity,"pure source changed")
        actual=final["evidence"]["actual"]
        print(encoded(dict(status="COMPLETE_SAME_CAPTURE_FILESYSTEM_RECOVERY_PASS",group=a.group,
            cases=actual["cases"],original_invocations=actual["original"]["entry_invocations"],
            native_invocations=actual["native"]["entry_invocations"],native=actual["native"],
            physical_refusals=8,full_relocations=2,
            new_original_or_native_applications=0)).decode(),end="")
    except BaseException as exc:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,
            error_type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc(),new_original_or_native_applications=0,
            original_failure_preserved=True,whole_runtime_replaced=False)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
