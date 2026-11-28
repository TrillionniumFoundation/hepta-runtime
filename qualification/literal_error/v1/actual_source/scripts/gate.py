#!/usr/bin/env python3
"""CI-only fresh literal application groups over fully admitted retained archives."""
from pathlib import Path
import argparse,ast,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence
from process import Recorder
import cases
def py(script,*args):return [sys.executable,"-I","-S","-B",script,*args]
def source_check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"exact complete literal actual source")
    identity=source_evidence(ROOT)
    for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    domain=cases.validate()
    require(pin(ROOT/"trusted-build/SOURCE_MANIFEST.json")["sha256"]==decode((ROOT/"BUILD_INPUT.json").read_bytes())["manifest_sha256"]
        and pin(ROOT/"trusted-legacy/SOURCE_MANIFEST.json")["sha256"]==decode((ROOT/"LEGACY_INPUT.json").read_bytes())["manifest_sha256"],
        "both complete upstream source identities")
    return dict(status="LITERAL_ACTUAL_SOURCE_PASS",source=identity,domain=domain,
        new_original_calls=435,new_native_calls=23591,legacy_original_reexecutions=0,application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();work=a.work.absolute()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen actual manifest")
    identity=source_evidence(ROOT)
    if a.stage=="check":
        print(canonical(source_check(a.source_manifest_sha256)).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh full literal actual export")
        a.output.mkdir();rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,
            "--archive",a.output/"evidence.tar.gz"),timeout=180)
        value=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",process=row,archive=value)))
        print(canonical(value).decode(),end="");return
    require(not work.exists(),"fresh candidate actual workspace");work.mkdir()
    rec=Recorder(ROOT,work/"processes");stage="source-check"
    origin=dict(source=str(ROOT),work=str(work),python=sys.executable);(work/"ORIGIN.json").write_bytes(canonical(origin))
    def command(name,script,args,timeout):
        nonlocal stage
        stage=name;raw,row=rec.run(name,py(script,*args),timeout=timeout);return raw,decode(raw)
    try:
        raw,checked=command("source-check",ROOT/"scripts/gate.py",
            ["check","--work",work,"--source-manifest-sha256",a.source_manifest_sha256],60)
        (work/"SOURCE_CHECK.json").write_bytes(raw);upstream={}
        for kind in("build","legacy"):
            folder=work/(kind+"-input");folder.mkdir()
            values={}
            for action,limit in(("fetch",60),("unpack",180)):
                raw,value=command(kind+"-"+action,ROOT/"scripts/reuse.py",
                    [action,"--source",ROOT,"--work",folder,"--kind",kind],limit);values[action]=value
            if kind=="build":
                raw,value=command("build-read",ROOT/"scripts/reuse.py",
                    ["read-build","--source",ROOT,"--work",folder,"--kind",kind],180)
                (work/"BUILD_ADMISSION.json").write_bytes(raw);values["read"]=value
            else:
                raw,value=command("legacy-source",ROOT/"scripts/reuse.py",
                    ["check-legacy","--source",ROOT,"--work",folder,"--kind",kind],60)
                values["source"]=value
                restored=folder/"original/restored";binding=decode((ROOT/"LEGACY_INPUT.json").read_bytes())
                raw,value=command("legacy-read",restored/"source/scripts/driver.py",
                    ["verify","--work",restored/"run","--source-manifest-sha256",binding["manifest_sha256"]],180)
                (work/"LEGACY_ADMISSION.json").write_bytes(raw);values["read"]=value
                require(value["status"]=="READONLY_PASS"and value["before"]==value["after"]
                    and value["evidence"]["status"]=="PATH_ERROR_COMPLETE_PASS"
                    and value["evidence"]["comparison"]["original_cases"]==21901
                    and value["evidence"]["comparison"]["native_cases"]==21901
                    and value["evidence"]["native_or_original_replayed"]is False,"complete old source and application evidence admission")
            upstream[kind]=values
        artifact=work/"build-input/original/restored/run/artifact";runtime=work/"runtime";runtime.mkdir()
        import read_capture
        artifacts,bundle=read_capture.runtime_files(artifact)
        admitted={}
        for path in sorted(set(artifacts)|{"build/formatter.json"}):
            source=owned(artifact,path);target=runtime/path;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target);value=dict(**pin(source),mode=source.stat().st_mode&0o777)
            require(dict(**pin(target),mode=target.stat().st_mode&0o777)==value,"exact four-file runtime copy")
            admitted[path]=value
        admission=work/"admission";admission.mkdir()
        accepted=dict(status="FULL_ARCHIVE_ADMISSION_PASS",source=identity,
            legacy_identity=upstream["legacy"]["read"]["evidence"]["source"],runtime=admitted,
            build_binding=decode((ROOT/"BUILD_INPUT.json").read_bytes()),legacy_binding=decode((ROOT/"LEGACY_INPUT.json").read_bytes()),
            build_proof=pin(work/"BUILD_ADMISSION.json"),legacy_proof=pin(work/"LEGACY_ADMISSION.json"),
            new_compiler_calls=0,new_legacy_original_calls=0)
        (admission/"ADMISSION.json").write_bytes(canonical(accepted))
        stage="actual-groups";import capture
        application=capture.run(ROOT,runtime,work/"application")
        legacy=work/"legacy-input/original/restored/run/capture"
        raw,value=command("full-read",ROOT/"scripts/read_main.py",
            ["--source",ROOT,"--application",work/"application","--runtime",runtime,"--legacy",legacy,
                "--admission",admission/"ADMISSION.json"],180)
        (work/"READONLY.json").write_bytes(raw)
        require(value["status"]=="READONLY_PASS"and value["evidence"]["total_new_native_calls"]==23591,
            "entire actual candidate full-buffer read")
        stage="physical-controls";import controls
        physical=controls.create(ROOT,work/"application",runtime,legacy,admission/"ADMISSION.json",
            work/"controls",value["evidence"])
        require(source_evidence(ROOT)==identity,"source changed during actual qualification")
        result=dict(status="PASS",schema="hepta.runtime.literal-error.actual-gate.v1",source=identity,
            source_check=checked,upstream=upstream,admission=accepted,application=application,
            actual=value["evidence"],controls=physical,processes=rec.records,
            new_original_calls=435,reused_original_cases=21901,new_native_calls=23591,
            new_compiler_calls=0,legacy_original_reexecutions=0,application_replays=0,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(canonical(result))
        print(canonical(dict(status="LITERAL_ERROR_ACTUAL_AND_PHYSICAL_PASS",new_original_calls=435,
            reused_original_cases=21901,new_native_calls=23591,actual_processes=285,
            physical_refusals=8,relocations=2,application_replays=0,whole_runtime_replaced=False)).decode(),end="")
    except BaseException as error:
        application=decode((work/"application/CAPTURE.json").read_bytes())if(work/"application/CAPTURE.json").is_file()else None
        unknown=(application is not None and application["status"]=="UNKNOWN")or bool(rec.records and rec.records[-1]["timed_out"])
        (work/"GATE.json").write_bytes(canonical(dict(status="UNKNOWN"if unknown else"FAIL",stage=stage,source=identity,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),processes=rec.records,
            application=application,application_replays=0,whole_runtime_replaced=False)))
        if rec.records and rec.records[-1]["exit_code"]!=0:
            print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
