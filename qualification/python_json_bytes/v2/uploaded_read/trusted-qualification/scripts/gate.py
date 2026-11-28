#!/usr/bin/env python3
"""CI-only exact frozen decoder qualification, bounded children and complete export."""
from pathlib import Path
import argparse,ast,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,owned,require,source_evidence
from process import Recorder
import cases
def py(script,*args):return [sys.executable,"-I","-S","-B",script,*args]
def source_check(expected,shard):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"exact complete JSON byte qualification source")
    identity=source_evidence(ROOT)
    for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    domain=cases.domain();selected=cases.shard_domain(shard)
    require(domain["semantic_cases"]==100640 and domain["controls"]==30 and domain["all_two_byte_inputs"]==65536,
        "complete frozen Unicode/byte domain")
    require(pin(ROOT/"trusted-build/SOURCE_MANIFEST.json")["sha256"]==
        decode(owned(ROOT,"BUILD_INPUT.json").read_bytes())["manifest_sha256"],"complete upstream source identity")
    return dict(status="PYTHON_JSON_BYTES_ACTUAL_SOURCE_PASS",source=identity,domain=domain,selected=selected,
        new_original_calls=selected["semantic_cases"],new_native_calls=selected["semantic_cases"]+selected["private_native_calls"],
        application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--shard",type=int,required=True);p.add_argument("--output",type=Path);a=p.parse_args();work=a.work.absolute()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen decoder qualification manifest")
    identity=source_evidence(ROOT)
    if a.stage=="check":print(canonical(source_check(a.source_manifest_sha256,a.shard)).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh whole decoder export");a.output.mkdir()
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,
            "--archive",a.output/"evidence.tar.gz"),timeout=180)
        value=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",process=row,archive=value)))
        print(canonical(value).decode(),end="");return
    require(not work.exists(),"fresh exact frozen actual workspace");work.mkdir();rec=Recorder(ROOT,work/"processes");stage="source-check"
    origin=dict(source=str(ROOT),work=str(work),python=sys.executable,shard=a.shard)
    (work/"ORIGIN.json").write_bytes(canonical(origin))
    def command(name,script,args,timeout):
        nonlocal stage
        stage=name;raw,row=rec.run(name,py(script,*args),timeout=timeout);return raw,decode(raw)
    try:
        raw,checked=command("source-check",ROOT/"scripts/gate.py",
            ["check","--work",work,"--source-manifest-sha256",a.source_manifest_sha256,"--shard",str(a.shard)],60)
        (work/"SOURCE_CHECK.json").write_bytes(raw);folder=work/"build-input";folder.mkdir();upstream={}
        for action,limit in(("fetch",60),("unpack",180),("read-build",180)):
            raw,value=command("build-"+action,ROOT/"scripts/reuse.py",
                [action,"--source",ROOT,"--work",folder,"--kind","build"],limit);upstream[action]=value
            if action=="read-build":(work/"BUILD_ADMISSION.json").write_bytes(raw)
        artifact=folder/"original/restored/run/artifact";runtime=work/"runtime";runtime.mkdir()
        import read_capture
        artifacts,bundle=read_capture.runtime_files(artifact);admitted={}
        for path in sorted(set(artifacts)|{"build/module.json"}):
            source=owned(artifact,path);target=runtime/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
            value=dict(**pin(source),mode=source.stat().st_mode&0o777)
            require(dict(**pin(target),mode=target.stat().st_mode&0o777)==value,"exact four-file native runtime copy");admitted[path]=value
        original_runtime=work/"original-runtime"
        raw,runtime_value=command("runtime-source",ROOT/"scripts/runtime.py",["--output",original_runtime],60)
        require(raw==owned(original_runtime,"RUNTIME.json").read_bytes(),"exact original runtime source record")
        admission=work/"admission";admission.mkdir()
        accepted=dict(status="FULL_ARCHIVE_ADMISSION_PASS",source=identity,runtime=admitted,
            original_runtime=pin(original_runtime/"RUNTIME.json"),build_binding=decode(owned(ROOT,"BUILD_INPUT.json").read_bytes()),
            build_proof=pin(work/"BUILD_ADMISSION.json"),new_compiler_calls=0,new_application_calls=0)
        (admission/"ADMISSION.json").write_bytes(canonical(accepted))
        stage="actual-groups";import capture
        application=capture.run(ROOT,runtime,original_runtime,work/"application",a.shard)
        raw,value=command("full-read",ROOT/"scripts/read_main.py",
            ["--source",ROOT,"--application",work/"application","--runtime",runtime,"--original-runtime",original_runtime,
                "--admission",admission/"ADMISSION.json"],180)
        (work/"READONLY.json").write_bytes(raw)
        require(value["status"]=="READONLY_PASS"and value["evidence"]["status"]=="PYTHON_JSON_BYTES_ACTUAL_COMPLETE_PASS",
            "all actual decoder bytes compare")
        physical=None
        if a.shard==0:
            stage="physical-controls";import controls
            physical=controls.create(ROOT,work/"application",runtime,original_runtime,admission/"ADMISSION.json",work/"controls",value["evidence"])
        require(source_evidence(ROOT)==identity,"source changed during actual qualification")
        result=dict(status="PASS",schema="hepta.runtime.python-json-bytes.actual-gate.v1",source=identity,shard=a.shard,
            source_check=checked,upstream=upstream,admission=accepted,original_runtime=runtime_value,application=application,
            actual=value["evidence"],controls=physical,processes=rec.records,new_compiler_calls=0,application_replays=0,
            new_original_calls=checked["new_original_calls"],new_native_calls=checked["new_native_calls"],whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(canonical(result))
        print(canonical(dict(status="PYTHON_JSON_BYTES_ACTUAL_AND_PHYSICAL_PASS",shard=a.shard,
            original_calls=result["new_original_calls"],native_calls=result["new_native_calls"],
            full_original_bytes=value["evidence"]["original_full_bytes"],full_native_buffer_bytes=value["evidence"]["native_full_buffer_bytes"],
            physical_refusals=8 if physical else 0,relocations=2 if physical else 0,application_replays=0)).decode(),end="")
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
