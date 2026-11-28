#!/usr/bin/env python3
"""First native-only boundary execution against completed original profiles."""
import argparse,ast,shutil,sys,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence
from process import Recorder
import cases
def py(script,*args):return[sys.executable,"-I","-S","-B",script,*args]
def checked(group):
    identity=source_evidence(ROOT)
    for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    total=cases.total();domain=cases.domain(group)
    require(total["native_calls"]==1299 and total["new_original_calls"]==total["original_application_replays"]==0
        and len(total["groups"])==12,"complete frozen never-executed native boundary domain")
    return dict(status="JSON_VALUE_BOUNDARY_SOURCE_PASS",source=identity,domain=domain,total=total,application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"whole frozen boundary source")
    identity=source_evidence(ROOT);work=a.work.absolute()
    if a.stage=="check":print(canonical(checked(a.group)).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh whole boundary export");a.output.mkdir()
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",py(ROOT/"scripts/export.py","--capture",work,"--archive",a.output/"evidence.tar.gz"),timeout=180)
        value=decode(raw);(a.output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",archive=value,process=row)))
        print(canonical(value).decode(),end="");return
    require(not work.exists(),"fresh native-only boundary workspace");work.mkdir();rec=Recorder(ROOT,work/"processes");stage="source-check"
    origin=dict(source=str(ROOT),work=str(work),group=a.group,python=sys.executable)
    (work/"ORIGIN.json").write_bytes(canonical(origin))
    def command(name,script,args,limit):
        nonlocal stage
        stage=name;raw,row=rec.run(name,py(script,*args),timeout=limit);return raw,decode(raw)
    try:
        raw,source_check=command("source-check",ROOT/"scripts/driver.py",
            ["check","--work",work,"--group",a.group,"--source-manifest-sha256",a.source_manifest_sha256],60)
        (work/"SOURCE_CHECK.json").write_bytes(raw)
        build=work/"build-input";build.mkdir();upstream={}
        for action,limit in(("fetch",60),("unpack",180),("read-build",180)):
            raw,value=command("build-"+action,ROOT/"scripts/reuse.py",
                [action,"--source",ROOT,"--work",build,"--kind","build"],limit);upstream[action]=value
            if action=="read-build":(work/"BUILD_ADMISSION.json").write_bytes(raw)
        original=work/"profile-input";original.mkdir();profiles={}
        for action,limit in(("fetch",60),("unpack",180),("read",180)):
            raw,value=command("profile-"+action,ROOT/"scripts/original_input.py",
                [action,"--source",ROOT,"--work",original,"--group",a.group],limit);profiles[action]=value
            if action=="read":(work/"PROFILE_ADMISSION.json").write_bytes(raw)
        artifact=build/"original/restored/run/artifact";runtime=work/"runtime";runtime.mkdir()
        import read_boundary
        files,bundle=read_boundary.runtime_files(artifact);admitted={}
        for path in sorted(set(files)|{"build/module.json"}):
            source=owned(artifact,path);target=runtime/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
            value=dict(**pin(source),mode=source.stat().st_mode&0o777)
            require(dict(**pin(target),mode=target.stat().st_mode&0o777)==value,"whole copied admitted native runtime")
            admitted[path]=value
        admission=work/"admission";admission.mkdir()
        for name in("ORIGIN.json","BUILD_ADMISSION.json","PROFILE_ADMISSION.json"):
            shutil.copy2(work/name,admission/name);require(pin(work/name)==pin(admission/name),"full immutable boundary admission file")
        accepted=dict(source=identity,domain=cases.domain(a.group),runtime=admitted,build_proof=pin(admission/"BUILD_ADMISSION.json"),
            profile_proof=pin(admission/"PROFILE_ADMISSION.json"),new_original_calls=0)
        (admission/"ADMISSION.json").write_bytes(canonical(accepted))
        raw,native=command("native",ROOT/"scripts/native_capture.py",["--group",a.group,"--capture",runtime,"--output",work/"native"],60)
        require(native["status"]=="PASS"and native["cases"]==accepted["domain"]["native_calls"],"every fresh native boundary call finished")
        shutil.copytree(work/"processes",admission/"processes",copy_function=shutil.copy2)
        for path in(work/"processes").iterdir():
            require(path.read_bytes()==(admission/"processes"/path.name).read_bytes()
                and path.stat().st_mode&0o777==(admission/"processes"/path.name).stat().st_mode&0o777,
                "complete immutable pre-read process records")
        raw,value=command("full-read",ROOT/"scripts/read_main.py",["--source",ROOT,"--work",work,"--group",a.group],180)
        require(value["status"]=="READONLY_PASS"and value["evidence"]["status"]=="COMPLETE_PYTHON_JSON_VALUE_C_BOUNDARY_PASS",
            "all actual native C-depth bytes compare")
        (work/"READONLY.json").write_bytes(raw)
        result=dict(schema="hepta.runtime.python-json-value.boundary-gate.v1",status="PASS",group=a.group,source=identity,
            source_check=source_check,upstream=upstream,profiles=profiles,admission=accepted,native=native,
            comparison=value["evidence"],processes=rec.records,native_calls=native["cases"],new_original_calls=0,
            application_replays=0,new_compiler_calls=0)
        (work/"GATE.json").write_bytes(canonical(result));require(source_evidence(ROOT)==identity,"frozen boundary source unchanged")
        print(canonical(dict(status="PYTHON_JSON_VALUE_BOUNDARY_CAPTURE_PASS",group=a.group,native_calls=native["cases"],
            returned=value["evidence"]["returned"],raised=value["evidence"]["raised"],
            full_native_buffer_bytes=value["evidence"]["full_native_buffer_bytes"],
            original_records_read=value["evidence"]["original_records_read"],new_original_calls=0,application_replays=0,
            guard_probes=len(value["probes"]),entries=value["entries"])).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="UNKNOWN"if rec.records and rec.records[-1]["timed_out"]else"FAIL",
            source=identity,group=a.group,stage=stage,error_type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),processes=rec.records,new_original_calls=0,application_replays=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
