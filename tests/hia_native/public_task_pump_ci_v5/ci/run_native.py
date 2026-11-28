"""Execute the unchanged serial1394 corpus only after this CI's full graph admission."""
from pathlib import Path
import argparse
import json
import os
import sys
import traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import command, put, require
from source_check import source
import read_all
import read_build
import build_controls

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("package","build","original","build-archive-receipt","original-archive-receipt","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    require(os.environ.get("GITHUB_ACTIONS")=="true","this fresh composition recipe is CI-only")
    package=a.package.resolve(strict=True)
    build=a.build.resolve(strict=True)
    original=a.original.resolve(strict=True)
    out=a.output.resolve()
    require(not out.exists(),"native capture already exists")
    admitted=source(package,a.manifest_sha256,syntax=True)
    out.mkdir(parents=True)
    origin={"schema":"hepta.runtime.task-pump-public-ci.v1",
        "package":str(package),"build":str(build),"original":str(original),"output":str(out),
        "python":sys.executable,"pid":os.getpid(),"manifest_sha256":a.manifest_sha256,
        "source_admission":admitted,"git_head":os.environ.get("GITHUB_SHA"),
        "run_id":os.environ.get("GITHUB_RUN_ID"),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),
        "records":1394,"tool_cases":1366,"process_deadline_seconds":180,"exchange_deadline_seconds":60,
        "workflow_job_limit_minutes":15,"async_qualification":False,"whole_sdk_qualification":False}
    put(out/"NATIVE_ORIGIN.json",origin)
    dependencies={"build":json.loads(a.build_archive_receipt.read_bytes()),
                  "original":json.loads(a.original_archive_receipt.read_bytes())}
    put(out/"DEPENDENCIES.json",dependencies)
    stage="source-and-build-admission"
    try:
        for label,root in (("build",build),("original",original)):
            row=dependencies[label]
            require(row["label"]==label and row["source_manifest_sha256"]==a.manifest_sha256,
                    "fresh dependency source differs")
            require(all(type(row[k]) is str and row[k] and row[k]==origin[k]
                        for k in ("git_head","run_id","run_attempt")),"dependency CI attempt differs")
            read_all.inventory(root,row["manifest"])
            require(source(root/"ci-package",a.manifest_sha256)==admitted,
                    "complete dependency source snapshot differs")
        wire,prepared=read_all.prepare(package)
        graph=read_build.verify_build(package,build,a.manifest_sha256)
        build_controls.verify_controls(package,build,a.manifest_sha256)
        journal=graph["entries"]["journal"]["elf"]
        expected_binary={key:journal[key] for key in ("bytes","sha256")}
        py=[sys.executable,"-I","-S","-B"]
        stage="observer-process-controls"
        command(out,"observer-controls",py+[str(package/"wire/observer_process_controls.py"),
            "--output",str(out/"observer-controls")])
        preflight=wire.guarded(lambda:prepared["controls"].verify_observer_process_controls(
            out/"observer-controls",prepared=prepared),
            roots=[package,out/"observer-controls"],prepared=prepared)
        put(out/"observer-preflight-readonly.json",preflight)
        stage="complete-native-serial1394"
        command(out,"native1394",py+[str(package/"wire/observe_native.py"),
            "--native",journal["path"],"--binary-sha256",expected_binary["sha256"],
            "--output",str(out/"public")])
        stage="complete-wire-and-journal-admission"
        joined=wire.verify(out/"public",original,expected_binary=expected_binary,prepared=prepared)
        stage="physical-public-reader-controls"
        prepared["controls"].create(out/"public",original,joined,out/"public-reader-controls",prepared=prepared)
        stage="complete-read-only-join"
        result=read_all.guarded_verify(package,build,original,out,a.manifest_sha256,
            prepared_pair=(wire,prepared))
    except BaseException as error:
        put(out/"FAILURE.json",{"status":"FAIL","stage":stage,
            "failure":{"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()},
            "all_requested_records":1394,"deadline_relaxed":False,"qualification":False})
        raise
    # The complete outer report is written only to the caller-owned stdout,
    # outside every protected capture/source root, after the guard has returned.
    print(json.dumps(result,sort_keys=True,allow_nan=False))

if __name__=="__main__":
    main()
