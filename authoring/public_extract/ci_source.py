"""Run only source authoring and mechanical assembly with fixed retained limits."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True

def dump(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def pin(path):
    with path.open("rb") as stream:
        return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}

def process(root,name,command,timeout):
    folder=root/"processes";folder.mkdir(exist_ok=True)
    started=time.monotonic()
    row={"name":name,"command":[str(x) for x in command],"timeout_seconds":timeout,
         "timed_out":False,"exit_code":None,"status":"RUNNING"}
    dump(folder/(name+".json"),row)
    child=None
    try:
        with (folder/(name+".stdout")).open("xb") as out,(folder/(name+".stderr")).open("xb") as err:
            child=subprocess.Popen(row["command"],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            try:row["exit_code"]=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["timed_out"]=True
                os.killpg(child.pid,signal.SIGKILL)
                row["exit_code"]=child.wait()
                raise
        assert row["exit_code"]==0,row
        row["status"]="PASS"
    except BaseException as exc:
        row.update(status="FAIL",error=repr(exc));raise
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        row["elapsed_seconds"]=time.monotonic()-started
        for stream in ("stdout","stderr"):
            path=folder/(name+"."+stream)
            if path.exists():row[stream]=pin(path)
        dump(folder/(name+".json"),row)
    return row

def main():
    p=argparse.ArgumentParser()
    for name in ("baseline","hepta","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--author-profile-sha256",required=True)
    a=p.parse_args()
    author=Path(__file__).resolve().parent
    a.output.mkdir(parents=True,exist_ok=False)
    status={"schema":"hepta.runtime.public-extract-source-ci.v1","status":"RUNNING",
        "native_semantic_executions":0,"rust_executions":0,"source_only":True,"processes":[]}
    try:
        status["processes"].append(process(a.output,"source-author",
            [sys.executable,"-I","-B",author/"author.py","--baseline",a.baseline,
             "--hepta",a.hepta,"--output",a.output/"generated",
             "--author-profile-sha256",a.author_profile_sha256],180))
        graph=a.output/"generated/source"
        sys.path.insert(0,str(graph/"scripts"))
        import public_nine_build
        checked=public_nine_build.source_check(graph)
        assert len(public_nine_build.MEMBERS)==110 and len(public_nine_build.EXTRA)==64
        assert public_nine_build.EXTRA[59:]==["extract_gateway","extract_params","extract_call","extract_adapter",None]
        for label,fixture in (("stdio",False),("fixture",True)):
            source=public_nine_build.adapter_source(graph,private_fixture=fixture)
            path=a.output/(label+".S");path.write_text(source)
            status["processes"].append(process(a.output,"assemble-"+label,
                ["as","--64","-o",a.output/(label+".o"),path],60))
        assert public_nine_build.source_check(graph)==checked
        status.update(status="SOURCE_ASSEMBLY_PASS",source_binding_sha256=checked["manifest_sha256"],
            complete_source_files=len(checked["files"])+1,public_handler_qualified=False,
            full_sdk_qualified=False,whole_runtime_replaced=False)
    except BaseException as exc:
        status.update(status="FAIL",error=repr(exc));raise
    finally:
        dump(a.output/"SOURCE_CI.json",status)
    print(json.dumps(status,sort_keys=True))

if __name__=="__main__":main()
