"""Freeze one declared lane, restore exact artifacts, and execute only its new pair."""
from pathlib import Path
import argparse,json,os,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import callable_common,read_capture,read_only_guard as guard,wait_domain
from capture_common import file_pin
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
def invoke(output,label,argv,*,limit):
    started=time.monotonic();record={"command":argv,"label":label,"application_lane_seconds":limit,"new_outer_timeout":False,"application_executions":label in ("original","native")}
    with (output/(label+".stdout")).open("xb") as stdout,(output/(label+".stderr")).open("xb") as stderr:
        try:
            p=subprocess.run(argv,stdout=stdout,stderr=stderr)
            record.update(exit_code=p.returncode,timed_out=False)
        except subprocess.TimeoutExpired:
            record.update(exit_code=None,timed_out=True);raise
        finally:
            record.update(elapsed_seconds=time.monotonic()-started,stdout=file_pin(output/(label+".stdout")),stderr=file_pin(output/(label+".stderr")))
            put(output/(label+".process.json"),record)
    if p.returncode:raise RuntimeError("actual "+label+" failed; complete prefix retained")
    return record
def main():
    p=argparse.ArgumentParser()
    for name in ("output","inputs"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--domain",choices=[g+"-"+e for g in ("ordinary-a","ordinary-b","eof") for e in ("legacy","modern")],required=True)
    a=p.parse_args();out=a.output.absolute()
    assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists()
    out.mkdir(parents=True);source=callable_common.syntax(HERE)
    binaries=json.loads((a.inputs/"BINARIES.json").read_bytes());assert binaries["status"]=="EXACT_ALREADY_BUILT_INPUTS_READY"
    put(out/"INPUTS_READY.json",binaries);put(out/"SOURCE.json",source)
    for name in ("NATIVE_DEPENDENCY_READONLY.json","FIXTURE_ARCHIVE_READ.json","ORIGINAL_ARCHIVE_READ.json","ORIGINAL_READER_PROCESS.json","original-reader.stdout","original-reader.stderr"):
        (out/name).write_bytes((a.inputs/name).read_bytes())
    work=Path("/tmp")/("hia-extract-contention-"+a.domain)/"work"
    put(out/"FROZEN_DOMAIN.json",wait_domain.domain(a.domain,work))
    status={"status":"RUNNING","domain":a.domain,"public_wait_only_new_domain":True,"old_domains_replayed":False,"production_installed":False,"full_runtime":False,"full_sdk":False}
    put(out/"RUN.json",status)
    try:
        for side in ("original","native"):
            invoke(out,side,[sys.executable,"-I","-S","-B",str(HERE/"capture.py"),"--binary",binaries[side]["path"],"--output",str(out/side),"--work",str(work),"--domain",a.domain,"--side",side],limit=180)
        def read():
            pair=[read_capture.read(out/side,side,{k:binaries[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
            return read_capture.compare(*pair)
        proof=guard.guarded(read,roots=[out,HERE],foreign_path=Path("/dev/null"))
        put(out/"READ_ONLY.json",proof);put(out/"QUALIFICATION.json",proof["evidence"])
        status.update(status="NEW_ACTUAL_CONTENTION_PAIR_PASS",cases=4,independent_readers_require_complete_archive=True)
    except BaseException as error:
        status.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:put(out/"RUN.json",status)
    print(json.dumps(status,sort_keys=True))
if __name__=="__main__":main()
