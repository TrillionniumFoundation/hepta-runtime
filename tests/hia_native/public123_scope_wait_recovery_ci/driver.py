"""Two independently bounded pure-reader processes; no application execution."""
from pathlib import Path
import argparse,hashlib,json,os,signal,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def pin(path):
    with path.open("rb") as stream:return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def run(out,name,args):
    argv=[sys.executable,"-I","-S","-B",*map(str,args)]
    started=time.monotonic();record={"argv":argv,"deadline_seconds":180,"application_executions":0,"timed_out":False,"kill_requested":False}
    with (out/(name+".stdout")).open("xb") as stdout,(out/(name+".stderr")).open("xb") as stderr:
        child=subprocess.Popen(argv,stdout=stdout,stderr=stderr,cwd=out,start_new_session=True)
        record["pid"]=child.pid
        try:record["exit_code"]=child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            record["timed_out"]=record["kill_requested"]=True
            os.killpg(child.pid,signal.SIGKILL);record["exit_code"]=child.wait(timeout=5)
        finally:
            record["elapsed_seconds"]=time.monotonic()-started
            record["stdout"]=pin(out/(name+".stdout"));record["stderr"]=pin(out/(name+".stderr"))
            put(out/(name+".process.json"),record)
    print("PURE_PROCESS",json.dumps(record,sort_keys=True),flush=True)
    sys.stdout.buffer.write((out/(name+".stdout")).read_bytes());sys.stdout.buffer.flush()
    sys.stderr.buffer.write((out/(name+".stderr")).read_bytes());sys.stderr.buffer.flush()
    assert not record["timed_out"] and record["exit_code"]==0,"bounded pure reader failed; all captured inputs retained"
def main():
    p=argparse.ArgumentParser()
    for k in ("capture-source","native-source","output"):p.add_argument("--"+k,type=Path,required=True)
    p.add_argument("--domain",required=True);p.add_argument("--role",choices=("complete","semantic"),required=True);a=p.parse_args()
    out=a.output.absolute();assert not out.exists();out.mkdir(parents=True)
    os.environ["WAIT_SOURCE"]=str(a.capture_source.resolve(strict=True))
    run(out,"recover",[HERE/"recover.py","--capture-source",a.capture_source,"--native-source",a.native_source,"--output",out/"pair","--domain",a.domain])
    name="controls" if a.role=="complete" else "semantic_controls"
    run(out,name,[HERE/(name+".py"),"--capture",out/"pair/retained/capture","--output",out/name])
    result={"status":"COMPLETE_RETAINED_WAIT_READER_GATE_PASS","domain":a.domain,"role":a.role,"original_executions":0,"native_executions":0,
        "source":"320862f03902153b5c804d1b68142126a9c7a606","independent_uploaded_read_required":True}
    put(out/"RESULT.json",result);print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
