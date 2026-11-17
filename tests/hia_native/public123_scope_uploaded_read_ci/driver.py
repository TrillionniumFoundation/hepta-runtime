"""One unchanged 180-second pure archive-reader budget."""
from pathlib import Path
import argparse,json,os,signal,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from archive_input import pin,put,require
def main():
    p=argparse.ArgumentParser();p.add_argument("--name",required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    out=a.output.absolute();require(not out.exists(),"fresh independent driver");out.mkdir(parents=True)
    argv=[sys.executable,"-I","-S","-B",str(HERE/"read_uploaded.py"),"--name",a.name,"--output",str(out/"read")]
    record={"argv":argv,"deadline_seconds":180,"application_executions":0,"timed_out":False,"kill_requested":False}
    started=time.monotonic()
    with (out/"reader.stdin").open("xb") as inp:inp.write(b"")
    with (out/"reader.stdin").open("rb") as inp,(out/"reader.stdout").open("xb") as stdout,(out/"reader.stderr").open("xb") as stderr:
        child=subprocess.Popen(argv,stdin=inp,stdout=stdout,stderr=stderr,cwd=out,start_new_session=True);record["pid"]=child.pid
        try:record["exit_code"]=child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            record["timed_out"]=record["kill_requested"]=True;os.killpg(child.pid,signal.SIGKILL);record["exit_code"]=child.wait(timeout=5)
    record["elapsed_seconds"]=time.monotonic()-started
    for suffix in ("stdin","stdout","stderr"):record[suffix]=pin(out/("reader."+suffix))
    put(out/"PROCESS.json",record)
    print("PURE_PROCESS "+json.dumps(record,sort_keys=True),flush=True)
    sys.stdout.buffer.write((out/"reader.stdout").read_bytes());sys.stdout.buffer.flush()
    sys.stderr.buffer.write((out/"reader.stderr").read_bytes());sys.stderr.buffer.flush()
    require(record["exit_code"]==0 and not record["timed_out"],"bounded independent full reader failed; all evidence retained")
if __name__=="__main__":main()
