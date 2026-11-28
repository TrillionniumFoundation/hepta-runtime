#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time
def pin(p):
    p=Path(p)
    with p.open("rb") as f:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);source=Path(__file__).with_name("probe_platform.py")
    argv=[sys.executable,"-I","-S","-B",str(source),"--output",str(a.output/"capture")]
    start=time.monotonic();proc=None;record=dict(argv=argv,timeout_seconds=60,timed_out=False)
    with (a.output/"probe.stdout").open("xb") as out,(a.output/"probe.stderr").open("xb") as err:
        try:
            proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            record.update(pid=proc.pid,pgid=os.getpgid(proc.pid));proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            record["timed_out"]=True;os.killpg(proc.pid,9);proc.wait()
        finally:
            record.update(exit_code=proc.returncode if proc else None,elapsed_seconds=time.monotonic()-start,
                source=pin(source),stdout=pin(a.output/"probe.stdout"),stderr=pin(a.output/"probe.stderr"))
            (a.output/"PROCESS.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
    if record["exit_code"]!=0 or record["timed_out"] or record["stderr"]["bytes"]:raise ValueError("platform survey process failed")
    value=json.loads((a.output/"capture/SURVEY.json").read_bytes())
    if json.loads((a.output/"probe.stdout").read_bytes())!=value:raise ValueError("complete stdout differs")
    summary=dict(status="ACTUAL_INPUT_PLATFORM_SURVEY_COMPLETE",process=record,
        platform={k:value[k]for k in("python","machine","kernel","uid","gid","groups","capabilities")},
        filesystems=[dict(label=x["label"],families=[dict(name=f["name"],status=f["status"],events=len(f["events"]),attributes=len(f.get("attributes",[])),last_event=f["events"][-1] if f["events"] else None)for f in x["families"]])for x in value["filesystems"]],
        preexisting_readonly=value["preexisting_readonly"],metadata_function_calls=0,hia_calls=0,rust_calls=0)
    print(json.dumps(summary,sort_keys=True,ensure_ascii=True))
if __name__=="__main__":main()
