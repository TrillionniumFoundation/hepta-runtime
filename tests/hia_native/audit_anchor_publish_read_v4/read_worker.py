"""One complete fixed pure-verifier partition, no native or Rust replay."""
from pathlib import Path
import argparse,os,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc,read_adapter

def summary(proof,raw):
    e=proof["evidence"]
    return dict(status=e["status"],part=e["part"],checked_names=e["checked_names"],proof=rc.pin(raw),
                pid=proof["pid"],parent_pid=proof["ppid"],pgid=proof["pgid"],guard_probes=len(proof["probes"]),
                native_or_rust_executions=0,reader_writes=0)

def run(complete,output,part):
    parent_file=output.parent.parent/"admission/PARENT.json";parent=rc.loads(rc.read(parent_file))
    rc.check(parent["pid"]==os.getppid() and parent["pgid"]==os.getpgrp() and
             type(parent["deadline_ns"]) is int and time.monotonic_ns()<parent["deadline_ns"],
             "actual same-group owned parent before preparation")
    prepared=read_adapter.prepare(complete)
    proof=read_adapter.verify_partition(prepared,part,parent_file)
    raw=rc.enc(proof);(output/"READBACK.json").write_bytes(raw)
    rc.check(time.monotonic_ns()<parent["deadline_ns"],"complete proof within unchanged whole-parent deadline")
    print(rc.enc(summary(proof,raw)).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--complete",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--part",type=int,required=True);a=p.parse_args();run(a.complete.resolve(strict=True),a.output.resolve(strict=True),a.part)
