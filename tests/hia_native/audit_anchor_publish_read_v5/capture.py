"""Run exactly two pure verification workers under one unchanged 180-second parent."""
from pathlib import Path
import argparse,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc,read_adapter,owned_readers,read_join

def run(complete,output):
    started=time.monotonic_ns();identity=rc.source();prepared=read_adapter.prepare(complete)
    output.mkdir(parents=True,exist_ok=False)
    parent,records=owned_readers.run(complete,output,identity,started,prepared["partitions"])
    result=read_join.verify(complete,output,prepared)
    rc.check(time.monotonic_ns()<parent["deadline_ns"] and rc.source()==identity,"complete join within original whole-parent budget")
    (output/"QUALIFICATION.json").write_bytes(rc.enc(result))
    print(rc.enc(result).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--complete",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.complete.resolve(strict=True),a.output.absolute())
