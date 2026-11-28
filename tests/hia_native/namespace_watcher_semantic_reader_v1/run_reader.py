"""Owned pure-reader process under its unchanged complete 180-second deadline."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from reader_common import source,read,encoded,require
from process import Recorder
def run(bundle,output):
    identity=source();output.mkdir(parents=True,exist_ok=False)
    recorder=Recorder(ROOT,output/"processes")
    try:
        raw,row=recorder.run("semantic-reader",[sys.executable,"-I","-B",ROOT/"qualify.py",
            "--bundle",bundle,"--output",output/"GUARDED.json"],timeout=180)
    except BaseException:
        if recorder.records:sys.stderr.buffer.write(read(output/"processes/semantic-reader.stderr"))
        raise
    require(source()==identity,"whole pure-reader source remains frozen")
    print(raw.decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--bundle",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.bundle.resolve(strict=True),a.output.absolute())
