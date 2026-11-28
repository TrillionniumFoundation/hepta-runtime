"""Prepared fixed readers under full-byte, metadata and no-execution guard."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,read,require,loads
import read_capture,read_only_guard,reader_controls

def prepare():
    # Freeze every ordinary lazy standard-library import before the audit boundary.
    import ast,copy,ctypes,errno,gzip,hashlib,io,json,math,mmap,os,re,stat,struct,subprocess,tarfile,tomllib,zlib
    gzip.decompress(gzip.compress(b"preload",mtime=0))
    tomllib.loads("x=1")
    copy.deepcopy({"x":[1,2]})
    read_capture.source_check.check()
    return True

def run(capture,controls=None,foreign=None):
    require(prepare() is True,"all readers loaded before guard")
    roots=[capture,ROOT]+([] if controls is None else [controls])
    def operation():
        baseline=read_capture.verify(capture)
        if controls is not None:baseline=dict(baseline,controls=reader_controls.verify(capture,controls,baseline))
        return baseline
    if foreign is None:
        original=loads(read(capture/"CAPTURE.json"))["producer_root"]
        foreign=str(Path(original).parent/"not-admitted-producer/CAPTURE.json")
    return read_only_guard.guarded(operation,roots=roots,foreign_path=foreign)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--capture",type=Path,required=True);p.add_argument("--controls",type=Path);p.add_argument("--receipt",type=Path);p.add_argument("--foreign")
    a=p.parse_args();result=run(a.capture.resolve(strict=True),None if a.controls is None else a.controls.resolve(strict=True),a.foreign)
    if a.receipt:a.receipt.write_bytes(encoded(result))
    print(encoded(dict(status="GUARDED_PINNED_ANCHOR_READBACK_PASS",before_entries=len(result["before"]),probes=len(result["probes"]),evidence=result["evidence"])).decode(),end="")
