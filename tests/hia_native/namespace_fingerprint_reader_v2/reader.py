"""Complete source-bound pure reader with fixed full-tree/no-execution guard."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import reader_common as rc
def prepare(original):
    identity=rc.source()
    sys.path.insert(0,str(original))
    import common
    rc.check(common.ROOT==original and common.source()=="682909fbec91ce42d145ebe8ee55c6943d385f1113b9ad25f03d9c3f694bf320","exact complete frozen original producer source")
    import ast,bz2,copy,ctypes,errno,gzip,hashlib,io,json,lzma,math,mmap,os,re,stat,struct,subprocess,tarfile,tomllib,zlib
    import read_capture,read_only_guard
    gzip.decompress(gzip.compress(b"preload",mtime=0));bz2.decompress(bz2.compress(b"preload"));lzma.decompress(lzma.compress(b"preload"))
    tomllib.loads("x=1");copy.deepcopy({"x":[1,2]})
    read_capture.prepare()
    rc.check(rc.source()==identity,"complete reader source after preload")
    return identity,read_capture,read_only_guard
def verify(original,capture):
    identity,capture_reader,guard=prepare(original)
    def operation():
        rc.check(rc.source()==identity,"every admitted reader source byte within guard")
        result=capture_reader.verify(capture)
        return dict(reader_source_sha256=identity,original_source_sha256=result["source_manifest_sha256"],
                    complete_evidence=result,native_executions=0,rust_executions=0)
    return guard.guarded(operation,roots=[capture,original,ROOT],foreign_path=str(capture.parent/"not-admitted-producer/CAPTURE.json"))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--original-source",type=Path,required=True);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True);a=p.parse_args()
    result=verify(a.original_source.resolve(strict=True),a.capture.resolve(strict=True))
    a.receipt.write_bytes(rc.enc(result))
    print(rc.enc({k:v for k,v in result.items() if k not in ("before","after")}).decode(),end="")
