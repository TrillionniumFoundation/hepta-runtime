"""Read-only full-tree join of the retained actual parallel verifier processes."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc,read_adapter,read_join

def verify(complete,output):
    prepared=read_adapter.prepare(complete)
    def operation():
        result=read_join.verify(complete,output/"read",prepared)
        rc.check(result==rc.loads(rc.read(output/"read/QUALIFICATION.json")),"complete parallel result exactly reproducible")
        process=read_join.custody(output,result)
        return dict(status="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_PARALLEL_READ_PASS",qualification=result,process=process,
                    source_manifest_sha256=rc.source(),native_or_rust_executions=0,reader_writes=0,
                    namespace_version_qualified=False,archive_store_qualified=False,hot_cache_qualified=False,
                    begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    return prepared["old"]["guard"].guarded(operation,roots=[complete,ROOT,output],
                foreign_path="/original-producer-not-admitted/CAPTURE.json")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--complete",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();output=a.output.resolve(strict=True);result=verify(a.complete.resolve(strict=True),output)
    (output/"READBACK.json").write_bytes(rc.enc(result))
    print(rc.enc({k:v for k,v in result.items() if k not in ("before","after")}).decode(),end="")
