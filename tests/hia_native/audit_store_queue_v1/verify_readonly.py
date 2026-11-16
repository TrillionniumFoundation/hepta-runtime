"""Preload fixed readers, then forbid execution and every protected write."""
from pathlib import Path
import argparse,hashlib,json,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import read_capture,reader_controls,original,projection
from read_only_guard import guarded
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--require-controls",action="store_true")
    a=p.parse_args();output=a.output.resolve(strict=True)
    assert hashlib.sha256((ROOT/"SOURCE_MANIFEST.json").read_bytes()).hexdigest()==a.source_manifest_sha256
    proof=guarded(lambda:read_capture.verify(output,require_controls=a.require_controls),
        roots=[ROOT,output],foreign_path=Path("/dev/null"))
    assert proof["before"]==proof["after"] and len(proof["probes"])==12
    assert proof["native_or_rust_executions"]==proof["reader_writes"]==0
    print(json.dumps(proof,sort_keys=True))
if __name__=="__main__":main()
