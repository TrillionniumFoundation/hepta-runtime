"""Preload and invert the exact single-node reader transform; never execute semantics."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc,read_adapter
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--complete",type=Path,required=True);a=p.parse_args()
    prepared=read_adapter.prepare(a.complete.resolve(strict=True))
    print(rc.enc(dict(status="EXACT_PURE_READER_TRANSFORM_PASS",source_manifest_sha256=prepared["identity"],
                     original_source_sha256=prepared["old_identity"],transform=prepared["transform"],
                     partitions=[list(x) for x in prepared["partitions"]],native_or_rust_executions=0)).decode(),end="")
