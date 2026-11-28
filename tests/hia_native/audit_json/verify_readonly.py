"""Preload fixed codec readers and then deny all execution and protected writes."""
from pathlib import Path
import argparse
import json
import sys
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0,str(ROOT))
import read_capture
import reader_controls
from common import require, source
from read_only_guard import guarded


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    parser.add_argument('--require-controls',action='store_true')
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    require(source() == args.source_manifest_sha256, 'explicit fixed reader source')
    proof = guarded(lambda:read_capture.verify(output,require_controls=args.require_controls),
                    roots=[ROOT,output],foreign_path=Path('/dev/null'))
    require(proof['before'] == proof['after'] and len(proof['probes']) == 12
            and proof['native_or_rust_executions'] == proof['reader_writes'] == 0, 'complete inert guarded read')
    print(json.dumps(proof,sort_keys=True,allow_nan=False))
