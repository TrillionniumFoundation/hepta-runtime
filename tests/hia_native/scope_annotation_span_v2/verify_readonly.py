"""Preload fixed readers, then prohibit execution and every protected write."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0,str(ROOT))
# Fixed metadata modules are imported before admission. Their definitions do
# not construct or execute any native owner, Rust process or compiler.
import qualify
import read_capture
import original_reader
import extract_reference
import controls
import cases
import evidence_controls
import original_evidence_controls
from read_only_guard import guarded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--source-manifest-sha256",required=True)
    parser.add_argument("--native-only",action="store_true")
    parser.add_argument("--require-evidence-controls",action="store_true")
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    assert hashlib.sha256((ROOT/"SOURCE_MANIFEST.json").read_bytes()).hexdigest() == args.source_manifest_sha256
    result = guarded(lambda:qualify.verify(output,full=not args.native_only,require_controls=args.require_evidence_controls),
                     roots=[ROOT,output],foreign_path=Path("/dev/null"))
    assert len(result["probes"]) == 12 and result["before"] == result["after"]
    assert result["native_or_rust_executions"] == result["reader_writes"] == 0
    print(json.dumps(result,sort_keys=True))


if __name__ == "__main__":
    main()
