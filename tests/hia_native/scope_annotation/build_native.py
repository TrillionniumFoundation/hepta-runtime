"""Owned build process; compiler authoring heaps retire before semantic calls."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime",type=Path,required=True)
    parser.add_argument("--hepta",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--bootstrap",type=Path)
    args=parser.parse_args();root=args.runtime.resolve(strict=True)
    sys.path.insert(0,str(root/"scripts"))
    from hia_native_scope_annotation_build import build_scope_annotation,verify_build
    manifest=build_scope_annotation(args.hepta,args.output,source_root=root,bootstrap=args.bootstrap)
    checked=verify_build(manifest,source_root=root)
    print(json.dumps(dict(schema="hepta.scope-annotation.actual-build-process.v1",manifest=str(manifest),
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),modules=len(checked["modules"])),sort_keys=True))

if __name__=="__main__":main()
