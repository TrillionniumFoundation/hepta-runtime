#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the finite nine-tool domain on this build's actual native executable."""
from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(Path(__file__).with_name('public_lifecycle'))]
from hia_native_public_lifecycle_qualification import verify_build
from public_lifecycle_registry import require
from lifecycle_suite import execute

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();before=verify_build(ROOT,args.build)
    result=execute(args.build.parent/before['executable'],args.output)
    require(verify_build(ROOT,args.build)==before,'native build changed during finite lifecycle cases')
    print(json.dumps(result,sort_keys=True))
