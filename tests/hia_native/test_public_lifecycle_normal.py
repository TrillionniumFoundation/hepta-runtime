#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete normal-wire corpus and live audit/retention consistency checks."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts'), str(Path(__file__).with_name('public_lifecycle'))]
from hia_native_public_lifecycle_qualification import verify_build
from normal_runner import execute

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    built=verify_build(ROOT,args.build)
    result=execute(args.build.parent/built['executable'],args.output)
    report=json.loads(result.read_bytes())
    print(json.dumps({k:report[k] for k in ('status','native_processes','native_requests','original_processes')},sort_keys=True))
