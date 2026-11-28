#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify or materialize the complete previous public source closure."""
import argparse
import json
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/'scripts'))
    from public_io_build import verify_base,PUBLIC_BASE_BINDING
    paths,binding=verify_base(root)
    if args.output is not None:
        out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
        for name,source in {**paths,'native/runtime_mcp_sources.json':binding}.items():
            target=out/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source.read_bytes())
        materialized=True
    else:materialized=False
    print(json.dumps({'schema':'hepta.runtime.public-binary-write.previous-source-inverse.v1',
        'passed':True,'files':len(paths),'binding':PUBLIC_BASE_BINDING,
        'materialized':materialized,'new_graph_qualified':False},sort_keys=True))


if __name__=='__main__':main()
