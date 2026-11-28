#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bound complete recovery export and retain its full process streams."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import recover
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();binding,original=recover.frozen(a.source_manifest_sha256)
    recover.require(not a.output.exists(),"recovery export output must be fresh")
    a.output.mkdir(parents=True);out=a.output.resolve();a.work.mkdir(parents=True,exist_ok=True)
    rec=Recorder(ROOT,out/"processes")
    try:
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",a.work.resolve(strict=True),"--archive",out/"evidence.tar.gz"],timeout=180)
        result=recover.decode(raw)
        (out/"EXPORT.json").write_bytes(recover.encode(dict(status="PASS",archive=result,
            process=row,source_manifest_sha256=binding,native_or_rust_executions=0)))
        print(json.dumps(result,sort_keys=True))
    except BaseException:
        if rec.records:print((rec.directory/"complete-export.stderr").read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
