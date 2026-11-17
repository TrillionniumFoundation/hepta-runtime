#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Preserve complete successful or failed evidence and bound pure archive reads."""
from pathlib import Path
import argparse
import json
import sys
import time
import traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--restore",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(not a.output.exists(),"archive gate output must be fresh")
    a.output.mkdir(parents=True);out=a.output.resolve()
    rec=Recorder(ROOT,out/"driver");py=[sys.executable,"-I","-S","-B"]
    started=time.monotonic();status="FAIL";stage="export";failure=None
    try:
        raw,row=rec.run("complete-export",py+[ROOT/"scripts/export.py","--capture",a.capture.resolve(strict=True),
            "--archive",out/"evidence.tar.gz"],timeout=180)
        print(raw.decode(),end="",flush=True)
        require(decode(raw)["gate_status"]=="PASS","complete failed-stage archive retained")
        stage="archive-read"
        raw,row=rec.run("complete-archive-read",py+[ROOT/"scripts/archive_read.py","--archive",out/"evidence.tar.gz",
            "--output",a.restore.absolute(),"--proof-output",out/"initial-read",
            "--source-manifest-sha256",a.source_manifest_sha256],timeout=180)
        value=decode(raw);require(value["status"]=="PASS","complete archive read failed")
        print(json.dumps({k:value[k] for k in ("status","archive","logical_files","logical_bytes","unique_objects",
            "unique_bytes","retained_guard_probes","independent_guard_probes","native_or_rust_executions")},sort_keys=True),flush=True)
        status="PASS";stage="complete"
    except BaseException as error:
        failure=dict(error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        raise
    finally:
        (out/"ARCHIVE_GATE.json").write_bytes(canonical(dict(schema="hepta.runtime.binary-call-plan.archive-gate.v1",
            status=status,stage=stage,failure=failure,elapsed_seconds=time.monotonic()-started,
            source_manifest_sha256=a.source_manifest_sha256,processes=rec.records,native_or_rust_executions=0)))
if __name__=="__main__":main()
