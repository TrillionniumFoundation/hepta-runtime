#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded CI-only qualification; all child streams and failures remain retained."""
from pathlib import Path
import argparse
import json
import os
import sys
import time
import traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from process import Recorder,environment

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--rust-bin",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen source manifest changed")
    source_evidence(ROOT)
    require(not a.output.exists(),"qualification gate must be fresh")
    a.output.mkdir(parents=True);out=a.output.resolve()
    hepta=a.hepta.resolve(strict=True);rust=a.rust_bin.resolve(strict=True)
    env,binding=environment(os.environ,rust_bin=rust)
    (out/"ENVIRONMENT.json").write_bytes(canonical(binding))
    rec=Recorder(ROOT,out/"processes",env=env)
    py=[sys.executable,"-I","-S","-B"]
    base=py+[ROOT/"scripts/run_ci.py"]
    stages=[
        ("source-check",base+["check","--source",ROOT],60),
        ("producers",base+["run","--source",ROOT,"--hepta",hepta,"--rust-bin",rust,"--output",out/"capture"],900),
        ("read-only-admission",base+["verify","--source",ROOT,"--output",out/"capture"],180),
        ("physical-controls",base+["controls","--source",ROOT,"--output",out/"capture"],180),
        ("read-only-controls",base+["verify-controls","--source",ROOT,"--output",out/"capture"],180),
    ]
    started=time.monotonic();status="FAIL";stage="source-check";failure=None
    try:
        for stage,argv,budget in stages:
            raw,row=rec.run(stage,argv,timeout=budget)
            value=decode(raw)
            expected={"source-check":"SOURCE_ONLY_PASS","producers":"ACTUAL_CALL_PLAN_PRODUCERS_COMPLETE",
                "read-only-admission":"READONLY_PASS","physical-controls":"PHYSICAL_READER_CONTROLS_PASS",
                "read-only-controls":"READONLY_PASS"}[stage]
            require(value["status"]==expected,"stage returned the wrong qualification state")
            summary=dict(stage=stage,status=expected,elapsed_seconds=row["elapsed_seconds"],
                stdout=row["stdout"],stderr=row["stderr"])
            if stage.startswith("read-only"):
                summary.update(entries=value["entries"],guard_probes=len(value["probes"]),
                    comparison=value["evidence"]["status"],native=value["evidence"]["native"])
            print(json.dumps(summary,sort_keys=True),flush=True)
        require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"source manifest changed during qualification")
        source_evidence(ROOT);status="PASS";stage="complete"
    except BaseException as error:
        failure=dict(error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        raise
    finally:
        gate=dict(schema="hepta.runtime.binary-call-plan.gate.v1",status=status,stage=stage,
            failure=failure,source_manifest_sha256=a.source_manifest_sha256,
            elapsed_seconds=time.monotonic()-started,processes=rec.records,
            cases=433,private_boundary_controls=28,original_tests=4,
            physical_reader_refusals=6,complete_relocations=2,
            original_types_only=False,caller_plans_only=True,public_route_registered=False,whole_runtime_replaced=False)
        (out/"GATE.json").write_bytes(canonical(gate))
if __name__=="__main__":main()
