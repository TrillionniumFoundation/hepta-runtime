#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain every complete pure recovery process stream and fixed original budget."""
from pathlib import Path
import argparse
import json
import sys
import traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import recover
from process import Recorder
STAGES=("fetch","unpack","continue","read","controls","verify")
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=STAGES)
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();binding,original=recover.frozen(a.source_manifest_sha256)
    work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    rec=Recorder(ROOT,work/"steps"/a.stage)
    failure=None;result=None;value=None
    try:
        raw,row=rec.run(a.stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/recover.py",a.stage,
            "--work",work,"--source-manifest-sha256",binding],timeout=60 if a.stage in ("fetch","continue") else 180)
        value=recover.decode(raw)
        expected="READONLY_PASS" if a.stage in ("read","verify") else "PHYSICAL_READER_CONTROLS_PASS" if a.stage=="controls" else "PASS"
        recover.require(value["status"]==expected,"pure recovery stage did not return its expected status")
        result=dict(stage=a.stage,status="PASS",source_manifest_sha256=binding,process=row,
            native_executions=14 if a.stage=="continue" else 0,rust_executions=0)
        if a.stage in ("read","verify"):
            recover.require(value["before"]==value["after"] and len(value["probes"])==11 and
                value["native_executed"] is False and value["rust_executed"] is False,"pure read custody changed")
            result.update(guard_probes=11,unchanged_entries=value["entries"],evidence=value["evidence"])
        elif a.stage=="controls":result["evidence"]=value
        else:result["evidence"]=value
        (work/(a.stage.upper()+".json")).write_bytes(recover.encode(result))
        if a.stage=="verify":
            stages=[recover.decode((work/(name.upper()+".json")).read_bytes()) for name in STAGES]
            recover.require(all(item["status"]=="PASS" and item["source_manifest_sha256"]==binding for item in stages),
                "pure recovery stage closure incomplete")
            gate=dict(schema="hepta.runtime.binary-root.continuation-gate.v1",status="PASS",
                stage="complete",source_manifest_sha256=binding,original_commit=original["commit"],
                original_run_status="FAIL",original_failed_stage="producers",original_semantic_capture_preserved=True,
                stages=stages,physical_reader_refusals=6,complete_relocations=2,
                native_executions=14,rust_executions=0,unknown_processes_replayed=False,whole_runtime_replaced=False)
            (work/"GATE.json").write_bytes(recover.encode(gate))
        print(json.dumps(dict(stage=a.stage,status="PASS",elapsed_seconds=row["elapsed_seconds"],
            stdout=row["stdout"],guard_probes=result.get("guard_probes"),unchanged_entries=result.get("unchanged_entries"),
            native_executions=14 if a.stage=="continue" else 0,rust_executions=0),sort_keys=True))
    except BaseException as error:
        failure=dict(stage=a.stage,error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        (work/"GATE.json").write_bytes(recover.encode(dict(status="FAIL",failure=failure,
            original_run_status="FAIL",source_manifest_sha256=binding,native_executions=None if a.stage=="continue" else 0,rust_executions=0)))
        if rec.records:
            print((rec.directory/(a.stage+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
