#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read each whole actual new capture with unchanged original cases and bytes."""
from pathlib import Path
import argparse,json,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
import read_native,readonly
def main():
    p=argparse.ArgumentParser();p.add_argument("--prepared",type=Path,required=True)
    p.add_argument("--capture",type=Path,required=True);a=p.parse_args();source_evidence(HERE)
    prepared=decode((a.prepared/"PREPARED.json").read_bytes());native=a.capture/"native"
    original=Path(prepared["original"]);plan=decode((original/"PLAN.json").read_bytes())
    current=decode((native/"PLAN.json").read_bytes());result=decode((native/"RESULTS.json").read_bytes())
    first,count=current["first"],current["count"]
    require((first,count) in ((0,6),(6,5),(11,6),(17,5)),"exact full public partition")
    selected=plan["cases"][first:first+count]
    require(current["cases"]==selected and current["original_plan"]==pin(original/"PLAN.json")
        and len(result)==count and current["declaration"]==plan["declaration"],"complete actual unchanged inputs")
    binary=Path(prepared["binary"]);expected={k:prepared["inputs"]["build"]["binary"][k] for k in ("bytes","sha256")}
    require(current["binary"]==pin(binary)==expected,"exact actual successor ELF")
    require({p.name for p in (native/"cases").iterdir()}=={"%03d"%case["case"] for case in selected},"whole selected actual case set")
    process=decode((a.capture/"CAPTURE_PROCESS.json").read_bytes())
    require(process["exit_code"]==0 and process["outer_timeout_seconds"] is None
        and process["child_process_limit_seconds"]==180 and process["child_exchange_limit_seconds"]==60,
        "unchanged actual process/exchange limits and no outer second timeout")
    rows=[]
    for case,record in zip(selected,result,strict=True):
        case_number=case["case"];n=native/"cases"/("%03d"%case_number);o=original/"cases"/("%03d"%case_number)
        require(record==decode((n/"RESULT.json").read_bytes()) and record["production_source"]==
            "7567502bf4e76b5975a689b988e9f96e1206462a","complete actual result/source association")
        start=time.monotonic()
        proof=readonly.guarded(lambda:read_native.compare(n,o,case,expected),roots=[HERE,n,o])
        elapsed=time.monotonic()-start;require(elapsed<180,"whole case independent reader original180s")
        path=a.capture/("READ-%03d.json"%case_number);path.write_bytes(canonical(proof))
        row=dict(case=case_number,name=case["name"],era=case["era"],status=proof["evidence"]["status"],
            elapsed_seconds=elapsed,guards=len(proof["probes"]),entries=proof["entries"],
            proof=pin(path),semantic_replay=False,worker_journal_semantic_read_pending=True)
        rows.append(row);(a.capture/"READ_RESULTS.json").write_bytes(canonical(rows))
        print("PUBLIC_CASE_READ "+json.dumps(row,sort_keys=True),flush=True)
    summary=dict(status="COMPLETE_PUBLIC_PARTITION_WIRE_AND_STABLE_STATE_READ_PASS",
        first=first,count=count,cases=rows,original_replayed=False,native_replayed=False,
        direct_eight_pending=True,worker_journal_semantic_read_pending=True,full_sdk=False)
    (a.capture/"READ_SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
