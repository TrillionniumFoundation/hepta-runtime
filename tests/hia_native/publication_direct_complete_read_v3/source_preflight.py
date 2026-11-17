#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the complete source and reversible reader edits without applications."""
from pathlib import Path
import json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import decode,require,source_evidence
from direct_provenance import drop_source,rawpin,replace_once
def main():
    source=source_evidence(HERE)
    files=list(HERE.rglob("*.py"))
    for path in files:compile(path.read_bytes(),str(path),"exec")
    spec=decode((HERE/"DIRECT_WORKER_SOURCE.json").read_bytes())
    before=(HERE/"retained_public_worker.py").read_bytes()
    after=(HERE/"direct_worker.py").read_bytes()
    require(rawpin(before)==spec["before"] and rawpin(after)==spec["after"],"complete source endpoints")
    text=before.decode()
    for row in spec["edits"]:text=replace_once(text,row["before"],row["after"])
    require(text.encode()==after,"complete forward transformation")
    for row in reversed(spec["edits"]):text=replace_once(text,row["after"],row["before"])
    require(text.encode()==before,"complete inverse transformation")
    drop=drop_source(HERE);info=decode((HERE/"INPUTS.json").read_bytes())
    require(sorted(n for r in info["roles"].values() for n in r["completed"])==
        info["all_direct_inputs"]==list(range(22,30)),"all eight inputs unchanged")
    require(info["budgets"]==dict(case_read_seconds=180,job_minutes=15),"unchanged budgets")
    require(drop["direct_future_drop"]==dict(generation_delta=1,scope_opcode=8,
        scope_lease=0,reason=2,cache_forget=False,result_extent=0),"explicit source-derived direct cancellation contract")
    print(json.dumps(dict(status="COMPLETE_DIRECT_SOURCE_ONLY_PASS",source=source,
        python_sources=len(files),reader_edits=len(spec["edits"]),native_or_rust_executed=False,
        source_only=True,read_execution_pending=True,full_sdk=False),sort_keys=True))
if __name__=="__main__":main()
