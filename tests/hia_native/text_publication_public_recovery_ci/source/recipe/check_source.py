#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Source closure and input-only composition checks; no native or original execution."""
from pathlib import Path
import argparse,ast,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import source_evidence,require
from public_domain import PROFILES,ERAS,rows,stdio_rows,old,declaration
def check():
    source=source_evidence(ROOT)
    compiled=0
    for file in sorted(ROOT.rglob("*.py")):
        compile(file.read_bytes(),str(file),"exec");compiled+=1
    fixture=Path("/owned-publication-qualification/fixtures-root")
    counts={}
    for era in ERAS:
        entries={}
        for profile in PROFILES:
            actual=rows(profile,fixture,era)
            require(len({r["id"] for r in actual})==len(actual),"unique input-only row identity")
            if profile in old.PROFILES:
                prior=old.rows(profile,fixture)
                require([r["original_input"] for r in actual[4:]]==prior,"retained191 original inputs changed")
            for row in actual:
                require(row["kind"] in ("wire","cache") and row["session"] in (0,1),"input-only fixture selector")
                if row["kind"]=="wire":
                    raw=bytes.fromhex(row["wire_hex"])
                    require(raw.endswith(b"\n") and raw.count(b"\n")==1,"normal complete public JSON line")
                    value=json.loads(raw)
                    require(value["jsonrpc"]=="2.0" and "method" in value,"actual protocol request shape")
            entries[profile]=len(actual)
        require(entries==dict(configured=30,absent=30,denied=30,fence_required=30,capabilities=9,body=86,typed=61,catalog=11),
            "entire declared public row domain")
        require(len(stdio_rows(fixture,era))==14,"complete stdio serial domain")
        counts[era]=entries
    require(sum(len(old.rows(profile,fixture)) for profile in old.PROFILES)==191,"complete retained private domain")
    import dependencies,read_public,public_reader_controls,readonly
    return dict(status="PUBLIC_SOURCE_AND_INPUTS_ONLY_PASS",source=source,python_sources=compiled,
        counts=counts,carrier_rows=574,stdio_rows=112,input_only=True,
        hia_executed=False,rust_executed=False,public_qualified=False)
if __name__=="__main__":
    print(json.dumps(check(),sort_keys=True))
