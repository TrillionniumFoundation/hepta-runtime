#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Whole current124 comparison with exact retained original capture and graph bytes."""
from pathlib import Path
import argparse,json,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,pin,require,source_evidence
import current_dependencies,read_current,read_public,readonly
from helper_source import prepare
def verify(capture,retained,graph_proof):
    source_evidence(ROOT);prepare(ROOT/"retained/text75_qualify.py")
    read_public.old.retained_filesystem();read_current.old.retained_filesystem()
    capture,retained,graph_proof=map(lambda p:Path(p).resolve(strict=True),(capture,retained,graph_proof))
    def operation():
        original=read_public.read(retained)
        custody=current_dependencies.verify_capture(capture,retained,graph_proof)
        deps=decode((capture/"DEPENDENCIES.json").read_bytes())
        require(pin(graph_proof.parent/"filesystem.elf")==deps["carrier_binary_pin"]
            and pin(graph_proof.parent/"runtime-mcp.elf")==deps["stdio_binary_pin"]
            and all((graph_proof.parent/n).stat().st_mode&0o111 for n in ("filesystem.elf","runtime-mcp.elf")),
            "complete actual application executable bytes and modes")
        current=read_current.read(capture)
        for field in ("mode","profile","era","cases","responses","publisher_successes"):
            require(current[field]==original[field],"whole original/current fixed domain "+field)
        return dict(status="COMPLETE_CURRENT124_ORDINARY_RETAINED_ORIGINAL_JOIN_PASS",
            current=current,original=original,custody=custody,native_applications=1,
            original_applications=0,full_sdk=False,all_136_handlers=False)
    start=time.monotonic()
    proof=readonly.guarded(operation,roots=[ROOT,capture,retained,graph_proof.parent])
    elapsed=time.monotonic()-start;require(elapsed<180,"whole original/current pure reader180")
    return proof,elapsed
def main():
    p=argparse.ArgumentParser()
    for name in ("capture","retained","graph-proof","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(not a.output.exists(),"fresh complete reader result")
    proof,elapsed=verify(a.capture,a.retained,a.graph_proof)
    a.output.write_bytes(canonical(dict(proof=proof,elapsed_seconds=elapsed)))
    e=proof["evidence"];print(json.dumps(dict(status=e["status"],cases=e["current"]["cases"],
        mode=e["current"]["mode"],profile=e["current"]["profile"],era=e["current"]["era"],
        guards=len(proof["probes"]),entries=proof["entries"],elapsed_seconds=elapsed,
        native_or_rust_executed=False),sort_keys=True))
if __name__=="__main__":main()
