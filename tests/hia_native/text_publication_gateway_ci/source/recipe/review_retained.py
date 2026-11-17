#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Reread all six already completed processes; never start native or Rust code."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,require,source_evidence,pin
from input_domain import PROFILES
from read_gateway import read
from fetch_gateway_capture import extract
from readonly import guarded
SOURCE_BEFORE="b96da997f0ae977f1a1b080aaf4b555980622d2fdd8ce2dee29a79c580068570"
ALLOWED_CHANGED={"recipe/read_private_trace.py","README.md"}
ALLOWED_ADDED={"recipe/readonly.py","recipe/fetch_gateway_capture.py","recipe/review_retained.py",
    "retained/view_call_key_bridge.S","retained/view_call_read_bridge.S"}
def source_relation(current,old):
    require(pin(old/"SOURCE_MANIFEST.json")["sha256"]==SOURCE_BEFORE,"captured source manifest differs")
    source_evidence(old);source_evidence(current)
    names=lambda root:{p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}-{"SOURCE_MANIFEST.json"}
    before,after=names(old),names(current)
    require(before<=after and after-before==ALLOWED_ADDED,"pure-reader successor source set differs")
    changed={name for name in before if (old/name).read_bytes()!=(current/name).read_bytes()}
    require(changed==ALLOWED_CHANGED,"successor changed captured native/original/domain/driver source")
    return dict(changed=sorted(changed),added=sorted(after-before),all_other_source_bytes_exact=True)
def compare(source,selected):
    source_relation(source,selected/"recipe-source")
    result={}
    for profile in PROFILES:
        result[profile]=read(selected/"capture/profiles"/profile)
    require(sum(x["cases"] for x in result.values())==191,"complete six-domain count")
    return dict(status="COMPLETE_RETAINED_GATEWAY191_COMPARISON_PASS",profiles=result,
        source_relation=source_relation(source,selected/"recipe-source"),
        executed_hia=False,executed_rust=False,public_route=False,full_async=False,full_sdk=False)
def main():
    p=argparse.ArgumentParser()
    for name in ("source","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True)
    require(not a.output.exists(),"new readonly review output")
    a.output.mkdir(parents=True)
    selected=extract(a.output/"retained")
    # All imports, exact AST definitions and standard library capabilities are
    # initialized before the active guard; the reader itself has no executor.
    report=guarded(lambda:compare(source,selected),roots=(source,a.output/"retained"))
    (a.output/"READONLY.json").write_bytes(canonical(report))
    print(json.dumps({k:v for k,v in report.items() if k not in ("before","after")},sort_keys=True),flush=True)
if __name__=="__main__":main()
