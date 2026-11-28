#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import source_evidence,require
from verify_reference import verify
from helper_source import prepare
from input_domain import declaration,rows,PROFILES
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True)
    evidence=source_evidence(source);count=0
    for path in sorted(source.rglob("*.py")):compile(path.read_bytes(),str(path),"exec");count+=1
    original=verify(source/"reference")
    manifest=json.loads((source/"reference/source_manifest.json").read_bytes())
    require(manifest["unchanged_retained_original_items"]==106 and len(manifest["exact_original_items"])==111,"original domain differs")
    prepare(source/"retained/text75_qualify.py")
    domain=declaration()
    numbers={profile:len(rows(profile,Path("/owned/fixtures-root"))) for profile in PROFILES}
    require(numbers["body"]==82 and domain["per_exchange_seconds"]==60 and domain["per_process_seconds"]==180,"input domain changed")
    print(json.dumps(dict(status="SOURCE_ONLY_PASS",source=evidence,python_sources=count,original=original,
        profiles=numbers,hia_executed=False,rust_executed=False),sort_keys=True))
if __name__=="__main__":main()
