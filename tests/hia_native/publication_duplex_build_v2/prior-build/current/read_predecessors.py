#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every retained source-author failure/success byte; never replay producers."""
from pathlib import Path
import argparse,json,shutil,sys
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(__file__).resolve().parent))
from async_build_common import *
import restore_full
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--downloads",type=Path,required=True);a=p.parse_args();package()
    require(not a.output.exists(),"fresh read proof");a.output.mkdir(parents=True)
    summaries=[]
    for row in doc(HERE/"PREDECESSORS.json"):
        out=a.downloads/str(row["artifact"]);_,report=restore_full.restore(out,row,extract=False)
        part=a.output/str(row["artifact"]);part.mkdir()
        for name in ("READ.json","ARCHIVE.json","FILES.json"):shutil.copyfile(out/name,part/name)
        report.update(source=row["source"],producer_conclusion=row["conclusion"]);summaries.append(report)
    result=dict(status="ALL_RETAINED_SOURCE_AUTHOR_ARCHIVES_FULLY_READ",entries=summaries,native_or_rust_executed=False)
    put(a.output/"SUMMARY.json",result);print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
