#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Admit the full original, production graph and direct fixture without execution."""
from pathlib import Path
import argparse,json,subprocess,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
def main():
    p=argparse.ArgumentParser()
    for name in ("capture-recipe","public-reader","build-recipe","direct-recipe","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE)
    for path in HERE.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
    (a.output/"SOURCE_CHECK.json").write_bytes(canonical(source))
    command=[sys.executable,"-I","-S","-B",str(a.capture_recipe/"prepare.py"),"--public-reader",str(a.public_reader),
        "--build-recipe",str(a.build_recipe),"--direct-recipe",str(a.direct_recipe),"--output",str(a.output/"domain")]
    start=time.monotonic()
    with (a.output/"prepare.stdout").open("xb") as out,(a.output/"prepare.stderr").open("xb") as err:
        result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
    row=dict(command=command,exit_code=result.returncode,elapsed=time.monotonic()-start,
        no_outer_repeated_timeout=True,original_inner_pure_read_limits=180,
        stdout=pin(a.output/"prepare.stdout"),stderr=pin(a.output/"prepare.stderr"))
    (a.output/"PREPARE_PROCESS.json").write_bytes(canonical(row))
    if result.returncode:sys.stderr.buffer.write((a.output/"prepare.stderr").read_bytes())
    require(result.returncode==0,"complete unchanged artifact and graph admission")
    print(json.dumps(dict(status="COMPLETE_DIRECT_DEPENDENCIES_ADMITTED",process=row,source=source),sort_keys=True))
if __name__=="__main__":main()
