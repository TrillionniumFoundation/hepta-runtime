#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind original thirty cases and both uploaded actual graph artifacts."""
from pathlib import Path
import argparse,json,subprocess,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
def main():
    p=argparse.ArgumentParser()
    for n in ("public-reader","build-recipe","direct-recipe","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE)
    for q in HERE.rglob("*.py"):compile(q.read_bytes(),str(q),"exec")
    (a.output/"SOURCE_CHECK.json").write_bytes(canonical(source))
    cmd=[sys.executable,"-I","-S","-B",str(a.public_reader/"prepare.py"),"--build-recipe",str(a.build_recipe),
        "--output",str(a.output/"public-prepared")]
    start=time.monotonic()
    with (a.output/"prior.stdout").open("xb") as out,(a.output/"prior.stderr").open("xb") as err:
        result=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
    (a.output/"PRIOR_PROCESS.json").write_bytes(canonical(dict(argv=cmd,exit_code=result.returncode,
        elapsed=time.monotonic()-start,inner_pure_read_deadline=180,outer_timeout=None,application_executed=False)))
    if result.returncode:sys.stderr.buffer.write((a.output/"prior.stderr").read_bytes())
    require(result.returncode==0,"full current production graph and actual original admission")
    sys.path.insert(0,str(a.direct_recipe))
    import direct_common
    modules=direct_common.setup(a.build_recipe)
    _,ac,restore,old,dynamic,guard,reader=modules
    info=decode((HERE/"DIRECT_INPUTS.json").read_bytes())
    target,archive=restore.restore(a.output/"direct-build",info["build"])
    require(ac.files(target/"recipe-source")==ac.files(a.direct_recipe),"exact whole direct build recipe")
    previous=a.output/"public-prepared/build/extracted/capture"
    start=time.monotonic();proof=direct_common.checked(target/"capture",previous,a.build_recipe)
    elapsed=time.monotonic()-start;require(elapsed<180,"complete direct build pure reader180s")
    (a.output/"DIRECT_BUILD_READ.json").write_bytes(canonical(proof))
    previous_prep=decode((a.output/"public-prepared/PREPARED.json").read_bytes())
    binary=target/info["build"]["binary"]["path"]
    require(pin(binary)=={k:info["build"]["binary"][k] for k in ("bytes","sha256")},"exact fresh direct fixture ELF")
    result=dict(binary=str(binary),original=previous_prep["original"],native=previous_prep["native"],
        inputs=info,source=source,archive=archive,guards=len(proof["probes"]),application_executed=False)
    (a.output/"PREPARED.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
