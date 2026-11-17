#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore immutable full artifacts and admit the four real graph entries."""
from pathlib import Path
import argparse,hashlib,json,os,stat,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
def command(root,name,args,limit=180):
    start=time.monotonic()
    with (root/(name+".stdout")).open("xb") as out,(root/(name+".stderr")).open("xb") as err:
        p=subprocess.run(list(map(str,args)),stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=limit)
    value=dict(command=list(map(str,args)),exit_code=p.returncode,elapsed=time.monotonic()-start,
        limit=limit,stdout=pin(root/(name+".stdout")),stderr=pin(root/(name+".stderr")))
    (root/(name+".json")).write_bytes(canonical(value))
    if p.returncode:sys.stderr.buffer.write((root/(name+".stderr")).read_bytes())
    require(p.returncode==0,"pure artifact admission failed: "+name)
def main():
    p=argparse.ArgumentParser();p.add_argument("--build-recipe",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE)
    for f in HERE.rglob("*.py"):compile(f.read_bytes(),str(f),"exec")
    (a.output/"SOURCE_CHECK.json").write_bytes(canonical(source))
    info=decode((HERE/"RETAINED_INPUTS.json").read_bytes());b=info["build"]
    command(a.output,"build-read",[sys.executable,"-I","-S","-B",
        a.build_recipe/"current/read_uploaded.py","--output",a.output/"build",
        "--artifact",b["artifact"],"--bytes",b["zip"]["bytes"],"--sha256",b["zip"]["sha256"]])
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    original,read=restore(a.output/"original",info["original"])
    require({f.relative_to(original/"recipe-source").as_posix():pin(f) for f in (original/"recipe-source").rglob("*") if f.is_file()}
        =={f.relative_to(HERE/"retained-original").as_posix():pin(f) for f in (HERE/"retained-original").rglob("*") if f.is_file()},
        "entire unchanged original qualification source")
    command(a.output,"original-read",[sys.executable,"-I","-S","-B",
        original/"recipe-source/recipe/entry.py","read","--capture",original/"capture",
        "--output",a.output/"ORIGINAL_READ.json"])
    binary=a.output/"build/extracted"/b["binary"]["path"]
    require(pin(binary)=={k:b["binary"][k] for k in ("bytes","sha256")},"actual two-session graph ELF identity")
    plan=decode((original/"capture/domain/PLAN.json").read_bytes())
    native=Path(plan["fixture_root"]).parent
    require(native.is_absolute() and not native.exists() and native!=a.output
        and not a.output.is_relative_to(native),"new exact original fixture root only")
    result=dict(binary=str(binary),original=str(original/"capture/domain"),native=str(native),inputs=info,
        source=source,original_archive=read,application_executed=False)
    (a.output/"PREPARED.json").write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
