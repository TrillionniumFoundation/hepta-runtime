#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""CI-only source generation and fresh compilation of a private publication body."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require

def check(source):
    manifest=decode((source/"SOURCE_MANIFEST.json").read_bytes())
    rows=manifest["files"]
    actual={p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    require(actual=={r["path"] for r in rows}|{"SOURCE_MANIFEST.json"},"source closure changed")
    for row in rows:
        path=source/row["path"];raw=path.read_bytes()
        require(len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
          and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"source identity changed")
        if path.suffix in (".py",".pseudo"):ast.parse(raw,filename=str(path))
    return dict(status="SOURCE_ONLY_PASS",files=len(rows))

def command(output,label,argv):
    root=output/"processes";root.mkdir(exist_ok=True)
    begin=time.monotonic_ns()
    record=dict(argv=[str(x) for x in argv],limit_seconds=180,timed_out=False,started_ns=begin)
    with (root/(label+".stdout")).open("xb") as out,(root/(label+".stderr")).open("xb") as err:
        process=subprocess.Popen(record["argv"],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
        record["pid"]=process.pid
        try:record["returncode"]=process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            record["timed_out"]=True
            os.killpg(process.pid,signal.SIGKILL)
            record["returncode"]=process.wait()
    record["elapsed_ns"]=time.monotonic_ns()-begin
    record["streams"]={name:pin(root/(label+"."+name)) for name in ("stdout","stderr")}
    (root/(label+".json")).write_bytes(canonical(record))
    require(record["returncode"]==0 and not record["timed_out"],"process failed: "+label)

def build(source,hepta,output):
    from hia_native_build import NativeBuild
    builder=NativeBuild(hepta,output/"build")
    members={}
    for name,path in (("text-file-publication",output/"generated/text_file_publication.hepta"),("binary-codec",source/"native/binary_codec.hepta")):
        manifest=builder.compile(name,path,standalone=None,buffer_profile="history.v1")
        members[name]=dict(manifest=manifest.relative_to(output).as_posix(),identity=pin(manifest),
          source=pin(path),image=decode(manifest.read_bytes())["image_sha256"])
    dep=output/"compiler-source";dep.mkdir()
    for name in builder.identity["files"]:
        target=dep/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(hepta/name,target)
    value=dict(status="TWO_FRESH_HIA_OWNERS_COMPILED",members=members,compiler=builder.identity,
        native_compiled=True,native_semantics_executed=False,current_original_compared=False,public_route=False)
    (output/"BUILD.json").write_bytes(canonical(value))
    print(json.dumps(value,sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("check","build","run"))
    for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":print(json.dumps(check(source),sort_keys=True));return
    require(os.environ.get("GITHUB_ACTIONS")=="true","native compilation is restricted to CI")
    hepta=a.hepta.resolve(strict=True);output=a.output.absolute()
    if a.mode=="build":build(source,hepta,output);return
    require(not output.exists(),"candidate output must be fresh");output.mkdir(parents=True)
    check(source);shutil.copytree(source,output/"source");source=output/"source"
    py=[sys.executable,"-I","-S","-B"]
    command(output,"author",py+[source/"authoring/author_publication.py","--source",source,"--hepta",hepta,"--output",output/"generated"])
    command(output,"build",py+[source/"scripts/build_body.py","build","--source",source,"--hepta",hepta,"--output",output])
    print((output/"BUILD.json").read_text())

if __name__=="__main__":main()
