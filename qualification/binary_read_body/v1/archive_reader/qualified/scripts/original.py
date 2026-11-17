#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Invoke the exact unedited current binary_file.py functions on retained actual fixtures."""
from pathlib import Path
import argparse,json,os,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,source_evidence,require,pin
from cases import group
from filesystem import snapshot
from buffer_store import Writer
def main():
    p=argparse.ArgumentParser()
    for name in("source","setup","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh reference output required");a.output.mkdir(parents=True)
    original=source/"trusted-build/target/binary_file.py"
    namespace=dict(__name__="qualified_binary_original",__file__=str(original))
    exec(compile(original.read_bytes(),str(original),"exec"),namespace)
    rows=decode(owned(a.setup,"inputs.json").read_bytes());selected={r["id"]for r in group(a.group)}
    store=Writer(a.output/"buffers");results=[]
    for query in rows:
        if query["id"]not in selected:continue
        row=dict(id=query["id"],input=query,before=snapshot(query["fixture"],store))
        before=time.monotonic_ns()
        try:
            if query["mode"]=="fingerprint":
                fd,name=namespace["parent"](query["request"]["root"],query["request"]["path"])
                try:value=namespace["fingerprint"](fd,name)
                finally:os.close(fd)
            else:value=namespace["main"](query["request"])
            row["result"]=dict(ok=True,value=value,canonical=canonical(value)[:-1].decode())
        except Exception as error:
            number=getattr(error,"errno",None)
            row["result"]=dict(ok=False,error=dict(type=type(error).__name__,errno=number,
                filename=getattr(error,"filename",None),message=str(error)if number is None else""))
            row["original_diagnostic"]=type(error).__name__+": "+str(error)
        row["elapsed_ns"]=time.monotonic_ns()-before;row["after"]=snapshot(query["fixture"],store)
        require(row["before"]==row["after"],"read-only original changed file metadata or content")
        results.append(row)
    (a.output/"cases.json").write_bytes(canonical(results))
    result=dict(status="ORIGINAL_BINARY_READ_DOMAIN_COMPLETE",cases=len(results),group=a.group,source=identity,
        original_source=pin(original),buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        exact_original_functions=True)
    (a.output/"CAPTURE.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
