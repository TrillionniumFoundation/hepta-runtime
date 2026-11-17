#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only uploaded fixture admission; never invokes the new ELF."""
from pathlib import Path
import argparse,json,os,sys,urllib.request
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import direct_common as c
def main():
    p=argparse.ArgumentParser()
    for n in ("recipe","previous","output","proof"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--artifact",type=int,required=True);p.add_argument("--head",required=True);p.add_argument("--digest",required=True)
    a=p.parse_args();a.proof.mkdir(parents=True,exist_ok=False)
    modules=c.setup(a.recipe);identity,ac,restore,old,dynamic,guard,reader=modules
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(a.artifact),
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","User-Agent":"publication-direct-build-full-reader"})
    with urllib.request.urlopen(req,timeout=60) as response:metadata=json.load(response)
    digest=metadata["digest"].removeprefix("sha256:")
    c.require(metadata["id"]==a.artifact and metadata["workflow_run"]["head_sha"]==a.head and not metadata["expired"]
        and digest==a.digest.removeprefix("sha256:") and len(digest)==64,"exact actual producer upload")
    origin=dict(artifact=a.artifact,zip=dict(bytes=metadata["size_in_bytes"],sha256=digest),head=a.head)
    c.put(a.proof/"IDENTITY.json",origin)
    target,archive=restore.restore(a.output,origin)
    c.require(ac.files(target/"recipe-source")==ac.files(HERE),"complete same new private recipe")
    result=c.checked(target/"capture",a.previous,a.recipe)
    c.put(a.proof/"READ_ONLY.json",result)
    import shutil
    for n in ("READ.json","ARCHIVE.json","FILES.json"):shutil.copyfile(a.output/n,a.proof/n)
    summary=dict(status="COMPLETE_UPLOADED_DIRECT_BUILD_PASS",archive=archive,
        guards=len(result["probes"]),entries=len(result["before"]),actual_build=result["evidence"]["direct"],
        native_or_rust_executed=False,reader_writes=0,application_qualified=False)
    c.put(a.proof/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
