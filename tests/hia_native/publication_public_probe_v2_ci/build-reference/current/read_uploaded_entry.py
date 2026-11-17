#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind the same frozen CI producer artifact before a byte-only independent read."""
from pathlib import Path
import argparse,json,os,sys,urllib.request
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(__file__).resolve().parent))
from async_build_common import require,put
import read_uploaded
def main():
    p=argparse.ArgumentParser();p.add_argument("--artifact",type=int,required=True);p.add_argument("--head",required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--digest",required=True);a=p.parse_args()
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(a.artifact),
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","User-Agent":"publication-build-independent-reader"})
    with urllib.request.urlopen(req,timeout=60) as r:metadata=json.load(r)
    require(metadata["id"]==a.artifact and metadata["workflow_run"]["head_sha"]==a.head and not metadata["expired"],"actual same frozen producer artifact")
    digest=metadata["digest"].removeprefix("sha256:")
    require(digest==a.digest.removeprefix("sha256:") and len(digest)==64,"producer upload/API digest agreement")
    identity=dict(artifact=a.artifact,producer_head=a.head,zip=dict(bytes=metadata["size_in_bytes"],sha256=digest))
    put(a.output.parent/(a.output.name+"-IDENTITY.json"),identity)
    sys.argv=[read_uploaded.__file__,"--output",str(a.output),"--artifact",str(a.artifact),"--bytes",str(metadata["size_in_bytes"]),"--sha256",digest]
    read_uploaded.main()
if __name__=="__main__":main()
