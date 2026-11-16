"""Publish reviewed source bytes with a fast-forward lease; execute no graph."""
from pathlib import Path
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import urllib.request

REPO="TrillionniumFoundation/hepta-runtime"
API="https://api.github.com/repos/"+REPO

def sha(raw):return hashlib.sha256(raw).hexdigest()
def oid(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def call(path,method="GET",body=None):
    data=None if body is None else json.dumps(body,separators=(",",":")).encode()
    request=urllib.request.Request(API+path,data=data,method=method,
        headers={"Authorization":"Bearer "+os.environ["GH_SOURCE_TOKEN"],"Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json"})
    with urllib.request.urlopen(request,timeout=60) as stream:return json.load(stream)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--expected-head",required=True)
    p.add_argument("--branch",required=True)
    a=p.parse_args()
    assert a.branch=="hia-extract-public-6780-20261116"
    ci=json.loads((a.capture/"SOURCE_CI.json").read_bytes())
    assert ci["status"]=="SOURCE_ASSEMBLY_PASS" and ci["native_semantic_executions"]==ci["rust_executions"]==0
    report=json.loads((a.capture/"generated/AUTHOR.json").read_bytes())
    assert report["status"]=="SOURCE_ASSEMBLED" and report["native_semantics_executed"] is False
    graph=a.capture/"generated/source"
    payload={}
    for name,pin in report["source_files"].items():
        relative=Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        raw=(graph/relative).read_bytes()
        assert pin=={"bytes":len(raw),"sha256":sha(raw)}
        payload[name]=raw
    assert sha(payload["native/runtime_mcp_sources.json"])==ci["source_binding_sha256"]
    known={row["git_blob"] for row in json.loads((a.runtime/"authoring/public_extract/BASELINE.json").read_bytes())["files"]}
    # Input author/overlay bytes already belong to the run's checked-out Git tree.
    for path in (a.runtime/"authoring/public_extract").rglob("*"):
        if path.is_file():known.add(oid(path.read_bytes()))
    payload["qualification/extract_lines/public_source/AUTHOR.json"]=(a.capture/"generated/AUTHOR.json").read_bytes()
    payload["qualification/extract_lines/public_source/SOURCE_CI.json"]=(a.capture/"SOURCE_CI.json").read_bytes()
    for path in (a.capture/"processes").iterdir():
        if path.is_file():payload["qualification/extract_lines/public_source/processes/"+path.name]=path.read_bytes()
    unique={oid(raw):raw for raw in payload.values()}
    def create(item):
        digest,raw=item
        if digest in known:return digest
        result=call("/git/blobs","POST",{"encoding":"base64","content":base64.b64encode(raw).decode()})
        assert result["sha"]==digest
        return digest
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        created=list(pool.map(create,unique.items()))
    assert len(created)==len(unique)
    ref=call("/git/ref/heads/"+a.branch)
    assert ref["object"]["sha"]==a.expected_head,"source branch advanced; do not overwrite"
    parent=call("/git/commits/"+a.expected_head)
    tree=call("/git/trees","POST",{"base_tree":parent["tree"]["sha"],
        "tree":[{"path":name,"mode":"100644","type":"blob","sha":oid(raw)} for name,raw in sorted(payload.items())]})
    commit=call("/git/commits","POST",{"message":"Assemble the actual 118-HIA public extract_lines source graph\n\nRetain exact source preservation proofs and both mechanical assembly results. Public semantics and catalog integration remain explicitly pending.",
        "parents":[a.expected_head],"tree":tree["sha"]})
    assert call("/git/ref/heads/"+a.branch)["object"]["sha"]==a.expected_head
    updated=call("/git/refs/heads/"+a.branch,"PATCH",{"sha":commit["sha"],"force":False})
    assert updated["object"]["sha"]==commit["sha"]
    result={"schema":"hepta.runtime.public-extract-source-publication.v1","status":"PUBLISHED",
        "parent":a.expected_head,"head":commit["sha"],"tree":tree["sha"],"files":len(payload),
        "source_binding_sha256":ci["source_binding_sha256"],"main_advanced":False,
        "public_handler_qualified":False,"native_semantics_executed":False,"rust_executed":False}
    (a.capture/"PUBLICATION.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
