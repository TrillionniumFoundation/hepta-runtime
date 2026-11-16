"""Persist selected actual native buffers and readonly proof on this evidence branch."""
from pathlib import Path
import argparse,base64,concurrent.futures,hashlib,json,os,urllib.request
API="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime"
def oid(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def call(path,method="GET",body=None):
    data=None if body is None else json.dumps(body,separators=(",",":")).encode()
    request=urllib.request.Request(API+path,data=data,method=method,
      headers={"Authorization":"Bearer "+os.environ["GH_SOURCE_TOKEN"],"Accept":"application/vnd.github+json",
       "X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json"})
    with urllib.request.urlopen(request,timeout=60) as stream:return json.load(stream)
def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--expected-head",required=True);p.add_argument("--branch",required=True);a=p.parse_args()
    assert a.branch=="hia-extract-catalog-6780-20261116"
    ci=json.loads((a.capture/"CATALOG_REUSE_CI.json").read_bytes())
    assert ci["status"]=="RETAINED_CATALOG_READONLY_PASS"
    evidence=a.capture/"evidence";report=json.loads((evidence/"READONLY.json").read_bytes())
    assert report["status"]=="PASS" and report["before"]==report["after"] and len(report["probes"])==12
    assert report["native_executions"]==report["rust_executions"]==report["reader_writes"]==0
    assets=json.loads((evidence/"ASSETS.json").read_bytes())
    assert assets["run"]==43813791993 and assets["artifact"]==14201568537
    assert assets["original_expected_wire_used_as_implementation"] is False
    payload={}
    for path in sorted(evidence.rglob("*")):
        if path.is_file():
            assert not path.is_symlink()
            payload["qualification/extract_lines/catalog_reuse/evidence/"+path.relative_to(evidence).as_posix()]=path.read_bytes()
    payload["qualification/extract_lines/catalog_reuse/CATALOG_REUSE_CI.json"]=(a.capture/"CATALOG_REUSE_CI.json").read_bytes()
    for path in (a.capture/"processes").iterdir():
        if path.is_file():payload["qualification/extract_lines/catalog_reuse/processes/"+path.name]=path.read_bytes()
    for name,pin in assets["files"].items():
        raw=(evidence/name).read_bytes()
        assert pin=={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    unique={oid(raw):raw for raw in payload.values()}
    def upload(item):
        digest,raw=item
        result=call("/git/blobs","POST",{"encoding":"base64","content":base64.b64encode(raw).decode()})
        assert result["sha"]==digest
        return digest
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        assert len(list(pool.map(upload,unique.items())))==len(unique)
    assert call("/git/ref/heads/"+a.branch)["object"]["sha"]==a.expected_head
    parent=call("/git/commits/"+a.expected_head)
    tree=call("/git/trees","POST",{"base_tree":parent["tree"]["sha"],
        "tree":[{"path":name,"mode":"100644","type":"blob","sha":oid(raw)} for name,raw in sorted(payload.items())]})
    commit=call("/git/commits","POST",{"message":"Retain actual native catalog assets after complete readonly recovery\n\nRead the same successful 136-input artifact, verify complete controls under the write/execute guard, and retain both actual ordinary/modern shapes. No native or Rust process is replayed.",
        "parents":[a.expected_head],"tree":tree["sha"]})
    assert call("/git/ref/heads/"+a.branch)["object"]["sha"]==a.expected_head
    updated=call("/git/refs/heads/"+a.branch,"PATCH",{"sha":commit["sha"],"force":False})
    assert updated["object"]["sha"]==commit["sha"]
    result={"schema":"hepta.runtime.extract-catalog-source-publication.v1","status":"PUBLISHED",
        "parent":a.expected_head,"head":commit["sha"],"tree":tree["sha"],"files":len(payload),
        "assets_sha256":hashlib.sha256((evidence/"ASSETS.json").read_bytes()).hexdigest(),
        "main_advanced":False,"native_reexecutions":0,"rust_executions":0}
    (a.capture/"PUBLICATION.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
