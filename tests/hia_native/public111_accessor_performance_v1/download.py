"""Retrieve one exact existing build ZIP without executing its contents."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);p.add_argument("--role",choices=("build","failure"),required=True)
    a=p.parse_args();out=a.output.resolve();assert not out.exists();out.mkdir(parents=True)
    declaration=json.loads((Path(__file__).resolve().parent/"CORPUS.json").read_bytes())
    wanted=declaration[a.role+"_artifact"];repo="TrillionniumFoundation/hepta-runtime"
    run=declaration["build_artifact"]["run_id"];attempt=declaration["build_artifact"]["attempt"]
    url=f"https://api.github.com/repos/{repo}/actions/artifacts/{wanted['id']}"
    headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as r:metadata=json.load(r)
    assert metadata["id"]==wanted["id"] and metadata["size_in_bytes"]==wanted["bytes"]
    assert metadata["digest"]=="sha256:"+wanted["sha256"] and metadata["expired"] is False
    assert metadata["workflow_run"]["id"]==run and metadata["workflow_run"]["head_sha"]==declaration["base_head"]
    try:response=urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url+"/zip",headers=headers),timeout=60)
    except urllib.error.HTTPError as e:
        assert e.code in (301,302,303,307,308)
        location=e.headers["Location"];parsed=urllib.parse.urlsplit(location)
        assert parsed.scheme=="https" and parsed.hostname and parsed.username is None
        response=urllib.request.urlopen(urllib.request.Request(location),timeout=60)
    digest=hashlib.sha256();size=0
    with response,(out/"artifact.zip").open("xb") as dest:
        while block:=response.read(1<<20):dest.write(block);digest.update(block);size+=len(block)
    assert {"bytes":size,"sha256":digest.hexdigest()}=={k:wanted[k] for k in ("bytes","sha256")}
    with zipfile.ZipFile(out/"artifact.zip") as z:
        assert set(z.namelist())=={"archive.json","capture.tar.gz"} and z.testzip() is None
        for name in z.namelist():
            with z.open(name) as src,(out/name).open("xb") as dest:
                while block:=src.read(1<<20):dest.write(block)
    receipt=json.loads((out/"archive.json").read_bytes())
    assert receipt["git_head"]==declaration["base_head"] and receipt["run_id"]==str(run)
    assert receipt["run_attempt"]==str(attempt) and receipt["label"]==("build" if a.role=="build" else "native")
    with (out/"capture.tar.gz").open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    assert receipt["archive"]=={"bytes":(out/"capture.tar.gz").stat().st_size,"sha256":digest}
    (out/"DOWNLOAD.json").write_text(json.dumps({"metadata":metadata,"full_zip":{"bytes":size,"sha256":wanted["sha256"]},"original_receipt":receipt,"native_executions":0,"rust_executions":0},sort_keys=True,indent=2)+"\n")
    print(json.dumps({"status":"FULL_EXISTING_ZIP_BYTES_PASS","artifact":wanted},sort_keys=True))

if __name__=="__main__":main()
