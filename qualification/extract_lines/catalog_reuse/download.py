"""Download and fully reopen one retained catalog artifact; never execute its payload."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
API="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime"
ARTIFACT=14201568537
RUN=43813791993
ZIP_BYTES=172417686
ZIP_SHA="b772b06a9eeb135b327e17697c51a1071dc079cf556ed52a0ad9a0dd4efac7d5"

def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    with path.open("rb") as stream:return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def authenticated(path):
    return urllib.request.Request(API+path,headers={"Authorization":"Bearer "+os.environ["GH_ARCHIVE_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})

def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    opener=urllib.request.build_opener(NoRedirect)
    with opener.open(authenticated("/actions/artifacts/"+str(ARTIFACT)),timeout=60) as stream:
        meta=json.load(stream)
    assert meta["id"]==ARTIFACT and meta["workflow_run"]["id"]==RUN and meta["expired"] is False
    assert meta["size_in_bytes"]==ZIP_BYTES and meta.get("digest") in (None,"sha256:"+ZIP_SHA)
    dump(a.output/"artifact-metadata.json",meta)
    with opener.open(authenticated("/actions/runs/"+str(RUN)),timeout=60) as stream:run=json.load(stream)
    assert run["id"]==RUN and run["status"]=="completed" and run["conclusion"]=="success"
    assert run["head_sha"]=="9fe19f38e295057194f5f7da20d8f129b067cb63"
    dump(a.output/"run-metadata.json",run)
    try:
        opener.open(authenticated("/actions/artifacts/"+str(ARTIFACT)+"/zip"),timeout=60)
        raise AssertionError("artifact redirect absent")
    except urllib.error.HTTPError as response:
        assert response.code in (301,302,303,307,308)
        location=response.headers["Location"]
    parsed=urllib.parse.urlsplit(location)
    assert parsed.scheme=="https" and parsed.hostname
    # Never send the GitHub token to the signed storage origin.
    request=urllib.request.Request(location,headers={"User-Agent":"HIA-retained-catalog-reader"})
    archive=a.output/"catalog.zip"
    with urllib.request.urlopen(request,timeout=60) as stream,archive.open("xb") as target:
        while True:
            raw=stream.read(1<<20)
            if not raw:break
            target.write(raw)
    assert pin(archive)=={"bytes":ZIP_BYTES,"sha256":ZIP_SHA}
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist()
        assert len({x.filename for x in infos})==len(infos)
        actual=[x for x in infos if not x.is_dir()]
        assert {x.filename for x in actual}=={"archive.json","catalog-policy.tar.gz"}
        metadata=json.loads(z.read("archive.json"))
        tarpath=a.output/"catalog-policy.tar.gz"
        with z.open("catalog-policy.tar.gz") as source,tarpath.open("xb") as target:
            while True:
                raw=source.read(1<<20)
                if not raw:break
                target.write(raw)
        assert z.testzip() is None
    assert metadata["archive"]=="catalog-policy.tar.gz"
    assert pin(tarpath)=={k:metadata[k] for k in ("bytes","sha256")}
    data=a.output/"retained";data.mkdir()
    files={}
    with tarfile.open(tarpath,"r:gz") as tar:
        for member in tar:
            path=Path(member.name)
            assert not path.is_absolute() and path.parts and ".." not in path.parts and path.as_posix()==member.name
            assert member.isfile() and member.size>=0 and member.name not in files
            target=data/path
            target.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256();size=0
            with tar.extractfile(member) as source,target.open("xb") as sink:
                while True:
                    raw=source.read(1<<20)
                    if not raw:break
                    digest.update(raw);size+=len(raw);sink.write(raw)
            assert size==member.size
            os.chmod(target,member.mode & 0o777)
            assert stat.S_ISREG(target.lstat().st_mode) and target.lstat().st_nlink==1
            files[member.name]={"bytes":size,"sha256":digest.hexdigest()}
    manifest=json.loads((data/"artifact-manifest.json").read_bytes())
    assert manifest["schema"]=="hepta.runtime.catalog-policy-artifact.v2"
    assert manifest["files"]=={k:v for k,v in files.items() if k!="artifact-manifest.json"}
    assert len(files)==metadata["files"] and metadata["complete_archive"] is True
    report={"schema":"hepta.runtime.extract-catalog-complete-archive.v1","status":"PASS","run":RUN,"artifact":ARTIFACT,
        "zip":{"bytes":ZIP_BYTES,"sha256":ZIP_SHA},"tar":pin(tarpath),"manifest":files["artifact-manifest.json"],
        "files":len(files),"logical_bytes":sum(x["bytes"] for x in files.values()),
        "complete_files":files,"native_executions":0,"rust_executions":0,"read_only_payload":True}
    dump(a.output/"ARCHIVE_READBACK.json",report)
    print(json.dumps({k:v for k,v in report.items() if k!="complete_files"},sort_keys=True))

if __name__=="__main__":main()
