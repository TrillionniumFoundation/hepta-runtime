#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independently restore every uploaded default-entry byte and guard the pure reader."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,shutil,sys,tarfile,time,urllib.error,urllib.parse,urllib.request,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require
import archive,entry,readonly
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def get(url):
    req=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    return urllib.request.urlopen(req,timeout=60)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--run",required=True);p.add_argument("--artifact-name",required=True)
    p.add_argument("--work",required=True,type=Path);p.add_argument("--output",required=True,type=Path)
    a=p.parse_args();require(not a.work.exists() and not a.output.exists(),"fresh uploaded read")
    a.work.mkdir(parents=True);a.output.mkdir(parents=True);entry.inputs()
    with get("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/runs/"+a.run+"/artifacts?per_page=100") as incoming:
        api=json.load(incoming)
    found=[r for r in api["artifacts"] if r["name"]==a.artifact_name]
    require(len(found)==1 and found[0]["expired"] is False,"one complete uploaded artifact")
    item=found[0];require(item["digest"].startswith("sha256:"),"uploaded artifact server digest")
    req=urllib.request.Request(item["archive_download_url"],headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:incoming=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact redirect")
        location=error.headers["Location"];require(urllib.parse.urlparse(location).scheme=="https","artifact HTTPS")
        incoming=urllib.request.urlopen(location,timeout=60)
    zip_path=a.work/"artifact.zip"
    with incoming,zip_path.open("xb") as out:
        while block:=incoming.read(1<<20):out.write(block)
    require(pin(zip_path)==dict(bytes=item["size_in_bytes"],sha256=item["digest"][7:]),"complete uploaded ZIP")
    with zipfile.ZipFile(zip_path) as z:
        require(z.namelist()==list(dict.fromkeys(z.namelist())) and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"}
            and z.testzip() is None,"full uploaded ZIP member set")
        for name in z.namelist():
            with z.open(name) as incoming,(a.work/name).open("xb") as out:
                while block:=incoming.read(1<<20):out.write(block)
    index=decode((a.work/"FILES.json").read_bytes());receipt=decode((a.work/"ARCHIVE.json").read_bytes())
    require(archive.verify(a.work/"evidence.tar.gz",index)==receipt,"complete uploaded TAR bytes/modes")
    wanted={r["path"]:r for r in index["files"]};seen=set();root=a.work/"extracted"
    with tarfile.open(a.work/"evidence.tar.gz","r:gz") as tar:
        for member in tar:
            name=PurePosixPath(member.name)
            require(member.isfile() and member.name in wanted and member.name not in seen and not name.is_absolute()
                and ".." not in name.parts and name.as_posix()==member.name,"ordinary exact archive member")
            path=root/member.name;path.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as incoming,path.open("xb") as out:
                while block:=incoming.read(1<<20):out.write(block)
            path.chmod(member.mode)
            row=wanted[member.name]
            require(pin(path)=={k:row[k] for k in ("bytes","sha256")} and path.stat().st_mode&0o777==row["mode"],
                "all restored bytes and modes")
            seen.add(member.name)
    require(seen==set(wanted),"complete extracted file set")
    recipe=root/"recipe-source"
    require({p.relative_to(recipe).as_posix():pin(p) for p in recipe.rglob("*") if p.is_file()}==
        {p.relative_to(entry.HERE).as_posix():pin(p) for p in entry.HERE.rglob("*") if p.is_file()},"frozen full reader source")
    capture=root/"capture"
    def operation():
        actual=entry.read(capture)
        original=decode((root/"capture-readonly.json").read_bytes())
        require(original["status"]=="READONLY_PASS" and original["before"]==original["after"]
            and original["native_executed"] is original["rust_executed"] is original["evidence_written"] is False
            and len(original["probes"])==11 and all(r["rejected"] is True for r in original["probes"])
            and original["evidence"]==actual,"complete original guarded result")
        require(archive.verify(a.work/"evidence.tar.gz",index)==receipt,"retained archive still exact")
        return actual
    started=time.monotonic()
    proof=readonly.guarded(operation,roots=(entry.HERE,a.work))
    elapsed=time.monotonic()-started
    require(elapsed<180,"retained pure-reader180-second limit")
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(a.work/name,a.output/name)
    summary=dict(status="ACTUAL_DEFAULT123_UPLOADED_READONLY_PASS",artifact=item["id"],zip=pin(zip_path),
        archive=receipt,elapsed_seconds=elapsed,entries=proof["entries"],guard_probes=len(proof["probes"]),evidence=proof["evidence"],
        hia_executed=False,rust_executed=False)
    (a.output/"RESULT.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
