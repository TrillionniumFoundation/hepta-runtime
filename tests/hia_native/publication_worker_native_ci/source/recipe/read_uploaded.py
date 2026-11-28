#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore all uploaded bytes and directory metadata, then guard the pure reader."""
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

def restore(work,index):
    rows=index["files"]+index["directories"];wanted={r["path"]:r for r in rows};seen=set()
    require(len(wanted)==len(rows),"unique complete retained archive index")
    root=work/"extracted";root.mkdir()
    with tarfile.open(work/"evidence.tar.gz","r:gz") as stream:
        for member in stream:
            archive.safe(member.name)
            require(member.name in wanted and member.name not in seen,"exact restore member")
            seen.add(member.name);row=wanted[member.name];path=root/member.name
            if row["kind"]=="dir":
                require(member.isdir(),"restored directory type")
                path.mkdir(parents=True,exist_ok=True)
            else:
                require(member.isfile(),"restored file type")
                path.parent.mkdir(parents=True,exist_ok=True)
                with stream.extractfile(member) as incoming,path.open("xb") as dest:
                    shutil.copyfileobj(incoming,dest,1<<20)
                require(pin(path)=={k:row[k] for k in ("bytes","sha256")},"complete restored bytes")
    require(seen==set(wanted),"complete restored set")
    # Apply all physical directory metadata after their children are restored.
    for row in sorted(rows,key=lambda r:len(PurePosixPath(r["path"]).parts),reverse=True):
        path=root/row["path"];path.chmod(row["mode"])
        for name,raw in row["xattrs"].items():os.setxattr(path,name,bytes.fromhex(raw),follow_symlinks=False)
        os.utime(path,ns=(row["mtime_ns"],row["mtime_ns"]),follow_symlinks=False)
        require(path.stat().st_mode&0o777==row["mode"] and path.stat().st_mtime_ns==row["mtime_ns"]
            and archive.attrs(path)==row["xattrs"],"complete restored metadata")
    actual={p.relative_to(root).as_posix() for p in root.rglob("*")}
    require(actual==set(wanted),"no omitted or extra physical archive entries")
    return root

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--run",required=True);p.add_argument("--head",required=True);p.add_argument("--artifact-name",required=True)
    p.add_argument("--work",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();require(not a.work.exists() and not a.output.exists(),"fresh uploaded read")
    a.work.mkdir(parents=True);a.output.mkdir(parents=True);entry.check_source()
    with get("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/runs/"+a.run) as incoming:
        run=json.load(incoming)
    require(run["head_sha"]==a.head,"exact qualification source head")
    with get("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/runs/"+a.run+"/artifacts?per_page=100") as incoming:
        api=json.load(incoming)
    found=[r for r in api["artifacts"] if r["name"]==a.artifact_name]
    require(len(found)==1 and found[0]["expired"] is False,"one uploaded complete artifact")
    item=found[0];require(item["digest"].startswith("sha256:"),"server ZIP digest")
    req=urllib.request.Request(item["archive_download_url"],headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:incoming=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact redirect")
        location=error.headers["Location"];require(urllib.parse.urlparse(location).scheme=="https","artifact HTTPS")
        incoming=urllib.request.urlopen(location,timeout=60)
    zip_path=a.work/"artifact.zip"
    with incoming,zip_path.open("xb") as dest:shutil.copyfileobj(incoming,dest,1<<20)
    require(pin(zip_path)==dict(bytes=item["size_in_bytes"],sha256=item["digest"][7:]),"entire uploaded ZIP identity")
    with zipfile.ZipFile(zip_path) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"}
            and z.testzip() is None,"uploaded complete ZIP set/CRC")
        for name in z.namelist():
            with z.open(name) as incoming,(a.work/name).open("xb") as dest:shutil.copyfileobj(incoming,dest,1<<20)
    index=decode((a.work/"FILES.json").read_bytes());receipt=decode((a.work/"ARCHIVE.json").read_bytes())
    require(archive.verify(a.work/"evidence.tar.gz",index)==receipt,"entire uploaded TAR bytes/metadata")
    root=restore(a.work,index);recipe=root/"recipe-source"
    require({p.relative_to(recipe).as_posix():pin(p) for p in recipe.rglob("*") if p.is_file()}==
        {p.relative_to(entry.HERE).as_posix():pin(p) for p in entry.HERE.rglob("*") if p.is_file()},"exact full source package")
    capture=root/"capture"
    def operation():
        actual=entry.read(capture)
        original=decode((root/"capture-readonly.json").read_bytes())
        require(original["status"]=="READONLY_PASS" and original["before"]==original["after"]
            and original["native_executed"] is original["rust_executed"] is original["evidence_written"] is False
            and len(original["probes"])==11 and all(r["rejected"] is True for r in original["probes"])
            and canonical(original["evidence"])==canonical(actual),"complete original guarded result")
        require(archive.verify(a.work/"evidence.tar.gz",index)==receipt,"retained full archive unchanged")
        return actual
    started=time.monotonic();proof=readonly.guarded(operation,roots=(entry.HERE,a.work))
    elapsed=time.monotonic()-started
    require(elapsed<180,"complete pure-reader180-second bound")
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(a.work/name,a.output/name)
    summary=dict(status="PUBLICATION_WORKER_BUILD_UPLOADED_READONLY_PASS",run=int(a.run),head=a.head,
        artifact=item["id"],zip=pin(zip_path),archive=receipt,elapsed_seconds=elapsed,entries=proof["entries"],
        guard_probes=len(proof["probes"]),evidence=proof["evidence"],
        hia_executed=False,rust_executed=False,native_async_qualified=False,full_sdk=False)
    (a.output/"RESULT.json").write_bytes(canonical(summary))
    print(json.dumps({k:v for k,v in summary.items() if k!="evidence"},sort_keys=True))
if __name__=="__main__":main()
