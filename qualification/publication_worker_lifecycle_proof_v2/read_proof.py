#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete already-uploaded proof bytes; no HIA/Rust/application invocation."""
from pathlib import Path
import argparse,hashlib,io,json,os,tarfile,urllib.error,urllib.parse,urllib.request,zipfile
def require(v,m):
    if not v:raise ValueError(m)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def unique(items):
    d={}
    for k,v in items:require(k not in d,"duplicate JSON key");d[k]=v
    return d
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh proof read directory");a.output.mkdir(parents=True)
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14328976869/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:incoming=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as e:
        require(e.code in (301,302,303,307,308),"artifact redirect")
        url=e.headers["Location"];require(urllib.parse.urlparse(url).scheme=="https","HTTPS artifact")
        incoming=urllib.request.urlopen(url,timeout=60)
    with incoming:raw=incoming.read()
    require(pin(raw)==dict(bytes=1051079,sha256="443d2b8401337f632a71135984da2377b8f300fd9a72b951e7b2969136b18897"),"full immutable proof ZIP")
    (a.output/"proof.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"} and z.testzip() is None,"complete proof ZIP set")
        data={name:z.read(name) for name in z.namelist()}
    require(pin(data["evidence.tar.gz"])==dict(bytes=1035245,sha256="40697a47b9d61e7024770d7f9a28a41cbfdc638555c115f7819471444678f1c7"),"full proof TAR")
    index=decode(data["FILES.json"]);rows=index["files"]+index["directories"]
    wanted={r["path"]:r for r in rows};seen=set();contents={}
    require(len(wanted)==len(rows) and len(index["files"])==64 and len(index["directories"])==13,"complete proof archive index")
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]),mode="r:gz") as stream:
        for member in stream:
            require(member.name in wanted and member.name not in seen,"exact proof archive member")
            seen.add(member.name);row=wanted[member.name]
            require(member.mode==row["mode"] and member.size==row["bytes"],"proof archive physical extent/mode")
            require(member.pax_headers.get("mtime")==str(row["mtime_ns"]//1000000000)+"."+f'{row["mtime_ns"]%1000000000:09d}',"proof exact mtime")
            require({k[len("HEPTA.xattr.hex.v1."):]:v for k,v in member.pax_headers.items() if k.startswith("HEPTA.xattr.hex.v1.")}==row["xattrs"],"proof complete xattrs")
            if row["kind"]=="file":
                require(member.isfile(),"proof regular member")
                value=stream.extractfile(member).read();require(pin(value)=={k:row[k] for k in ("bytes","sha256")},"proof whole bytes")
                contents[member.name]=value
            else:require(row["kind"]=="dir" and member.isdir() and member.size==0,"proof directory member")
    require(seen==set(wanted),"complete proof archive set")
    source=decode(contents["recipe-source/SOURCE_MANIFEST.json"])
    require(pin(contents["recipe-source/SOURCE_MANIFEST.json"])==dict(bytes=14714,sha256="3411b63b7bfdcd50e98352933fe0096e3443e1d3ace8f9ecd13e9fbf7194fca6"),"exact qualified domain source manifest")
    for row in source["files"]:
        value=contents["recipe-source/"+row["path"]]
        require(pin(value)=={k:row[k] for k in ("bytes","sha256")} and hashlib.sha1(b"blob "+str(len(value)).encode()+b"\0"+value).hexdigest()==row["git_blob"],"full qualified source identity")
    proof=decode(contents["capture/READONLY.json"]);result=decode(contents["capture/RESULT.json"])
    require(proof["status"]=="READONLY_PASS" and proof["before"]==proof["after"] and len(proof["before"])==proof["entries"]
        and len(proof["probes"])==11 and all(r["rejected"] for r in proof["probes"]),"whole independent before/after guard and probes")
    require(proof["native_executed"] is proof["rust_executed"] is proof["evidence_written"] is False,"passive independent proof")
    require(result["status"]=="PUBLICATION_WORKER_LIFECYCLE_UPLOADED_READONLY_PASS"
        and result["run"]==44084780425 and result["artifact"]==14327464243
        and result["head"]=="e29801ce24c249a074f8c169fc77dd1ffd1cb334"
        and result["evidence"]==proof["evidence"],"exact successful lifecycle identity")
    require(result["zip"]==dict(bytes=126426020,sha256="afd8e353f6a610b85bad888b2feb14aa0ae868e879f1d04a5a20ecdf92ceda50")
        and result["archive"]["archive"]==dict(bytes=125626522,sha256="68973627cc8485fa250974c83950ae525102c3ec5e79b7e6b74da147ed739868"),"whole retained producer archive")
    evidence=proof["evidence"];native=evidence["native"];controls=evidence["controls"]
    require(evidence["status"]=="COMPLETE_PRIVATE_NATIVE_PUBLICATION_WORKER_READ_PASS"
        and native["status"]=="COMPLETE_PRIVATE_NATIVE_WORKER_READ_PASS" and native["cases"]==len(native["rows"])==24,"full actual private native domain")
    rows=native["rows"]
    require([r["case"] for r in rows]==list(range(24)) and sum(r["observer"] for r in rows)==12
        and sum(r["paired"] is not None for r in rows)==16,"all ordered cases, observer pairs and retained original projections")
    require(controls["status"]=="COMPLETE_NATIVE_WORKER_CONTROLS_READ_PASS"
        and controls["physical_mutations"]==4 and controls["relocations"]==2,"full honestly resealed controls and relocation")
    for row in rows:
        j=row["journal"]
        require(j["status"]==("COMPLETE_NATIVE_WORKER_JOURNAL_PASS" if row["observer"] else "OBSERVER_DISABLED_JOURNAL_EMPTY"),"complete actual native journal admission")
        require(row["public_async_qualified"] is False if "public_async_qualified" in row else True,"no public qualification upgrade")
    require(evidence["original_rust_replayed"] is evidence["public_async_qualified"] is evidence["full_sdk"] is False,"scope preservation")
    require(contents["driver.stderr"]==b"","successful passive driver stderr")
    for name in ("capture/READONLY.json","capture/RESULT.json","capture/FILES.json","capture/ARCHIVE.json"):
        (a.output/Path(name).name).write_bytes(contents[name])
    report=dict(status="UPLOADED_PRIVATE_PUBLICATION_LIFECYCLE_PROOF_FULL_BYTES_PASS",
        source_head=result["head"],run=result["run"],artifact=result["artifact"],zip=result["zip"],archive=result["archive"],
        proof_artifact=14328976869,proof_zip=pin(raw),proof_tar=pin(data["evidence.tar.gz"]),
        proof_files=len(index["files"]),proof_directories=len(index["directories"]),proof_logical_bytes=sum(r["bytes"] for r in index["files"]),
        cases=24,observer_on=12,observer_off=12,original_direct_projections=16,
        commands=sum(r["commands"] for r in rows),actual_native_jobs=sum(r["jobs"] for r in rows),
        journal_frames=sum(r["journal"]["frames"] for r in rows),journal_bytes=sum(r["journal"]["bytes"] for r in rows),
        hia_calls=sum(r["journal"].get("hia_calls",0) for r in rows),
        complete_body_logical_bytes=sum(r["journal"].get("complete_body_logical_bytes",0) for r in rows),
        controls=controls,entries=proof["entries"],guard_probes=len(proof["probes"]),elapsed_seconds=result["elapsed_seconds"],
        rows=[dict(case=r["case"],name=r["name"],observer=r["observer"],commands=r["commands"],jobs=r["jobs"],journal=r["journal"],paired=r["paired"]) for r in rows],
        hia_executed=False,rust_executed=False,application_executed=False,public_async_qualified=False,full_sdk=False)
    (a.output/"LIFECYCLE_PROOF.json").write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n")
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
if __name__=="__main__":main()
