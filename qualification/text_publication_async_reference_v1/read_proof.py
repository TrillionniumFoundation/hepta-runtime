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
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14322672745/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:incoming=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as e:
        require(e.code in (301,302,303,307,308),"artifact redirect")
        url=e.headers["Location"];require(urllib.parse.urlparse(url).scheme=="https","HTTPS artifact")
        incoming=urllib.request.urlopen(url,timeout=60)
    with incoming:raw=incoming.read()
    require(pin(raw)==dict(bytes=1684889,sha256="9ab3ae41ffe0bd7e07c07152fd760fa4998086219c7d727b9f569dc0a96281d4"),"full immutable proof ZIP")
    (a.output/"proof.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"} and z.testzip() is None,"complete proof ZIP set")
        data={name:z.read(name) for name in z.namelist()}
    require(pin(data["evidence.tar.gz"])==dict(bytes=1677923,sha256="d1dffa799e40894a5a4c84713403de99dd1f82f1ccebd9551e086ea3ba000849"),"full proof TAR")
    index=decode(data["FILES.json"]);rows=index["files"]+index["directories"]
    wanted={r["path"]:r for r in rows};seen=set();contents={}
    require(len(wanted)==len(rows) and len(index["files"])==29 and len(index["directories"])==4,"complete proof archive index")
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
    require(pin(contents["recipe-source/SOURCE_MANIFEST.json"])==dict(bytes=5619,sha256="d7f8b8a2f00eed741332a8e386a4fae74825c188969dd22d3bf5370e3528f795"),"exact qualified domain source manifest")
    for row in source["files"]:
        value=contents["recipe-source/"+row["path"]]
        require(pin(value)=={k:row[k] for k in ("bytes","sha256")} and hashlib.sha1(b"blob "+str(len(value)).encode()+b"\0"+value).hexdigest()==row["git_blob"],"full qualified source identity")
    proof=decode(contents["capture/READONLY.json"]);result=decode(contents["capture/RESULT.json"])
    require(proof["status"]=="READONLY_PASS" and proof["before"]==proof["after"] and len(proof["before"])==proof["entries"]==8733
        and len(proof["probes"])==11 and all(r["rejected"] for r in proof["probes"]),"complete retained independent guard proof")
    require(proof["native_executed"] is proof["rust_executed"] is proof["evidence_written"] is False,"retained reader has no execution")
    require(result["status"]=="PUBLISHER_ASYNC_REFERENCE_UPLOADED_READONLY_PASS" and result["evidence"]==proof["evidence"]
        and result["artifact"]==14322262900 and result["head"]=="ae6206b4d8b6ffa347e7cadd8fb97a5a07946a03","complete actual reference proof")
    observed=proof["evidence"]["original"];require(observed["cases"]==30 and observed["full_domain"],"complete original30")
    require(proof["evidence"]["physical_controls"]["mutations"]==8 and proof["evidence"]["physical_controls"]["relocations"]==2,"full physical control domain")
    report=dict(status="UPLOADED_PROOF_FULL_BYTES_PASS",source_head=result["head"],run=result["run"],artifact=result["artifact"],
        original_archive=result["archive"],original_zip=result["zip"],original=observed,
        uploaded_proof_zip=pin(raw),uploaded_proof_tar=pin(data["evidence.tar.gz"]),proof_result=pin(contents["capture/RESULT.json"]),
        proof_file_count=29,proof_directory_count=4,proof_logical_bytes=sum(r["bytes"] for r in index["files"]),
        hia_executed=False,rust_executed=False,application_executed=False)
    (a.output/"OBSERVATIONS.json").write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n")
    for row in observed["rows"]:
        summary={k:row[k] for k in ("case","name","era","mode","commands","observed_futures","returned","dropped_without_return","response_lines","final_files","final_cache")}
        summary["events"]=[r for r in row["final_events"] if r["event"] in ("entered","returned","dropped","serve_finished","runtime_drop_begin","runtime_drop_complete")]
        print("OBSERVATION "+json.dumps(summary,ensure_ascii=False,sort_keys=True,separators=(",",":")),flush=True)
    print(json.dumps({k:v for k,v in report.items() if k!="original"},sort_keys=True))
if __name__=="__main__":main()
