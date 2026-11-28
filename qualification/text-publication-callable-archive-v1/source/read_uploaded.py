#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independently read every uploaded proof byte and bind complete readonly snapshots."""
from pathlib import Path,PurePosixPath
from decimal import Decimal
import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import tarfile
import urllib.error
import urllib.request
import zipfile
ARTIFACT=14302606311
ZIP=dict(bytes=869339406,sha256="c1166027579e9ec7f34d2049e762313b7df8d650122378e3a74ec5624d1f19f3")
TAR=dict(bytes=857106913,sha256="6c72b84512d5b9a175e61c81b5c0bda603488a0da261891ffcadd5eb29357bd5")
PROOF=dict(bytes=33933874,sha256="505d509f1a0b60af5bd4b69f8115de4a9026d0f08aab33cc91bbde82d1a2cf87")
SCOPE=dict(private_synchronous_callable=True,public_route=False,configured_path_authority=False,
    scope_cache_forget=False,async_task_lifecycle=False,full_sdk=False,all_136_handlers=False,old_stack_removed=False)
def need(value,message):
    if not value:raise ValueError(message)
def encode(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def decode(raw):
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,"duplicate JSON key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs)
def pin(path):
    with Path(path).open("rb") as f:return dict(bytes=Path(path).stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def download(root):
    request=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(ARTIFACT)+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json"})
    try:urllib.request.build_opener(NoRedirect).open(request,timeout=60)
    except urllib.error.HTTPError as error:need(error.code==302,"artifact redirect differs");url=error.headers["Location"]
    else:raise ValueError("artifact endpoint did not redirect")
    need(url.startswith("https://"),"non-HTTPS artifact redirect")
    path=root/"artifact.zip"
    with urllib.request.urlopen(url,timeout=60) as response,path.open("xb") as file:shutil.copyfileobj(response,file,1<<20)
    need(pin(path)==ZIP,"whole uploaded ZIP differs");return path

def run(output):
    need(os.environ.get("GITHUB_ACTIONS")=="true","independent byte reader restricted to owned CI")
    root=Path(output);need(not root.exists(),"fresh byte-reader output required");root.mkdir(parents=True)
    archive=download(root);zip_rows={}
    with zipfile.ZipFile(archive) as stream:
        entries=stream.infolist()
        need(len(entries)==3 and {r.filename for r in entries}=={"FILES.json","ARCHIVE.json","evidence.tar.gz"},"whole ZIP member set differs")
        for row in entries:
            need(not row.is_dir() and not row.flag_bits&1,"ZIP member type differs")
            path=root/row.filename
            with stream.open(row) as incoming,path.open("xb") as file:shutil.copyfileobj(incoming,file,1<<20)
            need(path.stat().st_size==row.file_size,"ZIP member incomplete");zip_rows[row.filename]=pin(path)
    need(pin(root/"evidence.tar.gz")==TAR,"whole proof tar differs")
    index=decode((root/"FILES.json").read_bytes());items={row["path"]:row for row in index["files"]}
    need(len(items)==len(index["files"])==41747 and sum(r["bytes"] for r in items.values())==2700145462,"complete archive logical set differs")
    need(decode((root/"ARCHIVE.json").read_bytes())==dict(status="COMPLETE_ARCHIVE_BYTES_PASS",files=41747,
        logical_bytes=2700145462,archive=TAR),"archive receipt differs")
    selected={};seen=set();all_rows=[]
    needed={"capture/BASELINE.json","capture/READONLY.json","capture/RESULT.json","capture/restored/RESTORE.json",
        "capture/restored/ARCHIVE.json","capture/restored/extracted/capture/CAPTURE_RESULT.json",
        "capture/restored/extracted/capture/body/native/capture.json",
        "capture/restored/extracted/capture/body/native/carrier-process.json",
        "capture/restored/extracted/capture/native-build/BUILD.json"}
    with tarfile.open(root/"evidence.tar.gz","r:gz") as stream:
        for member in stream:
            p=PurePosixPath(member.name)
            need(member.isfile() and not p.is_absolute() and ".." not in p.parts and p.as_posix()==member.name
                and member.name in items and member.name not in seen,"tar member set/type/path differs")
            seen.add(member.name);row=items[member.name]
            need(member.size==row["bytes"] and member.mode==row["mode"]
                and int(Decimal(member.pax_headers["mtime"])*1000000000)==row["original_mtime_ns"],"full tar metadata differs")
            digest=hashlib.sha256();count=0
            keep=member.name in needed or member.name.startswith("recipe-source/")
            output_file=None
            if keep:
                path=root/"selected"/member.name;path.parent.mkdir(parents=True,exist_ok=True);output_file=path.open("xb")
            try:
                with stream.extractfile(member) as file:
                    for data in iter(lambda:file.read(1<<20),b""):
                        digest.update(data);count+=len(data)
                        if output_file:output_file.write(data)
            finally:
                if output_file:output_file.close()
            need(count==row["bytes"] and digest.hexdigest()==row["sha256"],"complete member bytes differ")
            all_rows.append(dict(path=member.name,bytes=count,sha256=digest.hexdigest(),mode=member.mode))
            if keep:selected[member.name]=root/"selected"/member.name
    need(seen==set(items) and needed<=set(selected),"complete proof archive omitted file")
    proof=decode(selected["capture/READONLY.json"].read_bytes());summary=decode(selected["capture/RESULT.json"].read_bytes())
    need(pin(selected["capture/READONLY.json"])==PROOF,"complete uploaded readonly proof differs")
    need(proof["status"]=="READONLY_PASS" and proof["native_executed"] is False and proof["rust_executed"] is False
        and proof["evidence_written"] is False and proof["before"]==proof["after"]
        and len(proof["before"])==proof["entries"]==48303,"readonly proof metadata/byte stability differs")
    names=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
    need(proof["probes"]==[dict(name=n,rejected=True) for n in names],"guard rejection set differs")
    mappings={}
    for number,path in enumerate(proof["roots"]):
        if path.endswith("/qualification/text-publication-callable-readback-v1/source"):mappings[number]="recipe-source"
        elif path.endswith("/text-publication-callable-readback/restored"):mappings[number]="capture/restored"
        elif path.endswith("/text-publication-callable-readback/physical-controls"):mappings[number]="capture/physical-controls"
        else:raise ValueError("unknown actual readonly root")
    need(len(mappings)==3 and len(set(mappings.values()))==3,"readonly roots missing/duplicate")
    snapshot_files={};snapshot_entries=set()
    for row in proof["before"]:
        key=(row["root"],row["path"]);need(key not in snapshot_entries and row["root"] in mappings,"snapshot duplicate/foreign root")
        snapshot_entries.add(key);p=PurePosixPath(row["path"])
        need((row["path"]=="." or not p.is_absolute() and ".." not in p.parts and p.as_posix()==row["path"])
            and row["dev"]>=0 and row["inode"]>0 and row["links"]>=1,"snapshot identity invalid")
        if stat.S_ISDIR(row["mode"]):continue
        need(stat.S_ISREG(row["mode"]),"snapshot nonordinary file")
        name=mappings[row["root"]]+"/"+row["path"];need(name in items and name not in snapshot_files,"snapshot file omitted/duplicated")
        need(items[name]["bytes"]==row["bytes"] and items[name]["sha256"]==row["sha256"]
            and items[name]["mode"]==row["mode"]&0o777 and items[name]["original_mtime_ns"]==row["mtime_ns"],
            "complete archive file differs from actual guarded snapshot")
        snapshot_files[name]=row
    wanted={name for name in items if any(name.startswith(prefix+"/") for prefix in mappings.values())}
    need(set(snapshot_files)==wanted,"snapshot did not cover complete archived roots")
    evidence=proof["evidence"]
    need(evidence["status"]=="COMPLETE_PRIVATE_CALLABLE_ORIGINAL_FILES_JOURNAL_PASS" and evidence["cases"]==82
        and evidence["original_tests"]==8 and evidence["registry_packages"]==33 and evidence["scope"]==SCOPE
        and evidence["full_wire_and_filesystem_equal"] is True and evidence["per_body_call_workspace_before_after_captured"] is False,
        "qualified callable domain/scope differs")
    base=decode(selected["capture/BASELINE.json"].read_bytes())
    need({k:v for k,v in evidence.items() if k not in ("physical_controls","retained_archive")}==base,"guarded full comparison differs from prior complete read")
    controls=evidence["physical_controls"]
    need(controls["native_or_rust_executed"] is False and [r["name"] for r in controls["controls"]]==[
        "changed-image","extra-original-wire","changed-context-buffer","changed-control","resigned-journal-tail","resigned-journal-sequence"]
        and all(r["rejected"] is True for r in controls["controls"]),"physical reader controls differ")
    need(summary["status"]==evidence["status"] and summary["readback"]==PROOF and summary["unchanged_entries"]==48303
        and summary["physical_reader_controls"]==6 and summary["guard_probes"]==11 and summary["scope"]==SCOPE
        and summary["native_executed"] is False and summary["rust_executed"] is False,"final readback summary differs")
    source=root/"selected/recipe-source";manifest=decode((source/"SOURCE_MANIFEST.json").read_bytes())
    need(pin(source/"SOURCE_MANIFEST.json")==dict(bytes=2314,sha256="0daba1b773cb31a04f15eb2519c167416fa589b754003cfb49c9aba3a3af6f25")
        and len(manifest["files"])==9,"independent exact reader source differs")
    for row in manifest["files"]:
        raw=(source/row["path"]).read_bytes()
        need(len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
            and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"full reader Git source differs")
    physical=evidence["physical"]
    need(physical["cases"]==82 and physical["controls"]==30 and physical["two_contexts"] is True
        and physical["borrow_release_observed"] is True,"native context/control domain differs")
    result=dict(status="INDEPENDENT_COMPLETE_CALLABLE_ARCHIVE_AND_READONLY_PROOF_PASS",
        artifact=ARTIFACT,zip=ZIP,tar=TAR,zip_members=zip_rows,files=41747,logical_bytes=2700145462,
        complete_archive_file_index="FILES.json",actual_guard_snapshot_files=len(snapshot_files),unchanged_entries=48303,
        guard_probes=11,physical_reader_controls=6,physical=physical,scope=SCOPE,
        native_executed=False,rust_executed=False,qualified_capture_commit="0162ff08a3988fe33247ef6ab484b8e3e8f656ea",
        qualified_readback_commit="59501211af64ea74b8d898f6fd3c42aee32a55ba")
    (root/"INDEPENDENT.json").write_bytes(encode(result));(root/"FULL_READ_INDEX.json").write_bytes(encode(all_rows))
    print(json.dumps(result,sort_keys=True))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.output.absolute())
if __name__=="__main__":main()
