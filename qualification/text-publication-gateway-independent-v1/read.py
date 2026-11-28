#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent full uploaded proof and guarded reconstruction. No HIA/Rust execution."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import importlib
import json
import os
import shutil
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
sys.dont_write_bytecode=True
ARTIFACT=14308583229
ZIP=dict(bytes=10560823,sha256="09fab0b21e3bc0f7c6548caa648f7e5e7e225243dda169684c892ee87efe3829")
TAR=dict(bytes=9241157,sha256="b1f3ad7bc6dc3417618ef11c6feada77f321787d226091442b84dca0af43e0aa")
COUNT=4866
LOGICAL=66594415
SOURCE=dict(bytes=18779,sha256="920a2b17cd081af6f46df61485452bf399d99d99ed3f01172b4fb3545fc7ba6a")
def require(value,message):
    if not value:raise ValueError(message)
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def pin(path):
    with path.open("rb") as stream:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(stream,"sha256").hexdigest())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def download(path):
    request=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(ARTIFACT)+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(NoRedirect()).open(request,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact redirect")
        destination=error.headers["Location"];require(urllib.parse.urlparse(destination).scheme=="https","artifact HTTPS")
        response=urllib.request.urlopen(destination,timeout=60)
    with response,path.open("xb") as out:shutil.copyfileobj(response,out,1<<20)
    require(pin(path)==ZIP,"whole uploaded ZIP")
def relative(name):
    p=PurePosixPath(name);return not p.is_absolute() and ".." not in p.parts and p.as_posix()==name
def extract(root):
    root.mkdir()
    archive=root/"artifact.zip";download(archive)
    with zipfile.ZipFile(archive) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"},"ZIP full set")
        for info in z.infolist():
            require(not info.is_dir() and info.flag_bits&1==0,"ordinary unencrypted ZIP member")
            with z.open(info) as incoming,(root/info.filename).open("xb") as out:shutil.copyfileobj(incoming,out,1<<20)
    require(pin(root/"evidence.tar.gz")==TAR,"whole uploaded TAR")
    index=json.loads((root/"FILES.json").read_bytes());receipt=json.loads((root/"ARCHIVE.json").read_bytes())
    require(receipt["archive"]==TAR,"producer archive record")
    rows={x["path"]:x for x in index["files"]}
    require(len(rows)==len(index["files"])==COUNT and sum(x["bytes"] for x in rows.values())==LOGICAL
        and all(relative(x) for x in rows),"complete member index")
    dest=root/"extracted";dest.mkdir();seen=set()
    with tarfile.open(root/"evidence.tar.gz","r|gz") as stream:
        for member in stream:
            require(member.isfile() and member.name in rows and member.name not in seen,"ordinary complete TAR set")
            record=rows[member.name];target=dest/member.name;target.parent.mkdir(parents=True,exist_ok=True)
            with stream.extractfile(member) as incoming,target.open("xb") as out:
                digest=hashlib.sha256()
                while block:=incoming.read(1<<20):digest.update(block);out.write(block)
            target.chmod(member.mode)
            require(member.size==record["bytes"] and member.mode==record["mode"] and digest.hexdigest()==record["sha256"],
                "complete member bytes/mode")
            seen.add(member.name)
    require(seen==set(rows),"missing TAR members")
    source=dest/"recipe-source";capture=dest/"capture"
    require(pin(source/"SOURCE_MANIFEST.json")==SOURCE,"exact qualified reader source")
    # Ordinary-file-only exporters omit truly empty stores. Reconstruct exactly
    # the proven producer destinations, before the new read-only snapshot.
    profiles=("configured","absent","denied","fence_required","capabilities","body")
    controls=("missing-record","changed-input","changed-full-buffer","changed-cache-result","changed-scope-lifetime",
        "truncated-private-trace","unknown-private-trace","changed-forget-return","changed-file-mode","extra-original-output")
    roots=[capture/"selected/capture/profiles"/p for p in profiles]
    for move in ("one","two/deeper"):roots.extend(capture/"relocations"/move/"capture/profiles"/p for p in profiles)
    roots.extend(capture/"physical-controls"/name/"capture" for name in controls)
    require(set(capture.rglob("RETIRED_FIXTURE.json"))=={p/"RETIRED_FIXTURE.json" for p in roots},
        "complete retired fixture identity set")
    restored=[]
    for holder in roots:
        target=holder/"retired-fixture-buffers"
        if target.exists():continue
        snapshot=holder/"RETIRED_FIXTURE.json";value=json.loads(snapshot.read_bytes())
        def empty(x):
            if isinstance(x,dict):
                if "blocks" in x:require(set(x)=={"bytes","sha256","blocks"} and x["bytes"]==0 and x["blocks"]==[]
                    and x["sha256"]==hashlib.sha256(b"").hexdigest(),"omitted store has complete bytes")
                for y in x.values():empty(y)
            elif isinstance(x,list):
                for y in x:empty(y)
        empty(value["complete_snapshot"])
        prefix=target.relative_to(dest).as_posix()+"/"
        require(not any(name.startswith(prefix) for name in rows),"omitted store had a TAR member")
        target.mkdir();restored.append(dict(path=target.relative_to(dest).as_posix(),snapshot=pin(snapshot)))
    (root/"EMPTY_STORES.json").write_bytes(encoded(restored))
    return source,capture
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    require(not a.output.exists(),"new independent read root");a.output.mkdir(parents=True)
    source,capture=extract(a.output/"archive")
    sys.path[:0]=[str(source/"recipe"),str(source)]
    q=importlib.import_module("review_retained")
    controls=importlib.import_module("gateway_reader_controls")
    readonly=importlib.import_module("readonly")
    common=importlib.import_module("common")
    common.source_evidence(source)
    producer=json.loads((capture/"READONLY.json").read_bytes())
    require(producer["status"]=="READONLY_PASS" and producer["before"]==producer["after"] and producer["entries"]==5143
        and len(producer["probes"])==11 and all(x["rejected"] is True for x in producer["probes"])
        and producer["native_executed"] is False and producer["rust_executed"] is False
        and producer["evidence_written"] is False,"complete producer guard proof")
    selected=capture/"selected";baseline=controls.inventory(selected)
    reloc=json.loads((capture/"RELOCATIONS.json").read_bytes())
    require(reloc["baseline"]==baseline and reloc["complete_bytes_and_modes"] is True
        and len(reloc["copies"])==2 and reloc["native_executed"] is False and reloc["rust_executed"] is False,
        "complete producer relocation custody")
    original=json.loads((capture/"REVIEW.json").read_bytes())
    require(original["artifact"]==14308301274 and original["run"]==44037633975 and original["files"]==16845
        and original["logical_bytes"]==2943583972 and original["executed_hia"] is False and original["executed_rust"] is False
        and original["zip"]==dict(bytes=1989315830,sha256="de313d2042984fc611c3b638a83495c0813d01faac0f1e6997d2a4264221c8ed"),
        "full original execution archive custody")
    original_rows={r["path"]:r for r in json.loads((capture/"FILES.json").read_bytes())["files"]}
    require(len(original_rows)==16845,"original full index set")
    for path in selected.rglob("*"):
        if not path.is_file():continue
        name=path.relative_to(selected).as_posix();row=original_rows[name]
        require(pin(path)=={key:row[key] for key in ("bytes","sha256")} and path.stat().st_mode&0o777==row["mode"],
            "selected execution bytes differ from original complete index")
    def whole():
        primary=q.compare(source,selected)
        negative=controls.verify(selected/"capture/profiles/configured",capture/"physical-controls")
        moved=[]
        for name in ("one","two/deeper"):
            root=capture/"relocations"/name
            require(controls.inventory(root)==baseline,"complete relocated bytes/mode")
            moved.append(q.compare(source,root))
        actual=dict(status="COMPLETE_GATEWAY191_PHYSICAL_CONTROLS_RELOCATION_PASS",primary=primary,
            physical_controls=negative,relocations=moved,hia_executed=False,rust_executed=False,
            public_route=False,full_async=False,full_sdk=False)
        require(common.canonical(actual)==common.canonical(producer["evidence"]),"whole independent result differs")
        return actual
    result=readonly.guarded(whole,roots=(source,capture))
    (a.output/"INDEPENDENT_READONLY.json").write_bytes(encoded(result))
    summary=dict(status="COMPLETE_UPLOADED_GATEWAY191_INDEPENDENT_READ_PASS",artifact=ARTIFACT,
        zip=ZIP,archive=TAR,files=COUNT,logical_bytes=LOGICAL,source=SOURCE,
        original_execution_run=44037633975,qualified_read_run=44039747901,cases=191,
        physical_controls=10,relocations=2,independent_guard_probes=len(result["probes"]),
        independent_guard_entries=result["entries"],native_executed=False,rust_executed=False,
        public_route=False,full_async=False,full_sdk=False,production_installed=False)
    (a.output/"SUMMARY.json").write_bytes(encoded(summary))
    print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
