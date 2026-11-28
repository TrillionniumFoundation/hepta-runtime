#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete file/byte/mode archive with lossless content deduplication."""
from pathlib import Path
import argparse
import hashlib
import io
import os
import stat
import sys
import tarfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require

def identity(path):
    require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),"ordinary archive file required")
    return dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
def inventory(root):
    files={};directories={}
    for path in [root,*sorted(root.rglob("*"))]:
        mode=path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode),"archive contains non-ordinary entry")
        name="." if path==root else path.relative_to(root).as_posix()
        if stat.S_ISDIR(mode):directories[name]=stat.S_IMODE(mode)
        else:files[name]=identity(path)
    return files,directories
def export(capture,archive):
    require(not archive.exists() and not archive.is_relative_to(capture) and not archive.is_relative_to(ROOT),"archive must be fresh and external")
    files={};directories={};objects={};paths={}
    for prefix,folder in (("source",ROOT),("run",capture)):
        regular,dirs=inventory(folder)
        directories.update({prefix if name=="." else prefix+"/"+name:mode for name,mode in dirs.items()})
        for name,value in regular.items():
            logical=prefix+"/"+name
            key="objects/"+value["sha256"]+"-"+format(value["mode"],"03o")
            files[logical]=dict(**value,object=key);paths[logical]=folder/name
            if key in objects:require(objects[key]["identity"]==value,"duplicate object identity mismatch")
            else:objects[key]=dict(identity=value,path=folder/name)
    gate=decode((capture/"GATE.json").read_bytes()) if (capture/"GATE.json").exists() else dict(status="NO_GATE_RECORD")
    metadata=dict(schema="hepta.runtime.binary-params.complete-archive.v1",
        git_head=os.environ.get("GITHUB_SHA"),run_id=os.environ.get("GITHUB_RUN_ID"),
        source_manifest=files["source/SOURCE_MANIFEST.json"],gate_status=gate["status"],
        files=files,directories=directories,native_or_rust_executions=0,whole_runtime_replaced=False)
    raw=canonical(metadata)
    archive.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive,"w:gz",compresslevel=1,dereference=True) as target:
        for name,row in sorted(objects.items()):
            require(identity(row["path"])==row["identity"],"source object changed before packing")
            info=tarfile.TarInfo(name);info.size=row["identity"]["bytes"];info.mode=row["identity"]["mode"]
            with row["path"].open("rb") as stream:target.addfile(info,stream)
        info=tarfile.TarInfo("artifact-manifest.json");info.size=len(raw);info.mode=0o644
        target.addfile(info,io.BytesIO(raw))
    observed={}
    with tarfile.open(archive,"r|gz") as source:
        while member:=source.next():
            require(member.isfile() and member.name not in observed,"archive member kind or duplicate invalid")
            with source.extractfile(member) as stream:
                digest=hashlib.file_digest(stream,"sha256").hexdigest()
            observed[member.name]=dict(bytes=member.size,sha256=digest,mode=member.mode)
            source.members.clear()
    expected={name:row["identity"] for name,row in objects.items()}
    expected["artifact-manifest.json"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=0o644)
    require(observed==expected,"complete written object readback differs")
    for name,value in files.items():
        require(identity(paths[name])==observed[value["object"]]=={k:value[k] for k in ("bytes","sha256","mode")},
            "complete logical file differs after archive write")
    for prefix,folder in (("source",ROOT),("run",capture)):
        got,dirs=inventory(folder)
        require({prefix+"/"+p:v for p,v in got.items()}==
            {p:{k:v[k] for k in ("bytes","sha256","mode")} for p,v in files.items() if p.startswith(prefix+"/")},
            "archive file set changed")
        require({prefix if p=="." else prefix+"/"+p:m for p,m in dirs.items()}==
            {p:m for p,m in directories.items() if p==prefix or p.startswith(prefix+"/")},"archive directory set changed")
    result=dict(schema="hepta.runtime.binary-params.complete-archive-read.v1",archive=archive.name,
        **identity(archive),unique_objects=len(objects),logical_files=len(files),directories=len(directories),
        logical_bytes=sum(v["bytes"] for v in files.values()),unique_bytes=sum(v["identity"]["bytes"] for v in objects.values()),
        gate_status=gate["status"],all_object_bytes_and_modes_reread=True,
        all_logical_files_and_directories_bound=True,native_or_rust_executions=0,whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix+".json").write_bytes(canonical(result))
    print(canonical(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True);p.add_argument("--archive",type=Path,required=True)
    a=p.parse_args();export(a.capture.resolve(strict=True),a.archive.absolute())
