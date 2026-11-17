#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Frozen source identity for the real public publication worker graph."""
from pathlib import Path
import hashlib,json,stat,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"previous-build/retained-build"))
from read_primitives import require,pin,raw,doc,sha,files
PRODUCTION="a4d92ceadabb59376088be7301f26b06e44cf849"
FRESH=frozenset(("mcp","publisher_call","extract_gateway","publisher_worker"))
def put(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def blob(value):return hashlib.sha1(b"blob "+str(len(value)).encode()+b"\0"+value).hexdigest()
def package():
    root=HERE.parent
    m=doc(root/"SOURCE_MANIFEST.json")
    actual={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual=={r["path"] for r in m["files"]}|{"SOURCE_MANIFEST.json"},"complete recipe file set")
    for r in m["files"]:
        p=root/r["path"];v=raw(p)
        require(not p.is_symlink() and pin(p)=={k:r[k] for k in ("bytes","sha256")}
            and blob(v)==r["git_blob"] and stat.S_IMODE(p.stat().st_mode)==0o644,"recipe source: "+r["path"])
        if p.suffix==".py":compile(v,str(p),"exec")
    return {"manifest":pin(root/"SOURCE_MANIFEST.json"),"files":len(actual)}
def source_files(root,*,complete=True):
    root=Path(root).resolve(strict=True);index=doc(HERE/"PRODUCTION_ROWS.json")
    require(index["commit"]==PRODUCTION and len(index["rows"])==525,"frozen production identity")
    wanted={r["path"]:r for r in index["rows"]}
    if complete:require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}==set(wanted),"complete actual graph source set")
    for name,row in wanted.items():
        p=root/name
        require(not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o644 and pin(p)=={k:row[k] for k in ("bytes","sha256")} and blob(raw(p))==row["git_blob"],"production bytes/mode: "+name)
    binding=doc(root/"native/runtime_mcp_sources.json")
    require(binding["sources"]=={p:{k:r[k] for k in ("bytes","sha256")} for p,r in wanted.items() if p!="native/runtime_mcp_sources.json"},"complete runtime binding")
    return wanted
