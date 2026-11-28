#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Source and ordinary-file identity for the fixed borrowed-parent publication callable."""
from pathlib import Path,PurePosixPath
import ast
import hashlib
import json
import stat
HEPTA="d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
SCOPE=dict(private_synchronous_callable=True,borrowed_parent_publication=True,
    unchanged_stat_metadata_codec_children=True,qualified_dual_filename_errors=True,no_borrowed_parent_dup_or_close=True,
    original_regular_fstat_orphan_transition=True,shared_process_orphan_primitive=True,
    effect_notification_fixture=True,actual_seccomp_fixture=True,structured_error_fixture=True,
    public_route=False,configured_path_authority=False,original_filesystem_qualified=False,
    scope_cache_forget=False,async_task_lifecycle=False,full_sdk=False,all_136_handlers=False,
    old_stack_removed=False)
def require(v,m):
    if not v:raise ValueError(m)
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def decode(raw):
    def pairs(items):
        out={}
        for k,v in items:require(k not in out,"duplicate JSON key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs)
def pin(path):
    with Path(path).open("rb") as f:return dict(bytes=Path(path).stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def owned(root,name):
    p=PurePosixPath(name);require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"bad source path")
    here=Path(root)
    for part in p.parts:
        here=here/part;require(not here.is_symlink(),"symlink source")
    require(stat.S_ISREG(here.stat().st_mode),"non-ordinary source")
    return here
def sources(root):
    root=Path(root);manifest=decode(owned(root,"SOURCE_MANIFEST.json").read_bytes())
    actual={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    rows=manifest["files"]
    require(actual=={r["path"] for r in rows}|{"SOURCE_MANIFEST.json"} and len(rows)==len(actual)-1,"source closure differs")
    for row in rows:
        path=owned(root,row["path"]);raw=path.read_bytes()
        require(pin(path)=={k:row[k] for k in ("bytes","sha256")} and blob(raw)==row["git_blob"]
            and path.stat().st_mode&0o777==0o644,"source bytes/mode differ: "+row["path"])
    return dict(manifest=pin(root/"SOURCE_MANIFEST.json"),files=len(rows),scope=SCOPE)
def syntax(root):
    result=sources(root);count=0
    for p in Path(root).rglob("*"):
        if p.is_file() and p.suffix in (".py",".pseudo"):ast.parse(p.read_bytes(),filename=str(p));count+=1
    import native_source
    derivation=native_source.verify(root)
    return dict(status="SOURCE_ONLY_PASS",source=result,python_sources=count,native_derivation=derivation)
