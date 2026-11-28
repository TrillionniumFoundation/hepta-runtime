#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Frozen input and complete ordinary evidence identities; no native execution."""
from pathlib import Path,PurePosixPath
import hashlib,json,stat
TARGET="d3d75c30719db966b004756f610007a7c723729e"
HEPTA="d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
SCOPE=dict(private_error_formatter=True,linux_errno_1_to_4095=True,unicode_scalar_repr=True,
    original_python_diagnostics_compared=True,host_formatter_python_required=False,
    host_formatter_libc_required=False,read_gateway_integrated=False,remote_transport=False,
    public_routes=False,whole_runtime_replaced=False)
def require(v,m):
    if not v:raise ValueError(m)
def canonical(v):return(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()
encoded=canonical
def decode(raw):
    def unique(rows):
        out={}
        for k,v in rows:require(k not in out,"duplicate evidence key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError("nonfinite evidence")))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def owned(root,name):
    p=PurePosixPath(name)
    require(type(name)is str and name and p.as_posix()==name and not p.is_absolute() and ".."not in p.parts,"unowned relative evidence path")
    path=Path(root)/name
    require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),"ordinary evidence file required")
    return path
_CACHE={}
def pin(path):
    path=Path(path);before=path.stat()
    key=(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_nlink,
        before.st_size,before.st_mtime_ns,before.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode),"ordinary retained bytes required")
    if key not in _CACHE:
        with path.open("rb")as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
        after=path.stat()
        require(key==(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_nlink,
            after.st_size,after.st_mtime_ns,after.st_ctime_ns),"retained file changed")
        _CACHE[key]=digest
    return dict(bytes=before.st_size,sha256=_CACHE[key])
def source_evidence(source):
    source=Path(source);manifest=decode(owned(source,"SOURCE_MANIFEST.json").read_bytes());rows=manifest["files"]
    require(len({r["path"]for r in rows})==len(rows),"duplicate source")
    actual={p.relative_to(source).as_posix()for p in source.rglob("*")if p.is_file()}
    require(actual=={r["path"]for r in rows}|{"SOURCE_MANIFEST.json"},"source file set differs")
    for row in rows:
        path=owned(source,row["path"]);raw=path.read_bytes()
        require(dict(bytes=len(raw),sha256=sha(raw))=={k:row[k]for k in("bytes","sha256")}
            and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"]
            and row["mode"]=="100644"and stat.S_IMODE(path.stat().st_mode)==0o644,"frozen source bytes/mode differ")
    return dict(manifest=pin(source/"SOURCE_MANIFEST.json"),files=len(rows),target=TARGET,scope=SCOPE)
