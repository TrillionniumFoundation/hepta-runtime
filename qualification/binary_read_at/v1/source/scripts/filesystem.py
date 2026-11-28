#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual fixture creation and complete observations, outside the implementation."""
from pathlib import Path
import os,stat
from common import require
from cases import domain
DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
def data(case):
    period=bytes((n*73+case["seed"])%256 for n in range(256))
    return (period*((case["size"]+255)//256))[:case["size"]]
def version(row):
    return ":".join(str(row[k])for k in("dev","inode","size","mtime_ns","ctime_ns"))
def selected(case):
    return {"file":"data.bin","sidecar":".hepta-hidden","unicode":"snow-雪-é.bin","control":"line-\n-\x01.bin",
        "missing":"absent","directory":"dir","fifo":"pipe","symlink":"link","hardlink":"hard.bin",
        "empty":"","nul":"data\x00.bin","dot":".","dotdot":"..","long":"x"*260}[case["path"]]
def create(root,case):
    root.mkdir(parents=True);parent=root/"parent";parent.mkdir()
    raw=data(case)
    def write(name,value):
        with (parent/name).open("xb")as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
        (parent/name).chmod(case["permissions"])
    write("data.bin",raw)
    name=selected(case)
    if case["path"]in("sidecar","unicode","control"):write(name,raw)
    (parent/"dir").mkdir()
    if case["path"]=="fifo":os.mkfifo(parent/"pipe",0o600)
    if case["path"]=="symlink":os.symlink("data.bin",parent/"link")
    if case["path"]=="hardlink":os.link(parent/"data.bin",parent/"hard.bin")
    if case["mutation"]=="replace":write("replacement.bin",bytes([199])*len(raw))
def describe(root,case,rows):
    root=Path(root).absolute();parent=root/"parent";name=selected(case)
    selected_row=rows.get("parent/"+name,rows["parent/data.bin"])
    ver=version(selected_row)
    request=dict(name=name,root=str(parent),path=str(parent)+"/"+name,
        op={"read":"read","fingerprint":"fingerprint","private":"private_read"}[case["mode"]])
    if case["mode"]=="read":
        request.update(offset=case.get("offset",0),limit=case.get("limit",32768),
            expected_version=ver if case.get("expected")=="current"else "different"if case.get("expected")=="different"else None)
    return dict(id=case["id"],name=case["name"],mode=case["mode"],entry=case["entry"],
        fixture=str(root),parent=str(parent),request=request,mutation=case["mutation"],fd_limit=case["fd_limit"],
        initial_version=ver,snapshot=rows)
def metadata(st):
    return dict(mode=st.st_mode,uid=st.st_uid,gid=st.st_gid,dev=st.st_dev,inode=st.st_ino,
        links=st.st_nlink,size=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)
def snapshot(root,store):
    rows={};fd=os.open(root,DIR)
    def walk(parent,prefix):
        rows[prefix]=dict(kind="directory",**metadata(os.fstat(parent)))
        for name in sorted(os.listdir(parent)):
            st=os.stat(name,dir_fd=parent,follow_symlinks=False)
            logical=name if prefix=="."else prefix+"/"+name
            if stat.S_ISDIR(st.st_mode):
                child=os.open(name,DIR,dir_fd=parent)
                try:walk(child,logical)
                finally:os.close(child)
            elif stat.S_ISREG(st.st_mode):
                f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                try:
                    blocks=[]
                    while part:=os.read(f,1<<20):blocks.append(part)
                    raw=b"".join(blocks)
                    require(metadata(os.fstat(f))==metadata(st),"fixture changed during complete snapshot")
                finally:os.close(f)
                rows[logical]=dict(kind="file",content=store.put(raw),**metadata(st))
            elif stat.S_ISLNK(st.st_mode):
                rows[logical]=dict(kind="symlink",target=os.readlink(name,dir_fd=parent),**metadata(st))
            else:
                require(stat.S_ISFIFO(st.st_mode),"unexpected fixture kind")
                rows[logical]=dict(kind="fifo",**metadata(st))
    try:walk(fd,".")
    finally:os.close(fd)
    return rows
