#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual owned fixtures and complete descriptor-relative byte/metadata snapshots."""
from pathlib import Path
import os,stat
from common import require
from cases import domain,expand
DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
def version(st):return ":".join(map(str,(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)))
def data(case):
    count=case["size"];seed=case["seed"]
    block=bytes((i*73+seed)&255 for i in range(256))
    return(block*((count+255)//256))[:count]
def create(root,case):
    root=Path(root);require(not root.exists(),"fixture must be fresh")
    root.mkdir(parents=True,mode=0o755)
    raw=data(case);mode=case.get("permissions",0o644);fd=os.open(root,DIR)
    def write(parent,name):
        f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,mode,dir_fd=parent)
        try:
            os.fchmod(f,mode);pending=memoryview(raw)
            while pending:
                n=os.write(f,pending);require(n>0,"fixture write progress");pending=pending[n:]
            os.fsync(f);return os.fstat(f)
        finally:os.close(f)
    try:
        st=write(fd,"data.bin");selected=st
        os.mkdir("dir",0o755,dir_fd=fd)
        path=case["path"];names=domain()["fixtures"]
        if path in("unicode","control","sidecar","nested-sidecar"):
            name=names[path]if path in("unicode","control")else".hepta-hidden"
            if path=="nested-sidecar":
                d=os.open("dir",DIR,dir_fd=fd)
                try:selected=write(d,name)
                finally:os.close(d)
            else:selected=write(fd,name)
        if path=="hardlink":
            os.link("data.bin","hard.bin",src_dir_fd=fd,dst_dir_fd=fd)
            selected=os.stat("hard.bin",dir_fd=fd,follow_symlinks=False)
        if path=="fifo":os.mkfifo("pipe",0o600,dir_fd=fd)
        if path=="symlink":os.symlink("data.bin","link",dir_fd=fd)
        if path=="symlink-parent":
            d=os.open("dir",DIR,dir_fd=fd)
            try:write(d,"data.bin")
            finally:os.close(d)
            os.symlink("dir","linkdir",dir_fd=fd)
        long=[]
        if path=="long-path":
            parent=os.dup(fd)
            try:
                for n in range(names["long_path_components"]):
                    name="d"*(names["long_path_component_bytes"]-4)+str(n).zfill(4);long.append(name)
                    os.mkdir(name,0o755,dir_fd=parent);child=os.open(name,DIR,dir_fd=parent);os.close(parent);parent=child
                selected=write(parent,"leaf.bin")
            finally:os.close(parent)
    finally:os.close(fd)
    return describe(root,case,selected,long)
def describe(root,case,selected,long):
    base=str(root.absolute());root_kind=case["root"]
    roots=dict(base=base,empty="",relative="relative",parent=base+"/..",other=base+"/other",
        prefix=base[:-1],file=base+"/data.bin",dots=base+"/./",slashes=base.replace("/","///"),
        double="/"+base,triple="//"+base,slash="/",**{"double-slash":"//"})
    paths=dict(file=base+"/data.bin",empty="",relative="data.bin",parent=base+"/../data.bin",
        root=base,sidecar=base+"/.hepta-hidden",**{"nested-sidecar":base+"/dir/.hepta-hidden",
        "missing":base+"/absent","missing-parent-nul":base+"/absent/leaf\0",
        "regular-parent":base+"/data.bin/leaf","directory":base+"/dir","fifo":base+"/pipe",
        "symlink":base+"/link","symlink-parent":base+"/linkdir/data.bin","nul":base+"/data\0.bin",
        "nul-parent":base+"/di\0r/data.bin","dots":base+"/./data.bin",
        "slashes":base.replace("/","///")+"//data.bin","double":"/"+base+"/data.bin",
        "triple":"//"+base+"/data.bin","unicode":base+"/"+domain()["fixtures"]["unicode"],
        "control":base+"/"+domain()["fixtures"]["control"],"long-component":base+"/"+"x"*260,
        "long-path":base+"/"+"/".join(long)+"/leaf.bin","hardlink":base+"/hard.bin"})
    expected=case["expected"];ver=version(selected)
    versions=dict(none=None,current=ver,empty="",mismatch="different",noncanonical="0"+ver,nul="\0",unicode="雪")
    request=dict(root=roots[root_kind],path=paths[case["path"]],op={"read":"read","private":"private_read","fingerprint":"fingerprint"}[case["mode"]])
    if case["mode"]=="read":request.update(offset=expand(case["offset"]),limit=expand(case["limit"]),expected_version=versions[expected])
    return dict(id=case["id"],name=case["name"],mode=case["mode"],fixture=base,request=request,
        input_selected_stat={k:getattr(selected,k)for k in("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")},
        input_selected_version=ver)
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
