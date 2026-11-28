# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import os,stat
from common import require
from cases import domain
DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
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

def create(root,case):
    root.mkdir(parents=True);parent=root/"parent";parent.mkdir()
    for name in ("sub","empty","雪-é","'dir\n\x01"):(parent/name).mkdir()
    (parent/"data.bin").write_bytes(bytes(range(256)))
    (parent/"sub"/"retained.bin").write_bytes(b"old-held-directory")
    os.symlink("data.bin",parent/"link");os.symlink("sub",parent/"sub-link")
    os.mkfifo(parent/"pipe",0o600)
def describe(root,case,rows):
    prefix=str(root.absolute())
    return dict(id=case["id"],name=case["name"],session=case["session"],fixture=prefix,
        request={k:case[k].replace("{F}",prefix)for k in("root","path")},mutation=case["mutation"],
        free_fds=case["free_fds"],close=case["close"],snapshot=rows)
