#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Owned fixture setup and complete observational filesystem capture."""
from pathlib import Path
import os
import shutil
import stat
from common import require
from body_cases import payload

def reset(root, case):
    root=Path(root)
    require(root.name == "case-%03d" % case["id"] and root.parent.name == "fixtures",
        "fixture scope changed")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    # Parent directories described by actual file declarations are setup inputs.
    for row in case["initial"]:
        at=root/row["path"]; at.parent.mkdir(parents=True,exist_ok=True)
        if row["kind"]=="dir":
            at.mkdir(exist_ok=True); at.chmod(row["mode"])
        elif row["kind"]=="file":
            at.write_bytes(payload(row));at.chmod(row["mode"])
            for key,value in row.get("xattr",{}).items():
                os.setxattr(at,key,value.encode())
        elif row["kind"]=="hardlink":
            os.link(root/row["target"],at)
        elif row["kind"]=="symlink":
            os.symlink(row["target"],at)
        else:
            raise ValueError("unknown fixture kind")
    if case["mode"]=="create" and case["path"].startswith(("目录/","space a/","sub//")):
        (root/case["path"].split("/")[0]).mkdir(exist_ok=True)

def stat_row(info):
    return dict(mode=info.st_mode,dev=info.st_dev,ino=info.st_ino,nlink=info.st_nlink,
        uid=info.st_uid,gid=info.st_gid,size=info.st_size,
        atime_ns=info.st_atime_ns,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)

def snapshot(root, store):
    root=Path(root)
    result=[]
    def walk(path):
        info=path.lstat()
        name="." if path==root else path.relative_to(root).as_posix()
        row=dict(path=name,stat=stat_row(info))
        if stat.S_ISDIR(info.st_mode):
            row["kind"]="dir"
            row["entries"]=sorted(os.listdir(path))
        elif stat.S_ISREG(info.st_mode):
            row["kind"]="file";row["data"]=store.put(path.read_bytes())
        elif stat.S_ISLNK(info.st_mode):
            row["kind"]="symlink";row["target"]=os.readlink(path)
        else:
            raise ValueError("unrecognized owned fixture type")
        row["xattrs"]={name:os.getxattr(path,name,follow_symlinks=False).hex()
            for name in sorted(os.listxattr(path,follow_symlinks=False))}
        after=path.lstat()
        require((info.st_dev,info.st_ino,info.st_size,info.st_mode,info.st_mtime_ns,info.st_ctime_ns)
            ==(after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns,after.st_ctime_ns),
            "fixture changed during snapshot")
        result.append(row)
        if row["kind"]=="dir":
            for name in row["entries"]:
                walk(path/name)
    walk(root)
    return result

def retire(root, case):
    root=Path(root)
    require(root.name=="case-%03d"%case["id"] and root.parent.name=="fixtures","fixture retirement scope changed")
    # A complete before/after snapshot is retained before this reversible fixture reset.
    for at,dirs,files in os.walk(root,followlinks=False):
        os.chmod(at,0o700)
    shutil.rmtree(root)
