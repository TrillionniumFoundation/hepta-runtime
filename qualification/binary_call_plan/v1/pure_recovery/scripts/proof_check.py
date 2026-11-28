# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path, PurePosixPath
import stat
from common import owned, pin, require
PROBES=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
def identity(path):
    require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),"ordinary archive object required")
    return dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
def safe(name):
    p=PurePosixPath(name)
    require(type(name) is str and p.as_posix()==name and not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("source","run"),
        "invalid logical archive path")
    return p
def process(row,folder,budget):
    require(row["completed"] is True and row["exit_code"]==0 and row["timed_out"] is False
        and row["timeout_seconds"]==budget and 0<=row["elapsed_seconds"]<budget+1
        and row["pid"]==row["pgid"] and row["pid"]>0,"retained process did not pass its original budget")
    for suffix in ("stdout","stderr"):
        value=row[suffix]
        require(pin(owned(folder,value["file"]))=={k:value[k] for k in ("bytes","sha256")},"retained full process stream changed")
def proof(value,files,directories,roots):
    require(value["status"]=="READONLY_PASS" and value["before"]==value["after"],"readonly proof lost exact before/after custody")
    require([p["name"] for p in value["probes"]]==PROBES and all(p["rejected"] is True for p in value["probes"]),
        "readonly capability probes changed")
    require(value["native_executed"] is False and value["rust_executed"] is False and value["evidence_written"] is False,
        "readonly proof executed or wrote evidence")
    require(len(set(value["roots"]))==len(value["roots"]) and set(value["roots"])<=set(roots),"readonly root binding missing")
    actual_files=set();actual_dirs=set()
    for row in value["before"]:
        require(type(row["root"]) is int and 0<=row["root"]<len(value["roots"]),"readonly root index invalid")
        prefix=roots[value["roots"][row["root"]]]
        logical=prefix if row["path"]=="." else prefix+"/"+row["path"]
        safe(logical)
        if stat.S_ISREG(row["mode"]):
            require(logical not in actual_files and logical in files,"readonly ordinary file duplicated or missing")
            actual_files.add(logical);expected=files[logical]
            require(row["sha256"]==expected["sha256"] and row["bytes"]==expected["bytes"] and
                stat.S_IMODE(row["mode"])==expected["mode"],"readonly proof file differs from archived complete bytes")
        else:
            require(stat.S_ISDIR(row["mode"]) and logical not in actual_dirs and logical in directories,"readonly directory changed")
            actual_dirs.add(logical)
            require(stat.S_IMODE(row["mode"])==directories[logical],"readonly directory mode changed")
    prefixes=[roots[name] for name in value["roots"]]
    require(actual_files=={name for name in files if any(name.startswith(p+"/") for p in prefixes)},"readonly complete file set changed")
    require(actual_dirs=={name for name in directories if any(name==p or name.startswith(p+"/") for p in prefixes)},
        "readonly complete directory set changed")
