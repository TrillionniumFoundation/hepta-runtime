"""Full saved immutable guard-byte references; no application execution."""
from pathlib import Path
import stat
from common import decode,pin,require,owned
PROBES=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
def tree(root):
    root=Path(root);files={};dirs={}
    for p in [root,*sorted(root.rglob("*"))]:
        name="."if p==root else p.relative_to(root).as_posix()
        require(not p.is_symlink(),"guard tree symlink")
        if p.is_dir():dirs[name]=p.stat().st_mode&0o777
        else:
            require(p.is_file(),"guard ordinary file")
            files[name]=(p,p.stat().st_mode&0o777)
    return files,dirs
def saved_guard(value,roots):
    require(value["status"]=="READONLY_PASS" and value["before"]==value["after"]
        and value["native_executed"]is value["rust_executed"]is value["evidence_written"]is False,
        "saved guard complete nonmutating result")
    require(value["roots"]==sorted(roots) and value["probes"]==[dict(name=n,rejected=True)for n in PROBES],
        "all eleven exact saved guard denials")
    require(value["entries"]==len(value["before"]),"guard entry count")
    bound=0
    for number,name in enumerate(value["roots"]):
        files,dirs=roots[name];rows={r["path"]:r for r in value["before"]if r["root"]==number}
        require(len(rows)==sum(r["root"]==number for r in value["before"]) and set(rows)==set(files)|set(dirs),
            "complete saved guard entry set")
        for path,(physical,mode)in files.items():
            r=rows[path];actual=pin(physical)
            require(stat.S_ISREG(r["mode"]) and r["mode"]&0o777==mode
                and r["bytes"]==actual["bytes"] and r["sha256"]==actual["sha256"],
                "all saved guarded file bytes and modes")
            bound+=1
        for path,mode in dirs.items():
            r=rows[path];require(stat.S_ISDIR(r["mode"]) and r["mode"]&0o777==mode and "sha256"not in r,
                "all saved guard directory modes")
    require(all(type(r["root"])is int and 0<=r["root"]<len(roots)for r in value["before"]),
        "no foreign saved guard root")
    return bound
