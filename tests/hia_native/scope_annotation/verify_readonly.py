"""Guard verification against writes/execution and prove retained bytes unchanged.

This is an in-process regression guard for these source-bound Python readers,
not a sandbox for untrusted Python.  It never launches a native or Rust process.
"""
import argparse
from contextlib import redirect_stdout
# Import the standard-library dependency before installing the guard.  Its
# one-time PyDLL(None) initialization is not an HIA load or execution; all later
# ctypes/mmap activity is refused, including any attempted NativeModule use.
import ctypes
import hashlib
import importlib.util
import io
import json
import mmap
import os
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode=True


class ReadOnlyViolation(RuntimeError):
    pass


class ReadOnlyGuard:
    MUTATIONS=frozenset(("os.remove","os.rename","os.rmdir","os.mkdir","os.truncate",
        "os.chmod","os.chown","os.utime","os.link","os.symlink","os.setxattr","os.removexattr"))
    EXECUTION=frozenset(("subprocess.Popen","os.system","os.fork","os.forkpty",
        "os.posix_spawn","os.exec","mmap.__new__"))

    def __init__(self):
        self.active=False
        self.refusals=[]

    def audit(self,event,args):
        if not self.active:
            return
        if event=="open":
            _,mode,flags=args
            write_mode=isinstance(mode,str) and any(letter in mode for letter in "wax+")
            write_flags=isinstance(flags,int) and bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            denied=write_mode or write_flags
        else:
            denied=event in self.MUTATIONS or event in self.EXECUTION or event.startswith("ctypes.")
        if denied:
            self.refusals.append(event)
            raise ReadOnlyViolation("read-only verification refused "+event)

    def __enter__(self):
        sys.addaudithook(self.audit)
        self.active=True
        return self

    def __exit__(self,*args):
        self.active=False


def identity(path):
    row=path.lstat()
    result=dict(mode=row.st_mode,device=row.st_dev,inode=row.st_ino,links=row.st_nlink,
        bytes=row.st_size,mtime_ns=row.st_mtime_ns,ctime_ns=row.st_ctime_ns)
    if stat.S_ISREG(row.st_mode):
        digest=hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda:stream.read(1<<20),b""):
                digest.update(chunk)
        result["sha256"]=digest.hexdigest()
    elif stat.S_ISLNK(row.st_mode):
        result["target"]=os.readlink(path)
    elif not stat.S_ISDIR(row.st_mode):
        raise ValueError("verification tree contains a non-ordinary entry")
    if path.lstat()!=row:
        # Access times can change during reads; the stable fields above cannot.
        after=path.lstat()
        if any(getattr(row,name)!=getattr(after,name) for name in
                ("st_mode","st_dev","st_ino","st_nlink","st_size","st_mtime_ns","st_ctime_ns")):
            raise ValueError("verification input changed during snapshot")
    return result


def tree_snapshot(root):
    result={".":identity(root)}
    def visit(folder):
        with os.scandir(folder) as entries:
            rows=sorted(entries,key=lambda item:item.name)
        for entry in rows:
            path=Path(entry.path)
            item=identity(path)
            result[str(path.relative_to(root))]=item
            if stat.S_ISDIR(item["mode"]):
                visit(path)
    visit(root)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--phase",choices=("verify-native","verify"),required=True)
    args=parser.parse_args()
    root=args.source_root.resolve(strict=True)
    output=args.output.resolve(strict=True)
    sys.path[:0]=[str(root/"scripts"),str(root/"tests/hia_native/scope_annotation")]
    import hia_native_scope_annotation_qualification as q
    from rust_reference import put
    spec=importlib.util.spec_from_file_location("scope_annotation_readonly_qualifier",
        root/"scripts/qualify_hia_scope_annotation.py")
    qualifier=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(qualifier)
    source=q.source_evidence(root)
    source_before={name:identity(root/name) for name in source["files"]}
    before=tree_snapshot(output)
    guard=ReadOnlyGuard()
    report_path=output/"QUALIFICATION.json"
    forbidden_path=output/"readonly-write-must-not-exist"
    if forbidden_path.exists():
        raise ValueError("read-only control destination already exists")
    probes=(
        ("python-write",lambda:report_path.open("wb")),
        ("descriptor-write",lambda:os.open(report_path,os.O_WRONLY|os.O_TRUNC)),
        ("path-write",lambda:report_path.write_bytes(b"forbidden")),
        ("metadata-write",lambda:os.utime(report_path,ns=(1,1))),
        ("directory-create",lambda:forbidden_path.mkdir()),
        ("report-writer",lambda:put(report_path,{"forbidden":True})),
        ("process-launch",lambda:subprocess.Popen([sys.executable,"-c","raise SystemExit(99)"])),
        ("shell-launch",lambda:os.system("exit 99")),
        ("native-mapping",lambda:mmap.mmap(-1,4096)),
    )
    refused=[]
    stream=io.StringIO()
    with guard:
        for name,operation in probes:
            try:
                operation()
            except ReadOnlyViolation:
                refused.append(name)
            else:
                raise AssertionError("verification guard accepted "+name)
        count=len(guard.refusals)
        with redirect_stdout(stream):
            qualifier.main(["--source-root",str(root),"--output",str(output),"--phase",args.phase])
        if len(guard.refusals)!=count:
            raise AssertionError("verification attempted a forbidden side effect")
    after=tree_snapshot(output)
    source_after={name:identity(root/name) for name in source["files"]}
    q.require(before==after and source_before==source_after,"verification changed retained tree bytes or metadata")
    q.require(q.source_evidence(root)==source,"verification changed source closure")
    result=q.parse(stream.getvalue())
    q.require(result["source_sha256"]==source["sha256"] and result["native_calls"]==2484
        and result["cases"]==444 and result["controls"]==39,"verified domain summary differs")
    print(json.dumps(dict(schema="hepta.scope-annotation.readonly-control.v1",status="READONLY_PASS",
        phase=args.phase,verification=result,write_execution_refusals=refused,
        tree_entries=len(before),source_files=len(source_before),tree_bytes_and_metadata_unchanged=True,
        native_processes_executed=0,original_processes_executed=0,
        tree_snapshot_sha256=hashlib.sha256(q.encoded(before)).hexdigest()),sort_keys=True))


if __name__=="__main__":main()
