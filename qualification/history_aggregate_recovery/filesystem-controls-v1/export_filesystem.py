#!/usr/bin/env python3
"""Archive every owned continuation byte, including partial failure records."""
from __future__ import annotations
import argparse,hashlib,json,os,stat,tarfile,time
from pathlib import Path
def need(value,message):
    if not value:raise ValueError(message)
def pin(path):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"ordinary export file")
    with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    after=path.lstat()
    need((info.st_mode,info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
         (after.st_mode,after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"stable export file")
    return {"bytes":info.st_size,"sha256":digest}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--proof",type=Path,required=True);parser.add_argument("--package",type=Path,required=True)
    args=parser.parse_args();started=time.monotonic_ns()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    roots=[("proof",args.proof),("source",args.package)]
    for name,path in (("historical-source",Path("/home/runner/work/_temp/hia-historical-public58")),
                      ("filesystem-input",Path("/home/runner/work/_temp/hia-runtime-native"))):
        if path.exists():roots.append((name,path))
    rows=[]
    for label,root in roots:
        need(root.is_dir() and root.resolve()==root.absolute(),"ordinary owned export root")
        for path in [root,*sorted(root.rglob("*"))]:
            info=path.lstat();relative=Path(label)/path.relative_to(root)
            need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),"no unowned/special archive member")
            row={"path":relative.as_posix(),"mode":stat.S_IMODE(info.st_mode),
                 "type":"file" if stat.S_ISREG(info.st_mode) else "directory"}
            if row["type"]=="file":row.update(pin(path))
            rows.append((row,path))
    archive=args.output/"filesystem-continuation.tar.gz"
    with tarfile.open(archive,"w:gz",compresslevel=1,format=tarfile.PAX_FORMAT) as tar:
        for row,path in rows:
            need(stat.S_IMODE(path.lstat().st_mode)==row["mode"],"mode stable before archive")
            if row["type"]=="file":need(pin(path)=={k:row[k] for k in ("bytes","sha256")},"complete export bytes stable")
            info=tar.gettarinfo(str(path),arcname=row["path"])
            info.uid=info.gid=0;info.uname=info.gname=""
            if row["type"]=="file":
                with path.open("rb") as stream:tar.addfile(info,stream)
                need(pin(path)=={k:row[k] for k in ("bytes","sha256")},"complete export bytes stable after archive")
            else:tar.addfile(info)
    result_path=args.proof/"run/CONTINUATION.json"
    result=json.loads(result_path.read_bytes()) if result_path.exists() else None
    value={"schema":"hepta.history.filesystem-continuation-export.v1","status":"COMPLETE",
           "archive":pin(archive),"members":[row for row,_ in rows],"result":result,
           "complete_input_artifacts_preserved":True,"original_failure_reclassified_as_pass":False,
           "native_or_rust_executions":0,"elapsed_ns":time.monotonic_ns()-started}
    with (args.output/"manifest.json").open("xb") as stream:
        stream.write((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
    print(json.dumps({"status":"COMPLETE","archive":value["archive"],"members":len(rows),
        "continuation_status":result["status"] if result else "INCOMPLETE","native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
