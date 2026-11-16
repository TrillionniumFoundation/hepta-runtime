"""Archive complete source and successful or failed physical evidence."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import tarfile

ROOT=Path(__file__).resolve().parent

def file_pin(path):
    with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture",type=Path,required=True)
    parser.add_argument("--archive",type=Path,required=True)
    args=parser.parse_args()
    capture=args.capture.resolve(strict=True);archive=args.archive.absolute()
    assert not archive.is_relative_to(ROOT) and not archive.is_relative_to(capture) and not archive.exists()
    files,paths={},{}
    for prefix,folder in (("source",ROOT),("run",capture)):
        for path in sorted(folder.rglob("*")):
            info=path.lstat()
            assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),(str(path),info.st_mode)
            if path.is_dir():continue
            name=prefix+"/"+path.relative_to(folder).as_posix()
            files[name]=dict(**file_pin(path),mode=stat.S_IMODE(info.st_mode))
            paths[name]=path
    gate=json.loads((capture/"GATE.json").read_bytes()) if (capture/"GATE.json").exists() else dict(status="NO_GATE_RECORD")
    meta=dict(schema="hepta.audit-store-queue.archive-inputs.v2",git_head=os.environ.get("GITHUB_SHA"),
        run_id=os.environ.get("GITHUB_RUN_ID"),attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
        source_manifest=files["source/SOURCE_MANIFEST.json"],gate_status=gate["status"],files=files,
        semantic_reexecutions_by_exporter=0,whole_runtime_replaced=False)
    raw=encoded(meta);expected=dict(files)
    expected["artifact-manifest.json"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=0o644)
    archive.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive,"w:gz",compresslevel=1,dereference=True) as target:
        for name,path in paths.items():target.add(path,arcname=name,recursive=False)
        info=tarfile.TarInfo("artifact-manifest.json");info.size=len(raw);info.mode=0o644
        target.addfile(info,io.BytesIO(raw))
    observed={}
    with tarfile.open(archive,"r|gz") as source:
        while member:=source.next():
            assert member.isfile() and member.name not in observed and not Path(member.name).is_absolute() and ".." not in Path(member.name).parts
            with source.extractfile(member) as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
            observed[member.name]=dict(bytes=member.size,sha256=digest,mode=member.mode)
            source.members.clear()
    assert observed==expected
    for name,path in paths.items():assert file_pin(path)=={k:files[name][k] for k in ("bytes","sha256")}
    receipt=dict(schema="hepta.audit-store-queue.complete-archive.v2",archive=archive.name,**file_pin(archive),
                 files=len(observed),logical_bytes=sum(r["bytes"] for r in observed.values()),
                 all_members_reread=True,gate_status=gate["status"],source_manifest_sha256=meta["source_manifest"]["sha256"],
                 semantic_executions=0,whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix+".json").write_bytes(encoded(receipt))
    print(json.dumps(receipt,sort_keys=True))

if __name__=="__main__":main()
