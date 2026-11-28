"""Archive all independent proof and process bytes; no semantic or verification replay."""
from pathlib import Path
import argparse,hashlib,io,os,sys,tarfile
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from independent_support import source,read,loads,encoded,pin,need,files

def run(output,archive):
    identity=source()
    roots=[("source",ROOT),("result",output)]
    admitted={};physical={}
    for label,root in roots:
        for name,row in files(root).items():
            admitted[label+"/"+name]=row;physical[label+"/"+name]=root/name
    result=loads(read(output/"RESULT.json")) if (output/"RESULT.json").is_file() else dict(status="FAIL")
    value=dict(schema="hepta.audit-record-callable.independent-proof-archive.v1",
        git_head=os.environ.get("GITHUB_SHA"),run_id=os.environ.get("GITHUB_RUN_ID"),
        independent_source_sha256=identity,status=result["status"],files=admitted,native_or_rust_executions=0)
    raw_manifest=encoded(value)
    with tarfile.open(archive,"w:gz",compresslevel=1) as tar:
        for name,path in sorted(physical.items()):
            raw=read(path);need(pin(raw)=={k:admitted[name][k] for k in ("bytes","sha256")},"unchanged complete proof")
            item=tarfile.TarInfo(name);item.size=len(raw);item.mode=admitted[name]["mode"]
            tar.addfile(item,io.BytesIO(raw))
        item=tarfile.TarInfo("artifact-manifest.json");item.size=len(raw_manifest);item.mode=0o644
        tar.addfile(item,io.BytesIO(raw_manifest))
    seen={}
    with tarfile.open(archive,"r|gz") as tar:
        while item:=tar.next():
            need(item.isfile() and item.name not in seen,"unique full exported proof")
            with tar.extractfile(item) as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
            seen[item.name]=dict(bytes=item.size,sha256=digest,mode=item.mode);tar.members.clear()
    need(seen==dict(admitted,**{"artifact-manifest.json":dict(**pin(raw_manifest),mode=0o644)}),
         "complete uploaded proof archive reread")
    for label,root in roots:
        need(files(root)=={n[len(label)+1:]:r for n,r in admitted.items() if n.startswith(label+"/")},
             "complete source/result files unchanged")
    with archive.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
    report=dict(status=result["status"],bytes=archive.stat().st_size,sha256=digest,
        source_sha256=identity,files=len(admitted),logical_bytes=sum(r["bytes"] for r in admitted.values()),
        all_files_and_modes_read=True,native_or_rust_executions=0)
    archive.with_suffix(archive.suffix+".json").write_bytes(encoded(report))
    print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--archive",type=Path,required=True)
    a=p.parse_args();run(a.output.resolve(strict=True),a.archive.absolute())
