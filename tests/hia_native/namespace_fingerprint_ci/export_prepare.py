"""Complete byte-preserving archive of a successful or failed source/build preparation."""
import argparse,gzip,hashlib,json,os,stat,tarfile
from pathlib import Path
def digest_file(path):
    h=hashlib.sha256();size=0
    with path.open("rb") as stream:
        for raw in iter(lambda:stream.read(1<<20),b""):h.update(raw);size+=len(raw)
    return dict(bytes=size,sha256=h.hexdigest())
def run(root,archive):
    root=root.resolve(strict=True);rows={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:
            p=Path(folder)/name
            if not stat.S_ISDIR(p.lstat().st_mode):raise ValueError("ordinary directory required")
        for name in names:
            p=Path(folder)/name;info=p.lstat()
            if not stat.S_ISREG(info.st_mode):raise ValueError("ordinary complete file required")
            rows[p.relative_to(root).as_posix()]=dict(**digest_file(p),mode=stat.S_IMODE(info.st_mode))
    with archive.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw,mode="wb",mtime=0,compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed,mode="w|",format=tarfile.PAX_FORMAT) as tar:
                for name in sorted(rows):tar.add(root/name,arcname=name,recursive=False)
    seen=set()
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            if not member.isfile() or member.name in seen or member.name not in rows:raise ValueError("exact archive set")
            stream=tar.extractfile(member);h=hashlib.sha256();size=0
            for raw in iter(lambda:stream.read(1<<20),b""):h.update(raw);size+=len(raw)
            if dict(bytes=size,sha256=h.hexdigest(),mode=member.mode)!=rows[member.name]:raise ValueError("full archive bytes")
            seen.add(member.name)
    if seen!=set(rows):raise ValueError("complete archive")
    result=dict(schema="hepta.namespace-fingerprint.prepare-archive.v1",files=rows,archive=digest_file(archive),files_count=len(rows),
        logical_bytes=sum(r["bytes"] for r in rows.values()),native_or_rust_semantic_replay=0)
    archive.with_suffix(archive.suffix+".json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="files"},sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,required=True);p.add_argument("--archive",type=Path,required=True)
    a=p.parse_args();run(a.root,a.archive.absolute())
