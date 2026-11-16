"""Stream complete success or failure evidence into bounded archive pieces."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,stat,tarfile
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    with path.open("rb") as stream:return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
class Parts:
    def __init__(self,root,limit=384<<20):
        self.root=root;self.limit=limit;self.parts=[];self.handle=None;self.size=0;self.total=0;self.hash=hashlib.sha256()
    def write(self,data):
        raw=memoryview(data);count=len(raw)
        while raw:
            if self.handle is None:
                self.path=self.root/f"capture.tar.gz.part-{len(self.parts):03d}"
                self.handle=self.path.open("xb");self.size=0
            n=min(len(raw),self.limit-self.size)
            assert self.handle.write(raw[:n])==n
            self.hash.update(raw[:n]);self.size+=n;self.total+=n;raw=raw[n:]
            if self.size==self.limit:self.finish_part()
        return count
    def tell(self):return self.total
    def flush(self):
        if self.handle:self.handle.flush()
    def finish_part(self):
        if self.handle:
            self.handle.close();self.parts.append({"path":self.path.name,**pin(self.path)});self.handle=None
    def close(self):self.finish_part()
class HashWriter:
    def __init__(self,target):self.target=target;self.hash=hashlib.sha256();self.size=0
    def write(self,raw):
        self.hash.update(raw);self.size+=len(raw);return self.target.write(raw)
    def flush(self):return self.target.flush()
def run(source,destination):
    destination.mkdir(parents=True,exist_ok=False);rows=[];directories=[]
    for folder,dirs,names in os.walk(source,followlinks=False):
        p=Path(folder);assert stat.S_ISDIR(p.lstat().st_mode)
        directories.append({"path":p.relative_to(source).as_posix(),"mode":stat.S_IMODE(p.stat().st_mode)})
        for name in dirs:assert stat.S_ISDIR((p/name).lstat().st_mode)
        for name in names:
            path=p/name;assert stat.S_ISREG(path.lstat().st_mode) and path.resolve()==path.absolute()
            rows.append({"path":path.relative_to(source).as_posix(),"mode":stat.S_IMODE(path.stat().st_mode),**pin(path)})
    rows.sort(key=lambda row:row["path"]);directories.sort(key=lambda row:row["path"])
    parts=Parts(destination)
    try:
        with gzip.GzipFile(fileobj=parts,mode="wb",compresslevel=1,mtime=0) as zipped:
            hashed=HashWriter(zipped)
            with tarfile.open(fileobj=hashed,mode="w|") as archive:
                for row in directories:archive.add(source/row["path"],arcname="capture/"+row["path"],recursive=False)
                for row in rows:archive.add(source/row["path"],arcname="capture/"+row["path"],recursive=False)
    finally:parts.close()
    for row in rows:assert pin(source/row["path"])=={k:row[k] for k in ("bytes","sha256")}
    report={"schema":"hepta.runtime.configured-catalog-complete-archive.v1","source_root":str(source),
        "files":rows,"directories":directories,"file_count":len(rows),"logical_bytes":sum(r["bytes"] for r in rows),
        "tar":{"bytes":hashed.size,"sha256":hashed.hash.hexdigest()},
        "gzip":{"bytes":parts.total,"sha256":parts.hash.hexdigest()},"parts":parts.parts,"native_or_rust_executions":0}
    (destination/"MANIFEST.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("files","directories")},sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--input",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.input.resolve(strict=True),a.output.absolute())
