"""Restore complete configured-catalog archives with all ZIP, part, tar and file pins."""
from pathlib import Path,PurePosixPath
import argparse,gzip,hashlib,io,json,os,stat,tarfile,zipfile

def require(value,label):
    if not value:raise ValueError("configured artifact: "+label)
def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,"duplicate JSON key");result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def identity(path):
    info=path.lstat();require(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"regular archive input")
    with path.open("rb") as stream:return {"bytes":info.st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
def safe(name,*,root=False):
    path=PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts and "\\" not in name
        and str(path)==name and (root or str(path)!="."),"relative member path")
    return Path(*path.parts)
class Concatenated(io.RawIOBase):
    def __init__(self,paths):self.paths=iter(paths);self.current=None;self.bytes=0;self.hash=hashlib.sha256()
    def readable(self):return True
    def readinto(self,buffer):
        while True:
            if self.current is None:
                try:self.current=next(self.paths).open("rb")
                except StopIteration:return 0
            size=self.current.readinto(buffer)
            if size:self.bytes+=size;self.hash.update(memoryview(buffer)[:size]);return size
            self.current.close();self.current=None
    def close(self):
        if self.current:self.current.close()
        super().close()
class Hashed:
    def __init__(self,source):self.source=source;self.bytes=0;self.hash=hashlib.sha256()
    def read(self,size=-1):
        raw=self.source.read(size);self.bytes+=len(raw);self.hash.update(raw);return raw

def run(plan_path,output):
    plan=parse(plan_path.read_bytes());require(not output.exists(),"new readback namespace")
    output.mkdir(mode=0o700,parents=True)
    download=output/"download";download.mkdir()
    received={};zip_rows=[]
    for row in plan["artifacts"]:
        path=Path(row["path"]).absolute();actual=identity(path)
        meta=row["metadata"]
        require(actual=={"bytes":meta["size_in_bytes"],"sha256":meta["digest"].removeprefix("sha256:")},
            "entire downloaded GitHub ZIP")
        require(meta["expired"] is False and meta["workflow_run"]["id"]==plan["run_id"]
            and meta["workflow_run"]["head_sha"]==plan["head"],"actual immutable workflow artifact")
        names=[]
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                require(not member.is_dir() and stat.S_IFMT(member.external_attr>>16) in(0,stat.S_IFREG),
                    "only regular exported ZIP members")
                name=member.filename;relative=safe(name)
                require(len(relative.parts)==1 and name not in received,"one owned archive part")
                require(name=="MANIFEST.json" or name.startswith("capture.tar.gz.part-"),"known export role")
                destination=download/relative
                digest=hashlib.sha256();size=0
                with archive.open(member) as source,destination.open("xb") as target:
                    while block:=source.read(1<<20):
                        require(target.write(block)==len(block),"complete ZIP member write")
                        size+=len(block);digest.update(block)
                require(size==member.file_size,"complete ZIP member extent")
                received[name]={"bytes":size,"sha256":digest.hexdigest()};names.append(name)
        zip_rows.append({"id":meta["id"],"name":meta["name"],"archive":actual,"members":names})
    manifest=parse((download/"MANIFEST.json").read_bytes())
    require(manifest["schema"]=="hepta.runtime.configured-catalog-complete-archive.v1","archive schema")
    parts=manifest["parts"];require(0<len(parts)<=16,"bounded complete archive piece count")
    require([p["path"] for p in parts]==[f"capture.tar.gz.part-{i:03d}" for i in range(len(parts))],
        "complete ordered archive pieces")
    require(set(received)=={"MANIFEST.json"}|{p["path"] for p in parts},"no missing/extra export objects")
    for i,row in enumerate(parts):
        require(received[row["path"]]=={k:row[k] for k in("bytes","sha256")},"entire compressed part")
        require(0<row["bytes"]<=384<<20 and (i==len(parts)-1 or row["bytes"]==384<<20),"exact split extent")
    files={row["path"]:row for row in manifest["files"]}
    directories={row["path"]:row for row in manifest["directories"]}
    require(len(files)==len(manifest["files"])==manifest["file_count"]
        and len(directories)==len(manifest["directories"]) and "." in directories,"exact archive member domain")
    require(sum(row["bytes"] for row in files.values())==manifest["logical_bytes"],"complete logical extent")
    capture=output/"capture";seen=set();mode_rows=[]
    joined=Concatenated([download/p["path"] for p in parts])
    with io.BufferedReader(joined) as buffered,gzip.GzipFile(fileobj=buffered,mode="rb") as compressed:
        hashed=Hashed(compressed)
        with tarfile.open(fileobj=hashed,mode="r|") as archive:
            for member in archive:
                path=PurePosixPath(member.name)
                require(path.parts and path.parts[0]=="capture" and ".." not in path.parts,"tar top-level")
                relative=PurePosixPath(*path.parts[1:]).as_posix();safe(relative,root=True)
                require(relative not in seen,"single physical tar member");seen.add(relative)
                destination=capture/safe(relative,root=True)
                if member.isdir():
                    require(relative in directories and member.mode==directories[relative]["mode"],"exact owned directory mode")
                    destination.mkdir(mode=0o700);mode_rows.append((destination,member.mode))
                else:
                    require(relative in files and member.mode==files[relative]["mode"],"exact owned file role/mode")
                    if member.isfile():stream=archive.extractfile(member)
                    else:
                        require(member.islnk(),"no tar symlinks/devices")
                        linked=PurePosixPath(member.linkname)
                        require(linked.parts and linked.parts[0]=="capture" and ".." not in linked.parts,"owned hardlink target")
                        target=capture/Path(*linked.parts[1:]);identity(target);stream=target.open("rb")
                    require(stream is not None,"full tar input extent")
                    with stream,destination.open("xb") as target:
                        while block:=stream.read(1<<20):require(target.write(block)==len(block),"full file write")
                    destination.chmod(member.mode)
                    require(identity(destination)=={k:files[relative][k] for k in("bytes","sha256")},"every complete file")
        while hashed.read(1<<20):pass
        require({"bytes":hashed.bytes,"sha256":hashed.hash.hexdigest()}==manifest["tar"],"entire uncompressed tar")
    require({"bytes":joined.bytes,"sha256":joined.hash.hexdigest()}==manifest["gzip"],"entire concatenated gzip")
    require(seen==set(files)|set(directories),"all physical archive members")
    for path,mode in reversed(mode_rows):path.chmod(mode)
    for name,row in files.items():
        path=capture/safe(name)
        require(identity(path)=={k:row[k] for k in("bytes","sha256")}
            and stat.S_IMODE(path.stat().st_mode)==row["mode"],"second complete file/mode readback")
    report={"status":"COMPLETE_CONFIGURED_ARCHIVE_READBACK_PASS","head":plan["head"],"run_id":plan["run_id"],
        "files":len(files),"directories":len(directories),"logical_bytes":manifest["logical_bytes"],
        "zip_archives":zip_rows,"gzip":manifest["gzip"],"tar":manifest["tar"],"native_executions":0,"rust_executions":0}
    with (output/"ARCHIVE_READBACK.json").open("xb") as stream:stream.write((json.dumps(report,sort_keys=True,indent=2)+"\n").encode())
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--plan",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.plan.resolve(strict=True),a.output.absolute())
