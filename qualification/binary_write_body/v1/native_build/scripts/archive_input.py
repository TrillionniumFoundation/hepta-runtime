"""Full immutable archive reader and byte-level retained guard validation."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,shutil,stat,tarfile,urllib.request,zipfile
REPO="TrillionniumFoundation/hepta-runtime"
def require(ok,text):
    if not ok:raise ValueError(text)
def pin(path):
    path=Path(path)
    with path.open("rb") as stream:return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
def doc(path):return json.loads(Path(path).read_bytes())
def put(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class Hashing:
    def __init__(self,stream):self.stream=stream;self.digest=hashlib.sha256();self.count=0
    def read(self,n=-1):
        b=self.stream.read(n);self.digest.update(b);self.count+=len(b);return b
    def pin(self):return {'bytes':self.count,'sha256':self.digest.hexdigest()}
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        out=super().redirect_request(req,fp,code,msg,headers,newurl)
        if out is not None:out.remove_header("Authorization")
        return out
def download(path,artifact):
    token=os.environ["GH_TOKEN"]
    url="https://api.github.com/repos/"+REPO+"/actions/artifacts/"+str(artifact)+"/zip"
    request=urllib.request.Request(url,headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","User-Agent":"complete-evidence-reader"})
    with urllib.request.build_opener(Redirect()).open(request,timeout=60) as response,path.open("xb") as out:
        while block:=response.read(1<<20):out.write(block)
def safe(name):
    p=PurePosixPath(name)
    require(name and not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"ordinary archive path")
def flat_archive(path,identity,output):
    require(pin(path)==identity["zip"],"complete fixed fixture ZIP")
    require(not output.exists(),"fresh fixture restoration");output.mkdir(parents=True)
    with zipfile.ZipFile(path) as z:
        require(set(z.namelist())=={"ARCHIVE.json","FILES.json","evidence.tar.gz"} and len(z.infolist())==3,"full fixture outer ZIP")
        index=json.loads(z.read("FILES.json"));wanted={r["path"]:r for r in index["files"]};require(len(wanted)==len(index["files"])==identity["files"],"fixture archive member count")
        with z.open("evidence.tar.gz") as src:
            h=Hashing(src);seen=set()
            with tarfile.open(fileobj=h,mode="r|gz") as tar:
                for m in tar:
                    safe(m.name);require(m.isfile() and m.name in wanted and m.name not in seen,"ordinary unique complete fixture evidence")
                    r=wanted[m.name];require(m.size==r["bytes"] and m.mode==r["mode"],"fixture evidence extent/mode")
                    p=output/m.name;p.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(m) as a,p.open("xb") as b:
                        shutil.copyfileobj(a,b)
                    os.chmod(p,m.mode);require(pin(p)=={k:r[k] for k in ("bytes","sha256")},"complete fixture member bytes");seen.add(m.name)
            while h.read(1<<20):pass
            require(h.pin()==identity["archive"],"full compressed fixture TAR")
        expected={"status":"COMPLETE_ARCHIVE_BYTES_PASS","files":identity["files"],"logical_bytes":identity["logical_bytes"],"archive":identity["archive"]}
        require(json.loads(z.read("ARCHIVE.json"))==expected and seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==identity["logical_bytes"],"complete fixed fixture archive proof")
    return expected

PROBES=("python-file-write","descriptor-open","descriptor-write","metadata-mode","metadata-time","directory-create","subprocess","shell","native-dlopen","native-mmap","producer-or-foreign-read")
def admitted(root,expected=None):
    root=Path(root)
    if expected is not None:require(pin(root/"SOURCE_MANIFEST.json")==expected,"exact frozen source manifest")
    manifest=doc(root/"SOURCE_MANIFEST.json");rows=manifest["files"]
    names={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(len(rows)==len({r["path"] for r in rows}) and names=={r["path"] for r in rows}|{"SOURCE_MANIFEST.json"},"complete source inventory")
    for row in rows:
        safe(row["path"]);path=root/row["path"];raw=path.read_bytes()
        require(pin(path)=={k:row[k] for k in ("bytes","sha256")} and path.stat().st_mode&0o777==0o644,"complete source bytes and mode")
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"complete source Git object")
    return len(rows)
def files(root,exclude=()):
    return {p.relative_to(root).as_posix():p for p in sorted(Path(root).rglob("*")) if p.is_file() and p.relative_to(root).as_posix() not in exclude}
def saved_guard(value,roots,pid):
    require(value["schema"]=="hepta.runtime.owner-export-readonly.v1" and value["source_bound_guard"] is True,"retained exact guard")
    require(value["native_or_rust_executions"]==value["reader_writes"]==0 and value["before"]==value["after"],"unchanged complete before and after guard snapshots")
    require(value["pid"]==value["pgid"]==pid and type(value["ppid"]) is int and value["ppid"]>0,"actual bounded guard process")
    require(tuple(x["name"] for x in value["probes"])==PROBES and all(x["refusal"]=="owner-export read-only guard: "+x["guard_event"] for x in value["probes"]),"all eleven actual denial probes")
    complete=0
    expected_keys=set()
    for index,root in enumerate(roots):
        prefix=str(index)+":"
        recorded={k[len(prefix):]:r for k,r in value["before"].items() if k.startswith(prefix)}
        recorded_files={name:r for name,r in recorded.items() if r["sha256"] is not None}
        require(set(recorded_files)==set(root),"complete retained guard file set")
        for name,item in root.items():
            path,mode=item if isinstance(item,tuple) else (item,item.stat().st_mode&0o777)
            row=recorded_files[name];observed=pin(path)
            require(stat.S_ISREG(row["mode"]) and row["bytes"]==observed["bytes"] and row["sha256"]==observed["sha256"] and row["mode"]&0o777==mode,"full guarded file bytes and mode")
            complete+=1
        for name,row in recorded.items():
            if name!=".":safe(name)
            require(row["sha256"] is not None or stat.S_ISDIR(row["mode"]),"ordinary retained guard inventory")
            expected_keys.add(prefix+name)
    require(set(value["before"])==expected_keys,"no unbound retained guard root")
    return complete
def process(root,name,expected):
    value=doc(root/(name+".process.json"))
    require(value==expected and value["application_executions"]==0 and value["deadline_seconds"]==180 and 0<=value["elapsed_seconds"]<180,"exact completed bounded pure process")
    require(value["exit_code"]==0 and value["timed_out"] is value["kill_requested"] is False,"natural pure-reader success")
    for suffix in ("stdout","stderr"):require(pin(root/(name+"."+suffix))==value[suffix],"complete pure process streams")
    require((root/(name+".stderr")).read_bytes()==b"","no hidden reader error")
    return value
