"""Independent complete-archive/read-only admission; no semantic implementation."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
def need(ok,message):
    if not ok:raise ValueError(message)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def loads(raw):
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,"unique JSON members");result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def relative(name):
    need(type(name) is str,"path string");p=PurePosixPath(name)
    need(name and p.as_posix()==name and not p.is_absolute() and
         all(x not in ("",".","..") for x in p.parts),"exact contained archive path")
    return p
def read(p):
    before=p.lstat();need(stat.S_ISREG(before.st_mode),"ordinary complete retained file")
    with p.open("rb") as f:
        a=os.fstat(f.fileno());raw=f.read();b=os.fstat(f.fileno())
    need((before.st_dev,before.st_ino)==(a.st_dev,a.st_ino) and
         (a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_size,b.st_mtime_ns,b.st_ctime_ns)
         and len(raw)==b.st_size,"stable complete retained read")
    return raw
def files(root):
    result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for n in dirs:need(stat.S_ISDIR((Path(folder)/n).lstat().st_mode),"ordinary retained directory")
        for n in names:
            p=Path(folder)/n;result[p.relative_to(root).as_posix()]=dict(**pin(read(p)),mode=stat.S_IMODE(p.lstat().st_mode))
    return result
def source():
    raw=read(ROOT/"SOURCE.json");m=loads(raw)
    need(m["schema"]=="hepta.audit-record-callable.independent-source.v1" and
         set(files(ROOT))==set(m["files"])|{"SOURCE.json"},"complete independent source set")
    for name,row in m["files"].items():
        body=read(ROOT/relative(name))
        need(pin(body)=={k:row[k] for k in ("bytes","sha256")} and
             hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],
             "full independent source and Git identity: "+name)
    return pin(raw)["sha256"]
def expected():
    source();return loads(read(ROOT/"EXPECTED.json"))
