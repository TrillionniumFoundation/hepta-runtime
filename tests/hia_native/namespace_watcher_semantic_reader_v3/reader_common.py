"""Pure complete-byte helpers for the persistent Watcher reader."""
from pathlib import Path
import hashlib,json,os,stat,struct
ROOT=Path(__file__).resolve().parent
def require(value,message):
    if not value:raise ValueError(message)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def loads(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,"duplicate JSON member");result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def read(path):
    path=Path(path);before=path.lstat();require(stat.S_ISREG(before.st_mode),"ordinary retained file")
    with path.open("rb")as stream:
        opened=os.fstat(stream.fileno());require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),"actual retained file identity")
        raw=stream.read();after=os.fstat(stream.fileno())
    require((opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==
        (after.st_size,after.st_mtime_ns,after.st_ctime_ns)and len(raw)==after.st_size,"complete stable retained bytes")
    return raw
def files(root,exclude=()):
    result={};root=Path(root)
    for base,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:require(stat.S_ISDIR((Path(base)/name).lstat().st_mode),"no linked retained directory")
        for name in names:
            path=Path(base)/name;rel=path.relative_to(root).as_posix()
            if rel not in exclude:result[rel]=dict(**pin(read(path)),mode=stat.S_IMODE(path.lstat().st_mode))
    return result
def source(root=ROOT,expected=None,schema="hepta.namespace-watcher.semantic-reader.v1"):
    raw=read(root/"SOURCE.json")
    if expected is not None:require(raw==expected,"exact frozen complete source manifest")
    manifest=loads(raw);require(manifest["schema"]==schema,"exact source schema")
    wanted={}
    for name,row in manifest["files"].items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts,"ordinary relative source")
        body=read(root/p);require(pin(body)=={k:row[k]for k in("bytes","sha256")}and git(body)==row["git_blob"]
            and row["mode"]=="100644","every complete source byte and Git identity")
        wanted[name]=dict(**pin(body),mode=0o644)
    require(files(root,("SOURCE.json",))==wanted,"complete source set and file modes")
    return pin(raw)["sha256"]
def word(raw,at):
    require(type(at)is int and 0<=at<=len(raw)-8,"whole scalar extent")
    return struct.unpack_from("<Q",raw,at)[0]
def integer(value,minimum=0,maximum=(1<<64)-1):
    return type(value)is int and minimum<=value<=maximum
def pair_path(path):
    p=Path(path);require(p.is_absolute()and".."not in p.parts,"recorded absolute path");return p
def read_lines(path):
    raw=read(path);require(not raw or raw.endswith(b"\n"),"all complete process JSON lines")
    result=[]
    for line in raw.splitlines(keepends=True):
        require(line.endswith(b"\n")and line!=b"\n","ordinary complete nonempty response")
        result.append((line,loads(line)))
    return raw,result
