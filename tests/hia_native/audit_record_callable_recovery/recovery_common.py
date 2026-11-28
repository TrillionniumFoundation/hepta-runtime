"""Source-bound pure recovery helpers; every original capture stays unchanged."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
BASE_SOURCE="f7a18ccac088bb820a2df262b4f5b700f11a2e6ee0f2f307f2ada4fa89f90d4b"
def need(ok,message):
    if not ok:raise ValueError(message)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def loads(raw):
    def pairs(items):
        result={}
        for name,value in items:
            need(name not in result,"no duplicate JSON member");result[name]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def relative(name):
    need(type(name) is str,"relative path type");p=PurePosixPath(name)
    need(name and p.as_posix()==name and not p.is_absolute() and
         all(x not in ("",".","..") for x in p.parts),"exact contained relative path")
    return p
def read(path):
    st=path.lstat();need(stat.S_ISREG(st.st_mode),"ordinary complete source/evidence file")
    with path.open("rb") as f:
        opened=os.fstat(f.fileno());body=f.read();after=os.fstat(f.fileno())
    need((st.st_dev,st.st_ino)==(opened.st_dev,opened.st_ino) and
         (opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==
         (after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(body)==after.st_size,"complete stable owned read")
    return body
def files(root):
    result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:need(stat.S_ISDIR((Path(folder)/name).lstat().st_mode),"ordinary contained directory")
        for name in names:
            path=Path(folder)/name
            result[path.relative_to(root).as_posix()]=dict(**pin(read(path)),mode=stat.S_IMODE(path.lstat().st_mode))
    return result
def source():
    raw=read(ROOT/"RECOVERY_SOURCE.json");manifest=loads(raw)
    need(manifest["schema"]=="hepta.audit-record-callable.reader-recovery-source.v1" and
         manifest["original_source_sha256"]==BASE_SOURCE,"exact original/recovery source binding")
    expected=manifest["files"]
    need(set(files(ROOT))==set(expected)|{"RECOVERY_SOURCE.json"},"complete exact recovery source set")
    for name,row in expected.items():
        data=read(ROOT/relative(name))
        need(pin(data)=={k:row[k] for k in ("bytes","sha256")} and
             hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["git_blob"],
             "complete frozen recovery file/Git identity: "+name)
    return pin(raw)["sha256"]
