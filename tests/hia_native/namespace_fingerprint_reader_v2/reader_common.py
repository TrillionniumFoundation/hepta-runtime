"""Source custody for the separately frozen pure-reader successor."""
from pathlib import Path
import hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
def check(value,message):
    if not value:raise ValueError(message)
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pairs(rows):
    out={}
    for key,value in rows:
        check(key not in out,"duplicate JSON key");out[key]=value
    return out
def loads(raw):return json.loads(raw,object_pairs_hook=pairs)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
    before=path.lstat();check(stat.S_ISREG(before.st_mode),"ordinary retained file")
    with path.open("rb") as stream:
        opened=os.fstat(stream.fileno());check((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),"opened original identity")
        raw=stream.read();after=os.fstat(stream.fileno())
    check((opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==after.st_size,"stable complete read")
    return raw
def files(root):
    result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:check(stat.S_ISDIR((Path(folder)/name).lstat().st_mode),"ordinary directory")
        for name in names:
            path=Path(folder)/name;result[path.relative_to(root).as_posix()]=dict(**pin(read(path)),mode=stat.S_IMODE(path.lstat().st_mode))
    return result
def source():
    raw=read(ROOT/"SOURCE.json");m=loads(raw)
    check(m["schema"]=="hepta.namespace-fingerprint.reader-source.v1","frozen recovery source schema")
    check(set(files(ROOT))==set(m["files"])|{"SOURCE.json"},"whole recovery source set")
    for name,row in m["files"].items():
        body=read(ROOT/name)
        check(pin(body)=={k:row[k] for k in ("bytes","sha256")} and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"whole recovery source "+name)
    return pin(raw)["sha256"]
