"""Complete pinned source inventory and ordinary evidence helpers."""
from pathlib import Path,PurePosixPath
import ast,hashlib,json,stat
def require(v,m):
    if not v:raise ValueError(m)
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)+"\n").encode()
def decode(raw):
    def pairs(items):
        out={}
        for k,v in items:require(k not in out,"duplicate JSON key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError("nonfinite JSON")))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    p=Path(path)
    with p.open("rb") as f:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def owned(root,name):
    q=PurePosixPath(name);require(q.as_posix()==name and not q.is_absolute() and ".."not in q.parts,"owned relative source")
    p=Path(root)
    for part in q.parts:p=p/part;require(not p.is_symlink(),"source symlink")
    require(stat.S_ISREG(p.stat().st_mode),"ordinary owned source")
    return p
def source_evidence(root):
    root=Path(root);manifest=decode(owned(root,"SOURCE_MANIFEST.json").read_bytes());rows=manifest["files"]
    names={p.relative_to(root).as_posix() for p in root.rglob("*")if p.is_file()}
    require(len(rows)==len({x["path"]for x in rows}) and names=={x["path"]for x in rows}|{"SOURCE_MANIFEST.json"},"full source inventory")
    for r in rows:
        p=owned(root,r["path"]);raw=p.read_bytes()
        require(pin(p)=={k:r[k]for k in("bytes","sha256")} and p.stat().st_mode&0o777==0o644
            and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==r["git_blob"],"full source bytes/mode: "+r["path"])
    return dict(manifest=pin(root/"SOURCE_MANIFEST.json"),files=len(rows))

canonical=encoded
