"""Frozen input and evidence identities; definitions only."""
from pathlib import Path
import hashlib,json,stat
ROOT=Path(__file__).resolve().parent
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def read(path):
    path=Path(path);before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and path.resolve()==path.absolute()
    raw=path.read_bytes();after=path.lstat()
    fields=lambda s:(s.st_mode,s.st_size,s.st_ino,s.st_dev,s.st_mtime_ns,s.st_ctime_ns)
    assert fields(before)==fields(after) and len(raw)==before.st_size
    return raw
def pin(raw):return dict(bytes=len(raw),sha256=SHA(raw))
def put(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(encoded(value))
def source(expected=None):
    raw=read(ROOT/"SOURCE_MANIFEST.json")
    if expected is not None:assert SHA(raw)==expected
    data=json.loads(raw)
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
    assert actual==set(data["files"])|{"SOURCE_MANIFEST.json"}
    for name,value in data["files"].items():assert pin(read(ROOT/name))==value,name
    return SHA(raw)
