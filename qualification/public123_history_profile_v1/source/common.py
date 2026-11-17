"""Complete byte identity primitives for the private publication qualification."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import stat

HEPTA = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
SCOPE = dict(source_materialization_only=True, hia_executed=False, rust_executed=False,
    public_wait_qualified=False, publisher_async_qualified=False, full_sdk=False,
    all_136_handlers=False, production_installed=False, old_stack_removed=False)

def require(value, message):
    if not value:
        raise ValueError(message)

def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()

def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate evidence key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(path):
    p = Path(path)
    with p.open("rb") as stream:
        return dict(bytes=p.stat().st_size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())

def owned(root, name):
    p = PurePosixPath(name)
    require(type(name) is str and not p.is_absolute() and ".." not in p.parts
        and p.as_posix() == name, "noncanonical evidence path")
    here = Path(root)
    for part in p.parts:
        here = here / part
        require(not here.is_symlink(), "symlink evidence path")
    require(here.is_file() and stat.S_ISREG(here.stat().st_mode), "missing ordinary evidence file")
    return here

def source_evidence(root):
    root = Path(root)
    manifest = decode(owned(root, "SOURCE_MANIFEST.json").read_bytes())
    rows = manifest["files"]
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual == {r["path"] for r in rows} | {"SOURCE_MANIFEST.json"}, "source closure changed")
    for row in rows:
        raw = owned(root, row["path"]).read_bytes()
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"]
            and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob"],
            "source bytes changed: " + row["path"])
        require((root/row["path"]).stat().st_mode & 0o777 == 0o644, "source mode differs")
    return dict(files=len(rows), manifest=pin(root/"SOURCE_MANIFEST.json"), scope=SCOPE)
