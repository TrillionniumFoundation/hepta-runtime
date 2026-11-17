"""Exact file and source admission for the new serial session-owner recipe."""
from __future__ import annotations
import hashlib,json,os,stat,sys
from pathlib import Path
BASE = "tests/hia_native/caller_owner_export"
COMPILER_COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
SOURCE_SHA = "c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775"
IMAGE_SHA = "795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417"
SDK_MODEL_SHA = "ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a"
ORACLE = "tests/hia_native/owner_export_oracle"

def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def pairs(items):
    value = {}
    for key, member in items:
        require(key not in value, "duplicate JSON key")
        value[key] = member
    return value


def read(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute(), "nonregular or linked file: " + str(path))
    return path.read_bytes()


def document(path):
    return json.loads(read(path), object_pairs_hook=pairs)


def put(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else encoded(value)
    with path.open("xb") as handle:
        handle.write(raw)


def safe_relative(value):
    require(type(value) is str and value and not value.startswith("/") and
            all(part not in ("", ".", "..") for part in value.split("/")), "unsafe relative member")
    return value


def tree_files(root):
    root = Path(root).absolute()
    require(root.resolve() == root and root.is_dir(), "tree root is not an owned directory")
    result = {}
    for folder, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(folder) / name
            require(stat.S_ISDIR(path.lstat().st_mode) and path.resolve() == path, "linked tree directory")
        for name in names:
            path = Path(folder) / name
            raw = read(path)
            relative = path.relative_to(root).as_posix()
            result[relative] = {"bytes": len(raw), "sha256": sha(raw), "mode": stat.S_IMODE(path.stat().st_mode)}
    return dict(sorted(result.items()))



def source_evidence(source_root, expected_pins_sha=None):
    root=Path(source_root).absolute()
    raw=read(root/BASE/"source-pins.json")
    if expected_pins_sha is not None:require(sha(raw)==expected_pins_sha,"source pin manifest changed")
    pins=json.loads(raw,object_pairs_hook=pairs)
    require(pins["schema"]=="hepta.runtime.owner-export-source.v2" and pins["target_commit"]==TARGET_COMMIT and pins["compiler_commit"]==COMPILER_COMMIT,"source manifest identity")
    for name,row in pins["files"].items():
        data=read(root/safe_relative(name));require(row=={"bytes":len(data),"sha256":sha(data)},"source changed: "+name)
    require(sha(read(root/"native/caller_authority.hepta"))==SOURCE_SHA,"new owner source changed")
    require(sha(read(root/BASE/"reference/sdk-model.rs"))==SDK_MODEL_SHA,"target SDK model changed")
    sys.path.insert(0,str(root/"scripts"))
    import hia_native_owner_export_reference as reference
    original=reference.evidence(root)
    return {"pins_sha256":sha(raw),"files":pins["files"],"original":original}
