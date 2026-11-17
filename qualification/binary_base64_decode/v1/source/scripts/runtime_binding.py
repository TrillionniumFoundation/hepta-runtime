#!/usr/bin/env python3
"""Retain the exact actual reference interpreter and extension/library bytes."""
from pathlib import Path
import base64,binascii,os,shutil,sys
from common import canonical,decode,pin,require,owned
EXPECTED_PYTHON=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
def current():
    require(sys.version_info[:3]==(3,12,3)and sys.platform=="linux","actual CPython 3.12.3 reference")
    require(binascii.__spec__.origin=="built-in"and "binascii"in sys.builtin_module_names
        and not hasattr(binascii,"__file__"),"binascii must be bound by the pinned interpreter binary")
    paths=dict(python=Path(sys.executable).resolve(strict=True),
        base64=Path(base64.__file__).resolve(strict=True))
    require(pin(paths["python"])==EXPECTED_PYTHON,"reference interpreter binary differs")
    return dict(version=sys.version,platform=sys.platform,binascii_builtin=True,
        files={name:dict(path=str(path),**pin(path),mode=path.stat().st_mode&0o777)for name,path in paths.items()})
def prepare(capture):
    capture=Path(capture);value=current();out=capture/"reference-runtime";out.mkdir()
    for name,row in value["files"].items():
        target=out/name;shutil.copyfile(row["path"],target);target.chmod(row["mode"])
        require(pin(target)=={k:row[k]for k in("bytes","sha256")},"complete retained reference runtime")
    (out/"RUNTIME.json").write_bytes(canonical(value));return value
def bound(capture):
    value=decode(owned(capture,"reference-runtime/RUNTIME.json").read_bytes())
    require(value==current(),"reference process runtime differs")
    return value
def verify(capture):
    value=decode(owned(capture,"reference-runtime/RUNTIME.json").read_bytes())
    require(value["platform"]=="linux"and value["version"].startswith("3.12.3 ")
        and {k:value["files"]["python"][k]for k in("bytes","sha256")}==EXPECTED_PYTHON,
        "retained actual interpreter identity")
    require(set(value["files"])=={"python","base64"}and value["binascii_builtin"]is True,"whole reference runtime member domain")
    for name,row in value["files"].items():
        path=owned(capture,"reference-runtime/"+name)
        require(pin(path)=={k:row[k]for k in("bytes","sha256")}
            and path.stat().st_mode&0o777==row["mode"],"complete reference runtime bytes/mode")
    return value
