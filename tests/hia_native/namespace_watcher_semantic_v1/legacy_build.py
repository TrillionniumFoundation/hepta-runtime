"""Admit an exact existing Watcher build with its unchanged full original reader."""
import sys,types
from pathlib import Path
from common import ROOT,read,loads,pin,require,source
NAMES=("common","original_build_invocation","pack_contract","read_callable_prepare")
def prepare(retained):
    source();expected=loads(read(ROOT/"BUILD-PINS.json"));original=retained/"complete/source"
    raw=read(original/"SOURCE.json");require(pin(raw)==expected["source_manifests"]["source/SOURCE.json"],
        "complete runtime producer source manifest")
    sm=loads(raw)
    for n,r in sm["files"].items():
        p=Path(n);require(not p.is_absolute()and".."not in p.parts,"original relative source")
        b=read(original/n);require(pin(b)=={k:r[k]for k in("bytes","sha256")},"every original source byte")
    modules={};saved={n:sys.modules.get(n)for n in NAMES}
    try:
        for name in NAMES:
            path=original/(name+".py");module=types.ModuleType(name);module.__file__=str(path)
            module.__package__="";sys.modules[name]=module
            exec(compile(read(path),str(path),"exec"),module.__dict__);modules[name]=module
    finally:
        for name,previous in saved.items():
            if previous is None:sys.modules.pop(name,None)
            else:sys.modules[name]=previous
    require(modules["common"].ROOT==original,"only the exact immutable legacy source closure")
    return modules
def verify(retained,prepared=None):
    modules=prepare(retained)if prepared is None else prepared
    result=modules["read_callable_prepare"].verify(retained/"complete/run/build",retained/"complete/run/authored")
    expected=loads(read(ROOT/"BUILD-PINS.json"))
    require(result["image"]==expected["expected_flat"]and
        result["source_manifest_sha256"]==expected["source_sha256"],"exact compiled unchanged Watcher runtime")
    return result
