"""Exact fixed-eight build admission; no native invocation in this module.

The complete original build reader is loaded byte-for-byte. Its deterministic
symbolic source proof is evaluated before a read-only guard and retained only
for those exact source/compiler roots. The reader itself rechecks every source
and compiler byte before it requests that prepared proof.
"""
import copy,sys,types
from pathlib import Path
from common import ROOT,read,loads,pin,require,source
NAMES=("common","original_build_invocation","pack_contract","read_build_fixed8",
       "authoring","authoring.author_fixed8")
def install(modules):
    saved={n:sys.modules.get(n)for n in NAMES}
    for n,m in modules.items():sys.modules[n]=m
    return saved
def restore(saved):
    for name,previous in saved.items():
        if previous is None:sys.modules.pop(name,None)
        else:sys.modules[name]=previous
def prepare(retained,pins_name="BUILD-PINS.json"):
    source();expected=loads(read(ROOT/pins_name));original=retained/"complete/source"
    raw=read(original/"SOURCE.json")
    require(pin(raw)==expected["source_manifests"]["source/SOURCE.json"],"whole exact fixed-eight producer source")
    sm=loads(raw)
    for n,r in sm["files"].items():
        p=Path(n);require(not p.is_absolute()and".."not in p.parts,"retained relative source")
        b=read(original/n);require(pin(b)=={k:r[k]for k in("bytes","sha256")},"every exact producer source byte")
    modules={};saved={n:sys.modules.get(n)for n in NAMES};path=list(sys.path)
    try:
        for name in NAMES[:4]:
            p=original/(name+".py");m=types.ModuleType(name);m.__file__=str(p);m.__package__=""
            sys.modules[name]=m;exec(compile(read(p),str(p),"exec"),m.__dict__);modules[name]=m
        package=types.ModuleType("authoring");package.__path__=[str(original/"authoring")]
        package.__package__="authoring";sys.modules["authoring"]=package;modules["authoring"]=package
        name="authoring.author_fixed8";p=original/"authoring/author_fixed8.py"
        m=types.ModuleType(name);m.__file__=str(p);m.__package__="authoring"
        sys.modules[name]=m;exec(compile(read(p),str(p),"exec"),m.__dict__);modules[name]=m
        compiler=retained/"complete/run/build/compiler-source"
        proof=m.proof(original,compiler)
        require(read(retained/"complete/run/fixed8-author/PROOF.json")==m.encoded(proof),
            "whole original deterministic proof recomputed before guard")
        def prepared_proof(source_root,compiler_root):
            require(source_root==original and compiler_root==compiler,"prepared proof exact admitted roots")
            return copy.deepcopy(proof)
        m.proof=prepared_proof
    finally:
        restore(saved);sys.path[:]=path
    require(modules["common"].ROOT==original,"only exact build source namespace")
    return dict(modules=modules,retained=retained,pins_name=pins_name,
        source_manifest_sha256=expected["source_sha256"],prepared_symbolic_proof=pin(read(retained/"complete/run/fixed8-author/PROOF.json")))
def verify(retained,prepared=None,pins_name="BUILD-PINS.json"):
    state=prepare(retained,pins_name)if prepared is None else prepared
    require(state["retained"]==retained and state["pins_name"]==pins_name,"same prepared physical build")
    saved=install(state["modules"])
    try:result=state["modules"]["read_build_fixed8"].verify(retained/"complete/run/build",retained/"complete/run/authored")
    finally:restore(saved)
    expected=loads(read(ROOT/pins_name))
    require(result["status"]==expected["source_build_read"] and result["image"]==expected["expected_flat"]
        and result["source_manifest_sha256"]==expected["source_sha256"]==state["source_manifest_sha256"]
        and result["fixed_eight_proof"]==state["prepared_symbolic_proof"],
        "exact fixed-eight source, actual compiled image and complete build reader")
    return result
