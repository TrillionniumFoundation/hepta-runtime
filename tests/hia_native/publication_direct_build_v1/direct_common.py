#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind the complete new fixture and unchanged full build reader before use."""
from pathlib import Path
import hashlib,json,stat,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(p):
    b=Path(p).read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def put(p,value):Path(p).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def package(recipe):
    manifest=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
    names={p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()}
    require(names=={r["path"] for r in manifest["files"]}|{"SOURCE_MANIFEST.json"},"whole private source set")
    for row in manifest["files"]:
        p=HERE/row["path"];b=p.read_bytes()
        require(not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o644
            and pin(p)=={k:row[k] for k in ("bytes","sha256")}
            and hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==row["git_blob"],"exact private source")
        if p.suffix==".py":compile(b,str(p),"exec")
    change=json.loads((HERE/"READER_EDITS.json").read_bytes())
    text=(Path(recipe)/"current/read_build.py").read_text()
    require(pin(Path(recipe)/"current/read_build.py")=={k:change["source"][k] for k in ("bytes","sha256")},"whole actual predecessor reader")
    for row in change["edits"]:
        require(text.count(row["before"])==1,"unique exact direct reader transformation")
        text=text.replace(row["before"],row["after"],1)
    require(text==(HERE/"read_build_direct.py").read_text(),"whole pure direct graph reader exact transformation")
    return dict(manifest=pin(HERE/"SOURCE_MANIFEST.json"),files=len(names),reader_transformations=len(change["edits"]))
def setup(recipe):
    recipe=Path(recipe).resolve(strict=True);identity=package(recipe)
    sys.path.insert(0,str(recipe/"current"))
    import async_build_common,restore_full,read_all,dynamic_builder,read_only_guard
    async_build_common.package()
    sys.path.insert(0,str(HERE))
    import direct_compose,read_build_direct
    direct_compose.evidence()
    return identity,async_build_common,restore_full,read_all,dynamic_builder,read_only_guard,read_build_direct
def prepare(previous,recipe):
    setup_result=setup(recipe);identity,ac,restore,old,builder,guard,reader=setup_result
    previous=Path(previous).resolve(strict=True)
    require(ac.files(previous.parent/"recipe-source")==ac.files(recipe),"entire actual uploaded build recipe")
    prepared=old.prepare(previous)
    return setup_result,prepared
def checked(output,previous,recipe):
    (identity,ac,restore,old,builder,guard,reader),prepared=prepare(previous,recipe)
    output=Path(output).resolve(strict=True);previous=Path(previous).resolve(strict=True)
    _,original,retained=prepared[0]
    builder.load(output/"source")
    return guard.guarded(lambda:dict(previous=old.operation(previous,prepared),
        direct=reader.verify(retained,output,original)),
        roots=[previous.parent,output,HERE,Path(recipe)],foreign_path=Path("/dev/null"))
