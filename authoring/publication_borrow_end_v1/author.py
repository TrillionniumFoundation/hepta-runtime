#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Reproduce exactly three mechanical edits; preserve every actual HIA byte."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PREFIX="authoring/publication_borrow_end_v1"
def require(value,message):
    if not value:raise ValueError(message)
def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def canonical(value):return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    before=json.loads((HERE/"BASE_SOURCE_ROWS.json").read_bytes());change=json.loads((HERE/"CHANGES.json").read_bytes())
    own=json.loads((HERE/"SOURCE_MANIFEST.json").read_bytes())
    require(before["commit"]==change["base"],"same exact predecessor")
    for row in own["files"]:
        require(pin((HERE/row["path"]).read_bytes())=={k:row[k] for k in ("bytes","sha256","git_blob")},"author source bytes")
    a.output.mkdir(parents=True,exist_ok=False)
    previous={}
    for row in before["rows"]:
        q=a.source/row["path"];raw=q.read_bytes()
        require(pin(raw)=={k:row[k] for k in ("bytes","sha256","git_blob")},"complete predecessor "+row["path"])
        previous[row["path"]]=raw;dest=a.output/row["path"];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(0o644)
    require(pin(previous["native/runtime_mcp_sources.json"])==change["base_binding"],"exact prior binding")
    for path,rule in change["edits"].items():
        raw=previous[path];require(pin(raw)==rule["before"],"exact edit before")
        text=raw.decode()
        for edit in rule["edits"]:
            require(text.count(edit["before"])==1,"unique forward edit");text=text.replace(edit["before"],edit["after"],1)
        actual=text.encode();require(pin(actual)==rule["after"],"exact edit after")
        for edit in reversed(rule["edits"]):
            require(text.count(edit["after"])==1,"unique inverse edit");text=text.replace(edit["after"],edit["before"],1)
        require(text.encode()==raw,"complete inverse source");(a.output/path).write_bytes(actual)
    paths=[row["path"] for row in own["files"]]+["SOURCE_MANIFEST.json"]
    for path in paths:
        out=a.output/PREFIX/path;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(HERE/path,out);out.chmod(0o644)
    binding=json.loads(previous["native/runtime_mcp_sources.json"])
    for path in [*change["edits"],*(PREFIX+"/"+p for p in paths)]:
        bound=pin((a.output/path).read_bytes());binding["sources"][path]={k:bound[k] for k in ("bytes","sha256")}
    binding["publication_borrow_end_extension"]={
        "base_commit":change["base"],"base_binding_sha256":change["base_binding"]["sha256"],
        "changes":PREFIX+"/CHANGES.json","cancel_and_drop_are_alternative_terminal_operations":True,
        "completed_scope_alias_released_after_full_detach_observation":True,
        "slot68_owns_no_mapping":True,"unchanged_hia":True,"public_async_qualified":False,"full_sdk":False}
    (a.output/"native/runtime_mcp_sources.json").write_bytes(canonical(binding))
    outrows=[]
    for q in sorted(a.output.rglob("*")):
        if q.is_file():
            path=q.relative_to(a.output).as_posix();raw=q.read_bytes();outrows.append(dict(path=path,mode="100644",**pin(raw)))
            if path.endswith(".hepta"):require(raw==previous[path],"every actual HIA unchanged")
    require(len(outrows)==len(before["rows"])+len(paths),"complete successor source set")
    print("BORROW_END_SOURCE_EXPORT "+json.dumps(dict(status="EXACT_THREE_MECHANICAL_EDITS_AND_ALL_HIA_UNCHANGED",
        rows=outrows,hia_executed=False,rust_executed=False,public_async_qualified=False),sort_keys=True))
    print("BORROW_END_BINDING_EXPORT "+json.dumps(dict(path="native/runtime_mcp_sources.json",
        utf8=(a.output/"native/runtime_mcp_sources.json").read_text(),**pin((a.output/"native/runtime_mcp_sources.json").read_bytes())),sort_keys=True))
if __name__=="__main__":main()
