#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Register read names through exact predecessor continuation and result paths."""
from pathlib import Path
import argparse
import copy
import json
import subprocess
import sys
sys.dont_write_bytecode=True
BASE="8ac803a79135f4cd2d5efc93c77905d63f4bc2ea"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--hepta",type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(args.hepta.resolve(strict=True));_,_,_,assemble,render=api
    def before_file(name):
        return subprocess.check_output(["git","show",BASE+":"+name],cwd=root)
    original=before_file("native/runtime_mcp.hepta")
    comp=json.loads(before_file("native/runtime_mcp_composition.json"))
    before=assemble(original).as_dict();old={f["name"]:f for f in before["functions"]}
    support.require(comp["source_sha256"]==support.SHA(original),"original frontend whole source differs")
    support.require(comp["function_sha256"]=={n:support.SHA(support.CANON(f)) for n,f in old.items()},"original frontend AST index differs")
    names=dict(comp["functions"]);count=len(old)
    extra={name:"f"+str(count+i) for i,name in enumerate(
        ("retained_read_tool_kind","retained_read_prepare","prepare_file_info","prepare_binary_read","retained_read_after_tool","binary_request_magic"))}
    support.require(not names.keys() & extra.keys(),"read alias collision")
    names.update(extra);seed=copy.deepcopy(before)
    relocated={names["tool_kind"]:extra["retained_read_tool_kind"],names["prepare"]:extra["retained_read_prepare"],names["after_tool"]:extra["retained_read_after_tool"]}
    for name,destination in relocated.items():
        f=copy.deepcopy(old[name]);f["name"]=destination;seed["functions"].append(f)
    edits={};shared_magic=None
    for alias,magic in (("prepare_file_info","HRDIQ002"),("prepare_binary_read","HRDRQ002")):
        f=copy.deepcopy(old[names["prepare_extract"]]);f["name"]=extra[alias];changes=[]
        for block in f["blocks"]:
            for op in block["ops"]:
                if op["op"]!="const":continue
                value=op["attrs"]["value"]
                if value==support.WORD("HEXWGQ02"):
                    changes.append([block["id"],op["out"],value,support.WORD(magic)])
                    op["attrs"]["value"]=support.WORD(magic)
                elif block["id"]=="b16" and op["out"]==[{"name":"v177","type":"u64"}]:
                    support.require(value==15,"old extract local child differs")
                    changes.append([block["id"],op["out"],15,17]);op["attrs"]["value"]=17
        support.require(len(changes)==2,"only request identity and fixed child may change")
        if alias=="prepare_binary_read":
            block=next(b for b in f["blocks"] if b["id"]=="b13")
            index=next(i for i,op in enumerate(block["ops"]) if op["out"]==[{"name":"v119","type":"u64"}])
            old_magic=copy.deepcopy(block["ops"][index])
            support.require(old_magic=={"args":[],"attrs":{"value":support.WORD("HRDRQ002")},"op":"const","out":[{"name":"v119","type":"u64"}]},"shared request magic anchor differs")
            support.require(block["ops"][index+1]["args"]==["v111","v118","v119"],"original request workspace differs")
            new_magic={"args":["v111"],"attrs":{"function":extra["binary_request_magic"]},"op":"call","out":old_magic["out"]}
            block["ops"][index]=new_magic
            shared_magic={"block":"b13","out":old_magic["out"],"old":old_magic,"new":copy.deepcopy(new_magic)}
        seed["functions"].append(f);edits[alias]=changes
    stub=("hia-asm.v1 hepta.hia.program.v8 public_read_dispatch_seed\nfn "+extra["binary_request_magic"]+"(v0:mutbuf) -> (u64) effects(read,write,trap) entry(b0)\nblock b0(v0:mutbuf)\n  v1:u64 = const() {\"value\":0}\n  ret(v1)\nend\n").encode()
    seed["functions"].append(assemble(stub).as_dict()["functions"][0])
    constants={"INFO_WORD":support.WORD("file_inf"),"READ_WORD":support.WORD("binary_r"),"MULTI_WORD0":support.WORD("read_mul"),"MULTI_WORD1":support.WORD("tiple_fi"),"MULTI_REQUEST":support.WORD("HRDMQ002"),"READ_REQUEST":support.WORD("HRDRQ002")}
    raw,aliases,proof=support.compile_delta(api,render(seed).encode(),names,
        (root/"authoring/public_read/frontend.pseudo").read_text(),constants,before["module"])
    after={f["name"]:f for f in assemble(raw).as_dict()["functions"]}
    for name,f in old.items():
        if name not in relocated:support.require(after[name]==f,"retained frontend function differs: "+name)
    for name,destination in relocated.items():
        f=copy.deepcopy(after[destination]);f["name"]=name
        support.require(f==old[name],"relocated frontend inverse differs")
    for alias,changes in edits.items():
        f=copy.deepcopy(after[extra[alias]]);f["name"]=names["prepare_extract"]
        if alias=="prepare_binary_read":
            block=next(b for b in f["blocks"] if b["id"]==shared_magic["block"])
            index=next(i for i,op in enumerate(block["ops"]) if op["out"]==shared_magic["out"])
            support.require(block["ops"][index]==shared_magic["new"],"shared request dispatch differs")
            block["ops"][index]=copy.deepcopy(shared_magic["old"])
        for bid,out,previous,current in changes:
            op=next(op for b in f["blocks"] if b["id"]==bid for op in b["ops"] if op["out"]==out)
            support.require(op["attrs"]["value"]==current,"prepared read inverse anchor differs")
            op["attrs"]["value"]=previous
        support.require(f==old[names["prepare_extract"]],"complete prepared read inverse differs")
    proof.update(schema="hepta.runtime.public-read.frontend-author.v1",base_commit=BASE,
        baseline=support.identity(original),relocated=relocated,request_changes=edits,shared_request_magic=shared_magic,
        retained_functions={n:support.SHA(support.CANON(f)) for n,f in old.items() if n not in relocated},
        whole_prepared_request_inverse_exact=True,entry_exact=True,after_tool_complete_original_relocated=True,read_drop_fixed_child=17,
        local_child=17,global_descriptor=73,tool_kinds={"file_info":14,"binary_read":15,"read_multiple_files":16},
        catalog_changed=False,public_route_qualified=False,old_stack_removed=False)
    comp.update(source_sha256=support.SHA(raw),source_bytes=len(raw),functions=aliases,
        function_sha256={n:support.SHA(support.CANON(f)) for n,f in after.items()},public_read_extension=proof)
    (root/"native/runtime_mcp.hepta").write_bytes(raw)
    (root/"native/runtime_mcp_composition.json").write_bytes(support.ENCODE(comp))
    (root/"native/runtime_mcp_read_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"sha256":support.SHA(raw),"bytes":len(raw),"functions":len(after),
                      "public_route_qualified":False},sort_keys=True))
if __name__=="__main__":
    main()
