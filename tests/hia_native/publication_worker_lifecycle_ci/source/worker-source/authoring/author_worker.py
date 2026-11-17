#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Author the private publication worker lifetime owner with retained byte primitives."""
from pathlib import Path
import argparse,ast,copy,hashlib,json,sys
sys.dont_write_bytecode=True
def author(source,hepta,output):
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document,render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    original=(source/"authoring/publication_worker.pseudo").read_text()
    text=original
    for name,value in {"REQUEST_MAGIC":b"HPTWQ001","STATE_MAGIC":b"HPTWS001",
                       "RESULT_MAGIC":b"HPTWR001","GROW_MAGIC":b"HGRWS002"}.items():
        text=text.replace(name,str(int.from_bytes(value,"little")))
    nodes=ast.parse(text).body
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([x.annotation.id for x in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    result=compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"publication_worker_lifetime","functions":functions})
    baseline=(source/"retained/bellman_core.hepta").read_bytes()
    old=_parse_assembly_document(baseline)
    copies={"f5":names["read64"],"f6":names["get"],"f7":names["put"]}
    for before,after in copies.items():
        fn=copy.deepcopy(next(x for x in old["functions"] if x["name"]==before))
        assert all(op["op"]!="call" for block in fn["blocks"] for op in block["ops"])
        fn["name"]=after;result["functions"][int(after[1:])]=fn
    verify_program(result);raw=render_assembly(result).encode()
    assert _parse_assembly_document(raw)==result
    output.mkdir(parents=True,exist_ok=False)
    (output/"publication_worker.hepta").write_bytes(raw)
    digest=lambda x:hashlib.sha256(x).hexdigest()
    proof={"status":"SOURCE_AUTHOR_PASS","pseudo_sha256":digest(original.encode()),
        "author_sha256":digest(Path(__file__).read_bytes()),"baseline_sha256":digest(baseline),
        "source_bytes":len(raw),"source_sha256":digest(raw),"copied_byte_functions":copies,
        "functions":len(result["functions"]),"blocks":sum(len(f["blocks"]) for f in result["functions"]),
        "instructions":sum(len(b["ops"]) for f in result["functions"] for b in f["blocks"]),
        "native_executed":False,"public_route_qualified":False,"full_sdk":False}
    (output/"AUTHOR.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    return proof
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for n in ("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(author(a.source.resolve(),a.hepta.resolve(),a.output.absolute()),sort_keys=True))
