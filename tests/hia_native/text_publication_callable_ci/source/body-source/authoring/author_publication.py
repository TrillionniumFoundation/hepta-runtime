#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Author a private current-target publication policy; no Rust/native execution."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())

def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()

def literal(name, raw):
    code = ["def "+name+"(w:mutbuf,at:u64) -> u64:"]
    for i in range(0,len(raw)//8*8,8):
        code.append("    put(w,at+"+str(i)+","+str(int.from_bytes(raw[i:i+8],"little"))+")")
    for i in range(len(raw)//8*8,len(raw)):
        code.append("    store(w,at+"+str(i)+","+str(raw[i])+")")
    code.append("    return at+"+str(len(raw)))
    return "\n".join(code)+"\n"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    source=a.source.resolve(strict=True)
    hepta=a.hepta.resolve(strict=True)
    output=a.output.absolute()
    assert not output.exists()
    output.mkdir(parents=True)
    target=(source/"target/text_file_write.rs").read_bytes()
    assert pin(target)["sha256"]=="f502197e7409c5d565b1c3328816dceb9cacac8031fb4fbadd20b473286facfc"
    errors=json.loads((source/"authoring/errors.json").read_bytes())
    literals=json.loads((source/"authoring/literals.json").read_bytes())
    pseudo=(source/"authoring/publication.pseudo").read_text()
    for key,text in errors.items():
        assert ('"'+text+'"').encode() in target
        pseudo+="\n"+literal("error_"+key,text.encode())
    pseudo+="\ndef error_literal(w:mutbuf,at:u64,code:u64) -> u64:\n"
    for key in errors:
        pseudo+="    if code=="+key+":\n        return error_"+key+"(w,at)\n"
    pseudo+="    return at\n"
    for name,text in literals.items():pseudo+="\n"+literal(name,text.encode())
    constants={
      "REQUEST":int.from_bytes(b"HTPBQ001","little"),"RESPONSE":int.from_bytes(b"HTPBS001","little"),
      "WORK_MAGIC":int.from_bytes(b"HTPWK001","little"),"CODEC":int.from_bytes(b"HRCODEC1","little"),
      "INVALID":0xffffffff,"CAPACITY":0xfffffffe,"NEXT":0xfffffffd,"MAXIMUM":(1<<64)-1,
      "MAX_PATH":16<<20,"MAX_INPUT":16<<20,"MAX_EXPECT":16<<20,
      "PATH":4096,"OLD_STAT":1024,"LAST_STAT":1200,"STAGED":1408,
      "OLD_DIGEST":1472,"NEW_DIGEST":1536,"TEMP_NAME":1600,"CODEC_STATE":1664,
      "OS_ERROR":2048,"DECIMAL":3072,
      "CONTENT":"get(w,304)","EXPECT":"get(w,312)","READ_DATA":"get(w,320)",
      "DATA":"get(w,328)","COMPONENT":"get(w,336)","RESULT":"get(w,344)"}
    expanded=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(expanded).body
    assert all(isinstance(node,ast.FunctionDef) for node in nodes)
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    assert names["entry"]=="f0"
    signatures={node.name:([v.annotation.id for v in node.args.args],node.returns.id) for node in nodes}
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class B(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="copy_within":
                values=[self.expr(v) for v in node.args]
                return self.op("buffer.move_within",[values[0],*(self.cast(v,"usize") for v in values[1:])])
            return super().expr(node)
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=B(node,names,signatures,total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=["read","write","trap"],entry="b0",blocks=builder.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="text_file_publication",functions=functions))
    for function in program["functions"]:
        assert len(function["blocks"])<=256,function["name"]
        assert max(len(b["params"]) for b in function["blocks"])<=16,function["name"]
    raw=render_assembly(program).encode()
    actual=assemble_program(raw).as_dict()
    assert actual==program
    (output/"text_file_publication.hepta").write_bytes(raw)
    (output/"expanded.pseudo").write_text(expanded)
    proof=dict(schema="hepta.runtime.text-file-publication.source.v1",target_commit="d3d75c30719db966b004756f610007a7c723729e",
        original_file=pin(target),source=pin(raw),pseudo=pin((source/"authoring/publication.pseudo").read_bytes()),
        expanded_pseudo=pin(expanded.encode()),author=pin(Path(__file__).read_bytes()),constants=constants,aliases=names,
        functions=len(actual["functions"]),blocks=sum(len(f["blocks"]) for f in actual["functions"]),
        operation_counts={f["name"]:sum(len(b["ops"]) for b in f["blocks"]) for f in actual["functions"]},
        private_policy_only=True,syscalls_emitted_by_hia=True,sha256_via_actual_binary_codec=True,
        python_policy_implementation=False,public_route_integrated=False,full_async_qualified=False,
        current_original_compared=False,native_compiled=False,native_executed=False)
    (output/"text_file_publication_composition.json").write_bytes(encoded(proof))
    print(json.dumps(proof,sort_keys=True))

if __name__=="__main__":main()
