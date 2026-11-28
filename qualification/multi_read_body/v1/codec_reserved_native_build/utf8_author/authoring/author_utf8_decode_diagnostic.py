#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the strict UTF8 decode diagnostic used by the original multi-read body."""
from pathlib import Path
import argparse,ast,hashlib,json,re,sys
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
HELPERS=("load","get","put","copy_out","hex_digit","decimal")
LITERALS={
 "literal_byte":b"UnicodeDecodeError: 'utf-8' codec can't decode byte 0x",
 "literal_bytes":b"UnicodeDecodeError: 'utf-8' codec can't decode bytes in position ",
 "literal_position":b" in position ",
 "literal_colon":b": ",
 "literal_start":b"invalid start byte",
 "literal_continuation":b"invalid continuation byte",
 "literal_end":b"unexpected end of data"}
def literal(name,raw):
    lines=["","def "+name+"(w:mutbuf,at:u64) -> u64:"]
    end=len(raw)//8*8
    for i in range(0,end,8):lines.append("    put(w,at+"+str(i)+","+str(int.from_bytes(raw[i:i+8],"little"))+")")
    for i in range(end,len(raw)):lines.append("    store(w,at+"+str(i)+","+str(raw[i])+")")
    lines.append("    return at+"+str(len(raw)))
    return "\n".join(lines)+"\n"
def main():
    p=argparse.ArgumentParser()
    for name in("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists()
    provenance=json.loads((source/"PROVENANCE.json").read_bytes())
    for name,row in provenance["files"].items():
        raw=(source/name).read_bytes();assert len(raw)==row["bytes"]and SHA(raw)==row["sha256"],name
    target=(source/"target/multi_read_host.py").read_bytes()
    assert SHA(target)=="6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5"
    tree=ast.parse(target);body=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=="multi_read")
    calls=[n for n in ast.walk(body)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=="decode"]
    assert len(calls)==1
    expected=ast.parse("data.decode('utf-8', errors='strict')",mode="eval").body
    assert ast.dump(calls[0],include_attributes=False)==ast.dump(expected,include_attributes=False)
    baseline=(source/"baseline/binary_read_body.pseudo").read_text()
    pseudo=(source/"authoring/utf8_decode_diagnostic.pseudo").read_text()
    before={n.name:n for n in ast.parse(baseline).body if isinstance(n,ast.FunctionDef)}
    own={n.name:n for n in ast.parse(pseudo).body if isinstance(n,ast.FunctionDef)}
    proof={}
    for name in HELPERS:
        old=ast.dump(before[name],include_attributes=False);new=ast.dump(own[name],include_attributes=False)
        assert old==new,name;proof[name]=SHA(old.encode())
    constants={"REQUEST":int.from_bytes(b"HUTFQ001","little"),"RESPONSE":int.from_bytes(b"HUTFD001","little"),
        "INVALID":0xffffffff,"CAPACITY":0xfffffffe,"LIMIT":0xffff0000,"DECIMAL":256}
    for name,raw in LITERALS.items():pseudo+=literal(name,raw)
    generated=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(generated).body
    assert all(isinstance(n,ast.FunctionDef)for n in nodes)and nodes[0].name=="entry"
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([v.annotation.id for v in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v)for v in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    document=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="utf8_decode_diagnostic",functions=functions))
    raw=render_assembly(document).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    ops=sum(len(b["ops"])for fn in actual["functions"]for b in fn["blocks"])
    assert ops<=8192
    for fn in actual["functions"]:
        assert len(fn["blocks"])<=256 and max(len(b["params"])for b in fn["blocks"])<=16
    receipt=dict(schema="hepta.runtime.utf8-decode-diagnostic.author.v1",target_commit=provenance["target_commit"],
        target_sha256=SHA(target),target_call_ast_sha256=SHA(ast.dump(calls[0],include_attributes=False).encode()),
        source_bytes=len(raw),source_sha256=SHA(raw),functions=len(functions),instructions=ops,aliases=names,
        constants=constants,helper_ast_sha256=proof,
        function_sha256={fn["name"]:SHA(CANON(fn))for fn in actual["functions"]},
        native_compiled=False,native_executed=False,original_compared=False,public_route=False,whole_runtime_replaced=False)
    out.mkdir(parents=True)
    (out/"utf8_decode_diagnostic.hepta").write_bytes(raw)
    (out/"utf8_decode_diagnostic_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"utf8_decode_diagnostic.pseudo").write_text(generated)
    print(json.dumps(dict(status="SOURCE_AUTHOR_ONLY_PASS",functions=len(functions),instructions=ops,
        source_bytes=len(raw),source_sha256=SHA(raw),application_calls=0),sort_keys=True))
if __name__=="__main__":main()
