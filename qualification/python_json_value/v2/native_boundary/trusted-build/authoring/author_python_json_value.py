#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the CPython JSON value owner; no original or native application calls."""
import argparse,ast,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser()
    for key in("source","hepta","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.generate_hia_agent_binary64 import source_program as decimal_source
    from tools.generate_hia_agent_binary64_format import source_program as float_source
    pins={"tools/generate_hia_agent_binary64.py":"22730e6632b04145a14b2d2d95e0c862b0da337ecf0364574c0829ab66f395e3",
        "tools/generate_hia_agent_binary64_format.py":"dee2d6ec42dab0a09cba8e8e8917464d3a79cff9e217a5668833a56bf1b4f784"}
    for path,digest in pins.items():assert SHA((hepta/path).read_bytes())==digest
    math=ast.parse(decimal_source())
    convert=math.body[0];assert convert.name=="convert"
    text=ast.get_source_segment(decimal_source(),convert)
    assert "def convert(s:readbuf, o:mutbuf, w:mutbuf)"in text
    text=text.replace("def convert(s:readbuf, o:mutbuf, w:mutbuf)","def convert(w:mutbuf, source:u64, n:u64)")
    text=text.replace("    n = length(s)\n","")
    text=text.replace("if length(o) < 8 or length(w) < 4096:","if length(w) < 8192:")
    text=re.sub(r"byte\(s, ([^)]+)\)",r"byte(w, source+\1)",text)
    text=text.replace("put(o, 0,","put(w, 8192,")
    assert "byte(s,"not in text and "put(o,"not in text
    converted=ast.parse(text).body[0]
    converted.returns=ast.Name(id='u64',ctx=ast.Load())
    fmt_source=float_source();formatted=ast.parse(fmt_source).body[0]
    assert formatted.name=="render_binary64"
    text=ast.get_source_segment(fmt_source,formatted)
    text=text.replace("def render_binary64(s:readbuf, o:mutbuf, w:mutbuf)","def format_binary64(w:mutbuf, original:u64, destination:u64)")
    text=text.replace("    if length(s) != 8:\n        return 4294967295\n","")
    text=text.replace("    original = read64(s, 0)\n","")
    text=text.replace("    if length(o) < cursor:\n        return 4294967294\n","")
    text=text.replace("store(o, i, byte(w, 6144 + i))","store(w, destination+i, byte(w, 6144 + i))")
    assert "read64(s"not in text and "store(o,"not in text
    formatted=ast.parse(text).body[0]
    formatted.returns=ast.Name(id='u64',ctx=ast.Load())
    helpers={}
    for node in [*math.body[1:],*ast.parse(fmt_source).body[1:]]:
        if node.name=="read64":continue
        if node.name in helpers:assert ast.dump(helpers[node.name],include_attributes=False)==ast.dump(node,include_attributes=False)
        else:helpers[node.name]=node
    pseudo="\n\n".join((root/"authoring"/name).read_text()for name in
        ("parser.pseudo","objects.pseudo","compare.pseudo"))
    constants=dict(REQUEST=int.from_bytes(b"HPYJSQ01","little"),RESPONSE=int.from_bytes(b"HPYJSR01","little"),
        NEXT=12288,HEAP=12296,BASE=12304,END=12312,CURSOR=12320,ERR=12328,POSITION=12336,DETAIL=12344,
        DUMP_BUDGET=12352,KEY_BASE=12360,KEY_SIZE=12368,SORT_HEAD=12376,SORT_TAIL=12384,EQ_BUDGET=12392,PARSE_DEPTH=12400,PARSE_BUDGET=12408)
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    literals=json.loads((root/"authoring/literals.json").read_bytes())
    for name,value in literals.items():
        raw=value.encode("utf-8");pseudo+="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
        words=len(raw)//8*8
        for i in range(0,words,8):pseudo+="    put(w,at+"+str(i)+","+str(int.from_bytes(raw[i:i+8],"little"))+")\n"
        for i in range(words,len(raw)):pseudo+="    store(w,at+"+str(i)+","+str(raw[i])+")\n"
        pseudo+="    return at+"+str(len(raw))+"\n"
    nodes=ast.parse(pseudo).body+[converted,formatted,*helpers.values()]
    assert nodes[0].name=="entry"
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)};assert len(names)==len(nodes)
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total)
        try:b.statements(n.body)
        except BaseException:
            print("AUTHOR_FUNCTION "+n.name,flush=True)
            raise
        functions.append(dict(name=names[n.name],params=[b.param(p)for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    for f in functions:
        types={v["name"]:v["type"]for b in f["blocks"]for v in b["params"]}
        types.update({v["name"]:v["type"]for b in f["blocks"]for op in b["ops"]for v in op["out"]})
        for b in f["blocks"]:
            for op in b["ops"]:
                if op["op"].startswith("compare."):
                    assert len({types[v]for v in op["args"]})==1,(f["name"],b["id"],op,[types[v]for v in op["args"]])
    compact=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="python_json_value",functions=functions))
    operations=sum(len(b["ops"])for f in compact["functions"]for b in f["blocks"])
    blocks=sum(len(f["blocks"])for f in compact["functions"])
    stats=dict(functions=len(functions),instructions=operations,blocks=blocks,
        per_function=[dict(alias=next(k for k,v in names.items()if v==f["name"]),name=f["name"],
            instructions=sum(len(b["ops"])for b in f["blocks"]),blocks=len(f["blocks"]),
            max_block_arguments=max(len(b["params"])for b in f["blocks"]))for f in compact["functions"]])
    print(json.dumps(dict(status="AUTHOR_RESOURCE_ACCOUNTING",**stats),sort_keys=True),flush=True)
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(functions)<=limits["functions"]==128 and operations<=8192 and blocks<=limits["blocks_total"]==1536
    for f in compact["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048,f["name"]
    raw=render_assembly(compact).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    receipt=dict(schema="hepta.runtime.python-json-value.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        **stats,aliases=names,constants=constants,upstream_numeric_sources=pins,
        function_sha256={f["name"]:SHA(json.dumps(f,sort_keys=True,separators=(",",":")).encode())for f in actual["functions"]},
        original_profile="CPython 3.12.3 JSON values with explicit caller recursion budgets",
        source_limit=8388608,integer_decimal_digit_limit=4300,workspace_formula="16480 + 40 * total UTF-32 code points",
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"python_json_value.hepta").write_bytes(raw)
    (out/"python_json_value_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"python_json_value.pseudo").write_text(pseudo+"\n\n"+"\n\n".join(ast.unparse(n)for n in[converted,formatted,*helpers.values()])+"\n")
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
