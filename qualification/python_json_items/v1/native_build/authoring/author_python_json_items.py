#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author a native JSON dictionary-item stream from exact qualified HIA IR."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def main():
    p=argparse.ArgumentParser()
    for key in("source","hepta","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    baseline=(root/"baseline/python_json_value.hepta").read_bytes()
    composition_raw=(root/"baseline/python_json_value_composition.json").read_bytes()
    assert SHA(baseline)=="6f80633f2037b8d21d19cd56bb9ba7755e769913068c1422ffc239d233d65a65"
    assert SHA(composition_raw)=="4260e36ff8b8e2710530edf6d65cf2774e76945266797003112874888d16fe83"
    original=assemble_program(baseline).as_dict();composition=json.loads(composition_raw)
    funcs={f["name"]:f for f in original["functions"]};assert len(funcs)==110
    for name,f in funcs.items():assert SHA(CANON(f))==composition["function_sha256"][name]
    roots=("parse","original_order","original_next","load","get","put","header","scalar_truth",
        "integer_size","integer_negative","integer_output","report_error","attribute_error","type_name","no_attribute","character")
    selected={composition["aliases"][n]for n in roots};todo=list(selected)
    while todo:
        name=todo.pop()
        for block in funcs[name]["blocks"]:
            for op in block["ops"]:
                if op["op"]=="call":
                    child=op["attrs"]["function"];assert child in funcs
                    if child not in selected:selected.add(child);todo.append(child)
    assert "f0"not in selected
    ordered=sorted(selected,key=lambda x:int(x[1:]));rename={old:"f"+str(i+1)for i,old in enumerate(ordered)}
    inverse={new:old for old,new in rename.items()}
    def relocate(function,mapping):
        result=copy.deepcopy(function);result["name"]=mapping[result["name"]]
        for block in result["blocks"]:
            for op in block["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=mapping[op["attrs"]["function"]]
        return result
    retained=[relocate(funcs[name],rename)for name in ordered]
    for old,new in zip(ordered,retained):assert relocate(new,inverse)==funcs[old]
    constants=dict(REQUEST=int.from_bytes(b"HPYJSQ01","little"),
        VALUE_RESPONSE=int.from_bytes(b"HPYJSR01","little"),ITEMS_RESPONSE=int.from_bytes(b"HPYJIR01","little"),
        INVALID=4294967295,CAPACITY=4294967294,WORKSPACE=4294967293)
    pseudo=(root/"authoring/python_json_items.pseudo").read_text()
    pseudo+="\ndef items_suffix(w:mutbuf,at:u64) -> u64:\n"
    for i,b in enumerate(b"items'"):pseudo+="    store(w,at+"+str(i)+","+str(b)+")\n"
    pseudo+="    return at+6\n"
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body;assert nodes[0].name=="entry"
    names={alias:rename[name]for alias,name in composition["aliases"].items()if name in rename}
    assert not({n.name for n in nodes}&set(names))
    names["entry"]="f0"
    for i,n in enumerate(nodes[1:]):names[n.name]="f"+str(len(retained)+1+i)
    signatures={alias:([p["type"]for p in funcs[name]["params"]],funcs[name]["returns"][0])
        for alias,name in composition["aliases"].items()if name in rename}
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    total=total_scalar_functions(nodes);fresh=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        fresh.append(dict(name=names[n.name],params=[b.param(p)for p in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    document=dict(schema="hepta.hia.program.v8",module="python_json_items",functions=[fresh[0],*retained,*fresh[1:]])
    compact=compact_authoring_cfg(document);compact["functions"][1:len(retained)+1]=retained
    raw=render_assembly(compact).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw and actual["functions"][1:len(retained)+1]==retained
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    blocks=sum(len(f["blocks"])for f in actual["functions"])
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"])<=limits["functions"]==128 and operations<=8192 and blocks<=limits["blocks_total"]==1536
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048,f["name"]
    receipt=dict(schema="hepta.runtime.python-json-items.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,constants=constants,
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained=dict(source_commit="02bbeabc34a219f1d160904cec4994bff974df03",source_sha256=SHA(baseline),
            composition_sha256=SHA(composition_raw),roots=list(roots),functions=len(retained),relocations=rename,
            inverse_relocation_exact_ir=True,omitted_unreachable_functions=len(funcs)-len(retained)),
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"python_json_items.hepta").write_bytes(raw)
    (out/"python_json_items_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"python_json_items.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
