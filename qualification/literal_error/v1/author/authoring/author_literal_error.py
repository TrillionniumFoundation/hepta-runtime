#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Add three literal exception classes while retaining every qualified path-error function."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def main():
    p=argparse.ArgumentParser()
    for name in("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    baseline=(source/"baseline/path_error.hepta").read_bytes()
    composition_raw=(source/"baseline/path_error_composition.json").read_bytes()
    platform=(source/"baseline/platform_data.json").read_bytes()
    assert SHA(baseline)=="24f8e7e735a2c0c8b8b1a94958ab6d145b420ff00e54eab5f04525c3679c9f11"
    assert SHA(composition_raw)=="26cf99d5d6e881930896dba07fd99e2085b31ce3af3f23eb0da3a3ec8e52805b"
    assert SHA(platform)=="01433965084eea53dfd903866fb33e8a53f4a3e63a2d828ba5d00ddd1ca93829"
    composition=json.loads(composition_raw);baseline_ir=assemble_program(baseline).as_dict();old=baseline_ir["functions"]
    assert len(old)==32 and[f["name"]for f in old]==["f"+str(i)for i in range(32)]
    for f in old:
        assert SHA(CANON(f))==composition["function_sha256"][f["name"]]
        assert not any(op["op"]=="call"and op.get("attrs",{}).get("function")=="f0"for b in f["blocks"]for op in b["ops"])
    constants=dict(composition["constants"])
    pseudo=(source/"authoring/literal_error.pseudo").read_text()
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert [n.name for n in nodes]==["dispatch","literal_entry"]and all(isinstance(n,ast.FunctionDef)for n in nodes)
    names=dict(composition["aliases"]);names.update(dispatch="f0",previous_path_entry="f32",literal_entry="f33")
    byname={f["name"]:f for f in old};signatures={}
    for alias,name in composition["aliases"].items():
        f=byname[name];signatures[alias]=([x["type"]for x in f["params"]],f["returns"][0])
    signatures["previous_path_entry"]=signatures["dispatch"]
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    total=total_scalar_functions(nodes);fresh=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        fresh.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    relocated=copy.deepcopy(old[0]);relocated["name"]="f32"
    retained=copy.deepcopy(old[1:])+[relocated]
    document=dict(schema="hepta.hia.program.v8",module="literal_error",functions=[fresh[0],*retained,*fresh[1:]])
    compacted=compact_authoring_cfg(document);compacted["functions"][1:33]=retained
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw and actual["functions"][1:33]==retained
    recovered=copy.deepcopy(actual["functions"][32]);recovered["name"]="f0";assert recovered==old[0]
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"])==34 and len(actual["functions"])<=limits["functions"]==128 and operations<=8192
    blocks=sum(len(f["blocks"])for f in actual["functions"]);assert blocks<=limits["blocks_total"]==1536
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048,f["name"]
    receipt=dict(schema="hepta.runtime.literal-error.author.v1",source_sha256=SHA(raw),source_bytes=len(raw),
        functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,constants=constants,
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained_legacy=dict(qualified_commit="b9e31de096eed65c217b12329c9fcf3f9a3284d3",
            source_sha256=SHA(baseline),composition_sha256=SHA(composition_raw),functions=32,
            entry_relocation={"f0":"f32"},other_function_names_unchanged=True),
        literal_classes={"15":"Error","16":"NotImplementedError","17":"RuntimeError"},
        platform_data_sha256=SHA(platform),data_sha256=composition["data_sha256"],
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"literal_error.hepta").write_bytes(raw)
    (out/"literal_error_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"literal_error.pseudo").write_text(pseudo);(out/"platform_data.json").write_bytes(platform)
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
