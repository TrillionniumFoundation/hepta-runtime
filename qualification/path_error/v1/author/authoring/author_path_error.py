#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Add exact dual-filename diagnostics while retaining all 30 qualified functions."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def main():
    p=argparse.ArgumentParser()
    for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    baseline=(source/"baseline/structured_error.hepta").read_bytes()
    composition_raw=(source/"baseline/structured_error_composition.json").read_bytes()
    platform=(source/"baseline/platform_data.json").read_bytes()
    assert SHA(baseline)=="163b024e301f9eaa2481d638e5b2d390b1325b090535c89b3009128332a428e1"
    assert SHA(composition_raw)=="a1d53705790cd887f6fc918834916e6a52674fb8ee8ece9e46386ac1c039dce2"
    assert SHA(platform)=="01433965084eea53dfd903866fb33e8a53f4a3e63a2d828ba5d00ddd1ca93829"
    composition=json.loads(composition_raw);baseline_ir=assemble_program(baseline).as_dict()
    old=baseline_ir["functions"];assert len(old)==30
    assert [f["name"]for f in old]==["f"+str(i)for i in range(30)]
    for f in old:
        assert SHA(CANON(f))==composition["function_sha256"][f["name"]]
        assert not any(op["op"]=="call" and op.get("attrs",{}).get("function")=="f0" for b in f["blocks"] for op in b["ops"])
    constants=dict(composition["constants"]);constants["DUAL_RESPONSE"]=int.from_bytes(b"HOSER001","little")
    pseudo=(source/"authoring/path_error.pseudo").read_text()
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert [n.name for n in nodes]==["dispatch","dual_entry"]
    assert all(isinstance(n,ast.FunctionDef)for n in nodes)
    names=dict(composition["aliases"])
    names.update(dispatch="f0",previous_entry="f30",dual_entry="f31")
    signatures={}
    byname={f["name"]:f for f in old}
    for alias,name in composition["aliases"].items():
        f=byname[name];signatures[alias]=([x["type"]for x in f["params"]],f["returns"][0])
    signatures["previous_entry"]=signatures["entry"]
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    total=total_scalar_functions(nodes);fresh=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        fresh.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    relocated=copy.deepcopy(old[0]);relocated["name"]="f30"
    retained=copy.deepcopy(old[1:])+[relocated]
    document=dict(schema="hepta.hia.program.v8",module="path_error",functions=[fresh[0],*retained,*fresh[1:]])
    compacted=compact_authoring_cfg(document);compacted["functions"][1:31]=retained
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    assert actual["functions"][1:31]==retained
    recovered=copy.deepcopy(actual["functions"][30]);recovered["name"]="f0"
    assert recovered==old[0]
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"])==32 and len(actual["functions"])<=limits["functions"]==128
    assert operations<=8192
    blocks=sum(len(f["blocks"])for f in actual["functions"])
    assert blocks<=limits["blocks_total"]==1536
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048,f["name"]
    receipt=dict(schema="hepta.runtime.path-error.author.v1",source_sha256=SHA(raw),source_bytes=len(raw),
        functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,constants=constants,
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained_legacy=dict(qualified_commit="037c5df97a3f627d3e5f905b8d2bd1b77e78c2e1",
            source_sha256=SHA(baseline),composition_sha256=SHA(composition_raw),functions=30,
            entry_relocation={"f0":"f30"},other_function_names_unchanged=True),
        platform_data_sha256=SHA(platform),data_sha256=composition["data_sha256"],
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"path_error.hepta").write_bytes(raw)
    (out/"path_error_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"path_error.pseudo").write_text(pseudo)
    (out/"platform_data.json").write_bytes(platform)
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
