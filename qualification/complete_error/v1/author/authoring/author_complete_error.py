#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Preserve all 34 qualified formatter functions and admit one complete-error frame."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def main():
    p=argparse.ArgumentParser()
    for k in("source","hepta","output"):p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    before=(root/"baseline/path_error.hepta").read_bytes()
    cr=(root/"baseline/path_error_composition.json").read_bytes()
    assert SHA(before)=="23a5e7ae451cda076a2caa910d10ac34ae0757922b55df538dab03746ed4ff9a"
    assert SHA(cr)=="26826762229fab26ce54b17bea5805bf4552106fa3609e89756710876f006d30"
    base=assemble_program(before).as_dict();comp=json.loads(cr);fs=base["functions"]
    assert len(fs)==34 and [f["name"]for f in fs]==["f"+str(i)for i in range(34)]
    for f in fs:assert SHA(CANON(f))==comp["function_sha256"][f["name"]]
    def relocate(f,mapping):
        q=copy.deepcopy(f);q["name"]=mapping.get(q["name"],q["name"])
        for b in q["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=mapping.get(op["attrs"]["function"],op["attrs"]["function"])
        return q
    retained=[relocate(f,{"f0":"f34"})for f in fs]
    for old,new in zip(fs,retained):assert relocate(new,{"f34":"f0"})==old
    constants=dict(comp["constants"]);constants["COMPLETE_ERROR"]=int.from_bytes(b"HCPER001","little")
    pseudo=(root/"authoring/complete_error.pseudo").read_text()
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body;assert len(nodes)==1 and nodes[0].name=="entry"
    names={k:("f34"if v=="f0"else v)for k,v in comp["aliases"].items()}
    names.update(entry="f0",previous_formatter="f34")
    signatures={}
    table={f["name"]:f for f in fs}
    for k,v in comp["aliases"].items():signatures[k]=([p["type"]for p in table[v]["params"]],table[v]["returns"][0])
    signatures["previous_formatter"]=(["readbuf","mutbuf","mutbuf"],"u32")
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    n=nodes[0];b=Builder(n,names,signatures,total_scalar_functions(nodes));b.statements(n.body)
    fresh=dict(name="f0",params=[b.param(x)for x in b.params],returns=[b.returns],
        effects=["read","write","trap"],entry="b0",blocks=b.blocks)
    doc=dict(schema="hepta.hia.program.v8",module="complete_error",functions=[fresh,*retained[1:],retained[0]])
    doc=compact_authoring_cfg(doc);doc["functions"][1:34]=retained[1:];doc["functions"][34]=retained[0]
    raw=render_assembly(doc).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw and actual["functions"][1:34]==retained[1:]and actual["functions"][34]==retained[0]
    ops=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    blocks=sum(len(f["blocks"])for f in actual["functions"])
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"])<=limits["functions"]==128 and ops<=8192 and blocks<=limits["blocks_total"]==1536
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048
    receipt=dict(schema="hepta.runtime.complete-error.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=len(actual["functions"]),instructions=ops,blocks=blocks,constants=constants,aliases=names,
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained_legacy=dict(qualified_commit="96a3ecccb3b054a9bf0059659040d4bb9e38e4a9",
            source_sha256=SHA(before),composition_sha256=SHA(cr),functions=34,entry_relocation={"f0":"f34"},
            inverse_relocation_exact_ir=True,other_function_names_unchanged=True),
        complete_error=dict(magic="HCPER001",header_bytes=64,kind=3,reserved_words=[16,24,32,40,48],
            full_prefixed_utf8=True,zero_payload_rejected=True,newline_added=False,workspace_unchanged=True),
        platform_data_sha256=comp["platform_data_sha256"],native_compiled=False,native_executed=False,
        original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"complete_error.hepta").write_bytes(raw)
    (out/"complete_error_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"complete_error.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
