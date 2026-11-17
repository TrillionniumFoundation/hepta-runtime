#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the complete borrowed-parent publish state machine in HIA."""
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
    baseline=(root/"baseline/binary_read_body.hepta").read_bytes()
    composition_raw=(root/"baseline/binary_read_body_composition.json").read_bytes()
    assert SHA(baseline)=="3dbf1f5f46e9bc7e8a139714db1ff9588a95d1d9cc7d1dab1a8da03470a7fbd3"
    assert SHA(composition_raw)=="737f9b2985f6a70965ae5dd3c323074b46d11080c484c7ce8f0b9ffc2f352f35"
    original=assemble_program(baseline).as_dict();composition=json.loads(composition_raw)
    funcs={f["name"]:f for f in original["functions"]};assert len(funcs)==63
    for name,f in funcs.items():assert SHA(CANON(f))==composition["function_sha256"][name]
    roots=("load","get","put","u32_at","copy_in","copy_out","utf8","negative","equal")
    selected={composition["aliases"][n]for n in roots};todo=list(selected)
    while todo:
        name=todo.pop()
        for b in funcs[name]["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":
                    child=op["attrs"]["function"];assert child in funcs
                    if child not in selected:selected.add(child);todo.append(child)
    assert "f0"not in selected
    ordered=sorted(selected,key=lambda x:int(x[1:]));rename={old:"f"+str(i+1)for i,old in enumerate(ordered)}
    inverse={new:old for old,new in rename.items()}
    def relocate(function,mapping):
        result=copy.deepcopy(function);result["name"]=mapping[result["name"]]
        for b in result["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=mapping[op["attrs"]["function"]]
        return result
    retained=[relocate(funcs[name],rename)for name in ordered]
    for old,new in zip(ordered,retained):assert relocate(new,inverse)==funcs[old]
    constants=dict(composition["constants"])
    for name,tag in (("PUB_REQUEST",b"HPUBQ001"),("PUB_RESPONSE",b"HPUBR001"),("PUB_WORK",b"HPUBW001"),
            ("META_REQUEST",b"HMDTQ001"),("META_RESPONSE",b"HMDSR001"),("PATH_ERROR",b"HOSER001")):
        constants[name]=int.from_bytes(tag,"little")
    constants.update(NAME=8192,TEMP_NAME="get(w,200)",PRIOR="get(w,208)",ERROR="get(w,216)",
        PUB_REPLY="get(w,224)",PUB_STAT=256,CHILD=1024)
    pseudo=(root/"authoring/publish_at.pseudo").read_text()
    literals={"literal_embedded":"embedded null byte","literal_regular":"invalid regular file or private sidecar",
        "literal_destination":"destination version changed; no publication performed",
        "literal_source":"source changed before metadata copy"}
    for name,value in literals.items():
        raw=value.encode("utf-8");pseudo+="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
        for index,b in enumerate(raw):pseudo+="    store(w,at+"+str(index)+","+str(b)+")\n"
        pseudo+="    return at+"+str(len(raw))+"\n"
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body;assert nodes[0].name=="entry"
    names={alias:rename[name]for alias,name in composition["aliases"].items()if name in rename}
    names["entry"]="f0"
    for i,n in enumerate(nodes[1:]):names[n.name]="f"+str(len(retained)+1+i)
    assert len(names)==len(set(names))
    signatures={alias:([p["type"]for p in funcs[name]["params"]],funcs[name]["returns"][0])
        for alias,name in composition["aliases"].items()if name in rename}
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    total=total_scalar_functions(nodes);fresh=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        fresh.append(dict(name=names[n.name],params=[b.param(p)for p in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    document=dict(schema="hepta.hia.program.v8",module="publish_at",functions=[fresh[0],*retained,*fresh[1:]])
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
    receipt=dict(schema="hepta.runtime.publish-at.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,constants=constants,
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained=dict(qualified_baseline="bd953bbf6751cdd13ecc956c9caf5f0b1e25f562",source_sha256=SHA(baseline),
            composition_sha256=SHA(composition_raw),roots=list(roots),functions=len(retained),relocations=rename,
            inverse_relocation_exact_ir=True,omitted_unreachable_functions=len(funcs)-len(retained)),
        wire=dict(request="HPUBQ001",response="HPUBR001",child_error_envelopes=["HBRDS001","HMDSR001","HOSER001"],
            start_command=1,resume_command=2,orphan_operation=4),
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"publish_at.hepta").write_bytes(raw)
    (out/"publish_at_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"publish_at.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
