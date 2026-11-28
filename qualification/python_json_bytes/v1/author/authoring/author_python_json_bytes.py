#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author only the native CPython JSON bytes decoder; execute no application."""
import argparse,ast,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def main():
    p=argparse.ArgumentParser()
    for key in("source","hepta","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    pseudo=(root/"authoring/python_json_bytes.pseudo").read_text()
    literals=json.loads((root/"authoring/literals.json").read_bytes())
    for name,value in literals.items():
        raw=value.encode("utf-8")
        pseudo+="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
        for i,b in enumerate(raw):pseudo+="    store(w,at+"+str(i)+","+str(b)+")\n"
        pseudo+="    return at+"+str(len(raw))+"\n"
    pseudo=re.sub(r"\bRESPONSE\b",str(int.from_bytes(b"HPYDER01","little")),pseudo)
    nodes=ast.parse(pseudo).body;assert nodes[0].name=="entry"
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append(dict(name=names[n.name],params=[b.param(p)for p in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    document=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="python_json_bytes",functions=functions))
    raw=render_assembly(document).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    blocks=sum(len(f["blocks"])for f in actual["functions"])
    limits=json.loads((hepta/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"])<=limits["functions"]==128 and operations<=8192 and blocks<=limits["blocks_total"]==1536
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=limits["ssa_names_per_function"]==2048,f["name"]
    receipt=dict(schema="hepta.runtime.python-json-bytes.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,
        function_sha256={f["name"]:SHA(json.dumps(f,sort_keys=True,separators=(",",":")).encode())for f in actual["functions"]},
        source_profile="CPython 3.12.3 json.detect_encoding and bytes.decode with surrogatepass",
        input_limit=6291456,workspace_minimum=1024,output="HPYDER01 and complete UTF-32LE code points or original formatted UnicodeDecodeError",
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"python_json_bytes.hepta").write_bytes(raw)
    (out/"python_json_bytes_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"python_json_bytes.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
