#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Append a borrowed-parent entry while preserving all 63 qualified HIA functions."""
from pathlib import Path
import argparse,ast,copy,hashlib,json,re,sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def main():
    p=argparse.ArgumentParser()
    for key in("source","hepta","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    original_raw=(source/"baseline/binary_read_body.hepta").read_bytes()
    assert SHA(original_raw)=="3dbf1f5f46e9bc7e8a139714db1ff9588a95d1d9cc7d1dab1a8da03470a7fbd3"
    original=assemble_program(original_raw).as_dict()
    composition_raw=(source/"baseline/binary_read_body_composition.json").read_bytes()
    assert SHA(composition_raw)=="737f9b2985f6a70965ae5dd3c323074b46d11080c484c7ce8f0b9ffc2f352f35"
    composition=json.loads(composition_raw);assert composition["source_sha256"]==SHA(original_raw)
    funcs=original["functions"];assert len(funcs)==63 and [f["name"]for f in funcs]==["f"+str(i)for i in range(63)]
    assert not any(op["op"]=="call"and op.get("attrs",{}).get("function")=="f0"for f in funcs for b in f["blocks"]for op in b["ops"])
    for f in funcs:assert SHA(CANON(f))==composition["function_sha256"][f["name"]]
    names=dict(composition["aliases"]);names.update(dispatch="f0",original_entry="f63",at_start="f64",at_resume="f65",at_flow="f66")
    byname={f["name"]:f for f in funcs}
    signatures={name:([p["type"]for p in byname[old]["params"]],byname[old]["returns"][0])
        for name,old in composition["aliases"].items()}
    signatures["original_entry"]=signatures["entry"]
    constants=dict(composition["constants"]);constants["AT_REQUEST"]=int.from_bytes(b"HBRDFD01","little")
    pseudo=(source/"authoring/binary_read_at.pseudo").read_text()
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert [n.name for n in nodes]==["dispatch","at_start","at_resume","at_flow"]
    for n in nodes:signatures[n.name]=([p.annotation.id for p in n.args.args],n.returns.id)
    total=total_scalar_functions(nodes);fresh=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        fresh.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    old_entry=copy.deepcopy(funcs[0]);old_entry["name"]="f63"
    retained=[*copy.deepcopy(funcs[1:]),old_entry]
    document=dict(schema="hepta.hia.program.v8",module="binary_read_body",functions=[fresh[0],*retained,*fresh[1:]])
    compacted=compact_authoring_cfg(document)
    # The existing owner is already qualified. Restore its exact IR rather than
    # allowing a new compaction run to rewrite even an unreachable old block.
    compacted["functions"][1:64]=copy.deepcopy(retained)
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    assert actual["functions"][1:64]==retained
    inverse=copy.deepcopy(actual["functions"][63]);inverse["name"]="f0";assert inverse==funcs[0]
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    assert len(actual["functions"])==67 and operations<=8192
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
    receipt=dict(schema="hepta.runtime.binary-read-at.author.v1",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=67,instructions=operations,aliases=names,constants=constants,
        qualified_baseline=dict(commit="bd953bbf6751cdd13ecc956c9caf5f0b1e25f562",source_sha256=SHA(original_raw),
            composition_sha256=SHA(composition_raw),retained_functions=63,relocation={"f0":"f63"}),
        function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        borrowed_parent=dict(workspace_marker_offset=424,native_parent_fd_offset=344,native_borrow_flag_offset=352,
            duplicate_fd=False,parent_close_forbidden=True,baseline_normal_path_functions_unchanged=True),
        internal_modes=["fingerprint_at","private_read_at"],native_compiled=False,native_executed=False,
        original_compared=False,mutation_races_qualified=False,public_route=False,whole_runtime_replaced=False)
    out.mkdir(parents=True)
    (out/"binary_read_body.hepta").write_bytes(raw)
    (out/"binary_read_body_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"binary_read_at.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
