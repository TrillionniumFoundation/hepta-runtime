#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit a fourth fixed remote helper while retaining all original read frames."""
from pathlib import Path
import argparse
import ast
import copy
import json
import sys

sys.dont_write_bytecode=True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(args.hepta.resolve(strict=True))
    original=(root/"native/public_read_wire.hepta").read_bytes()
    composition=json.loads((root/"native/public_read_wire_composition.json").read_bytes())
    prior=(root/"authoring/public_read/wire.pseudo").read_text()
    edits=[
      ("kind < 1 or kind > 3", "kind < 1 or kind > 4"),
      ("load(s,144)!=choose(load(s,8)==3,1,load(s,8))", "load(s,144)!=choose(load(s,8)==4,3,choose(load(s,8)==3,1,load(s,8)))"),
      ("    packet_size=96+load(s,88)+load(s,224)+load(s,240)\n",
       "    packet_size=96+load(s,88)+load(s,224)+load(s,240)\n    if load(s,8)==4:\n        packet_size=packet_size+load(s,232)\n"),
      ("    if kind==3:\n        return emit_multi_packet(s,o,at,size)\n",
       "    if kind==3:\n        return emit_multi_packet(s,o,at,size)\n    if kind==4:\n        return emit_write_packet(s,o,at,size)\n"),
    ]
    current=prior
    for before,after in edits:
        support.require(current.count(before)==1,"exact read wire source anchor differs")
        current=current.replace(before,after)
    inverse=current
    for before,after in reversed(edits):
        support.require(inverse.count(after)==1,"wire projection inverse anchor differs")
        inverse=inverse.replace(after,before)
    support.require(inverse==prior,"complete read wire pseudo inverse differs")
    selected={"entry","valid_outer","valid_request","emit_packet"}
    nodes=[f for f in ast.parse(current).body if f.name in selected]
    support.require({f.name for f in nodes}==selected,"complete wire delta functions differ")
    pseudo=ast.unparse(ast.Module(body=nodes,type_ignores=[]))+"\n"+(root/"authoring/public_binary_write/wire_write.pseudo").read_text()
    constants={"INVALID":0xffffffff,**{name:support.WORD(value) for name,value in {
      "WIRE_REQUEST":"HRWRQ001","WIRE_RESULT":"HRWRR001","SSH_REQUEST":"HRSSQ001",
      "BOOTSTRAP_RESULT":"HSSBR001","COMMAND_MAGIC":"HSDCMD01","READ_PACKET":"HBRDQ001",
      "INFO_PACKET":"HFRDQ001","MULTI_PACKET":"HMRDQ001","MULTI_TYPED":"HMRPR001",
      "WRITE_PACKET":"HBPWQ001"}.items()}}
    raw,names,proof=support.compile_delta(api,original,composition["aliases"],pseudo,constants,"runtime_public_io_wire")
    before_doc=api[3](original).as_dict();after_doc=api[3](raw).as_dict()
    old={f["name"]:f for f in before_doc["functions"]}
    changed={names[name] for name in selected}
    inverse=copy.deepcopy(after_doc);inverse["module"]=before_doc["module"]
    inverse["functions"]=[old[f["name"]] if f["name"] in changed else f
                           for f in inverse["functions"] if f["name"] in old]
    support.require(api[4](inverse).encode()==original,"whole original wire HIA inverse differs")
    original_asm=(root/"asm/public_read_ssh.S").read_bytes()
    old_asm=b"    cmp rax,3\n    ja .Lrsh_start_invalid\n    lea rdi,[rbx+64]"
    new_asm=old_asm.replace(b"cmp rax,3",b"cmp rax,4")
    support.require(original_asm.count(old_asm)==1,"original fixed helper selection differs")
    assembly=original_asm.replace(old_asm,new_asm)
    support.require(assembly.replace(new_asm,old_asm)==original_asm,"whole SSH storage boundary inverse differs")
    proof.update(schema="hepta.runtime.public-binary-write.wire-author.v1",aliases=names,
       baseline=support.identity(original),whole_original_wire_inverse=True,
       original_pseudo=support.identity(prior.encode()),pseudo_edits=edits,
       fixed_helper_kind=4,original_read_kinds=[1,2,3],write_packet="HBPWQ001",
       original_command_environment_and_deadline_unchanged=True,
       assembly=dict(baseline=support.identity(original_asm),source=support.identity(assembly),
                     only_edit=[old_asm.decode(),new_asm.decode()],whole_original_inverse=True),
       public_route_qualified=False)
    output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    (output/"public_io_wire.hepta").write_bytes(raw)
    (output/"public_io_wire_composition.json").write_bytes(support.ENCODE(proof))
    (output/"public_io_wire.pseudo").write_text(pseudo)
    (output/"public_io_ssh.S").write_bytes(assembly)
    print(json.dumps(dict(source=proof["source"],functions=proof["functions"],operations=proof["operations"]),sort_keys=True))


if __name__=="__main__":main()
