#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Extend the exact installed span owner with binary configured-root operation 9."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from authoring_support import compile_delta,substitute
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
BASELINE="6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81"
LITERALS={
    1:b"runtime tools are disabled; start with --runtime-config <file>",
    2:b"unknown host \x60",
    3:b"native binary tools require an operator host",
    4:b"file outside configured roots",
    5:b"\x60; call host_list for configured names",
}
def literal_pseudo():
    raw="\ndef binary_literal(o:mutbuf,at:u64,code:u64) -> u64:\n"
    for code,value in sorted(LITERALS.items()):
        raw+=f"    if code=={code}:\n"
        end=len(value)//8*8
        for at in range(0,end,8):
            raw+=f"        put(o,at+{at},{int.from_bytes(value[at:at+8],'little')})\n"
        for at in range(end,len(value)):
            raw+=f"        store(o,at+{at},{value[at]})\n"
        raw+=f"        return at+{len(value)}\n"
    raw+="    return at\n\ndef binary_literal_size(code:u64) -> u64:\n"
    for code,value in sorted(LITERALS.items()):
        raw+=f"    if code=={code}:\n        return {len(value)}\n"
    return raw+"    return 0\n"
def main():
    p=argparse.ArgumentParser()
    for key in ("source","hepta","output"):p.add_argument("--"+key,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    original=(source/"baseline/config_directory_owner_span.hepta").read_bytes()
    assert SHA(original)==BASELINE and len(original)==288259
    before={f["name"]:copy.deepcopy(f) for f in assemble_program(original).as_dict()["functions"]}
    assert len(before)==52
    text=original.decode()
    begin=text.index("\nfn f0(")+1
    end=text.index("\nfn ",begin)
    original_entry=text[begin:end]
    anchor='  v370:bool = compare.eq(v369,v368)\n'
    assert original_entry.count(anchor)==1
    assert max(int(v) for v in re.findall(r"\bv([0-9]+)\b",original_entry))==640
    replacement=('  v641:u64 = const() {"value":9}\n'
        '  v642:bool = compare.eq(v369,v368)\n'
        '  v643:bool = compare.eq(v369,v641)\n'
        '  v370:bool = bool.or(v642,v643)\n')
    patched_entry=original_entry.replace(anchor,replacement)
    patched=(text[:begin]+patched_entry+text[end:]).encode()
    patched_functions={f["name"]:f for f in assemble_program(patched).as_dict()["functions"]}
    for name,body in before.items():
        if name!="f0":assert patched_functions[name]==body,name
    comp=json.loads((source/"baseline/config_op8_growth_composition.json").read_bytes())
    aliases=dict(comp["function_names"]);aliases["retained_query"]="f52"
    additions=dict(binary_root="f53",binary_named_host="f54",binary_longest_root="f55",
        binary_prefix="f56",binary_result="f57",binary_literal="f58",binary_literal_size="f59")
    constants=dict(REQUEST=int.from_bytes(b"HRCFGQ01","little"),
        RESPONSE=int.from_bytes(b"HRCFGM01","little"),INVALID=0xffffffff,
        CAPACITY=0xfffffffe,LIMIT=0xffff0000)
    pseudo=substitute((source/"authoring/binary_root.pseudo").read_text()+literal_pseudo(),constants)
    raw,after,retained=compile_delta(a.hepta,patched,aliases,pseudo,{"query":"f8"},additions,(("f8","f52"),))
    program=assemble_program(raw).as_dict();program["module"]="config_binary_root_span"
    raw=render_assembly(program).encode()
    after={f["name"]:f for f in assemble_program(raw).as_dict()["functions"]}
    retained={}
    for name,body in before.items():
        if name not in ("f0","f8"):
            assert after[name]==body,name
            retained[name]=SHA(CANON(body))
    moved=copy.deepcopy(after["f52"]);moved["name"]="f8"
    assert moved==before["f8"]
    assert after["f0"]==patched_functions["f0"]
    ops=sum(len(b["ops"]) for f in after.values() for b in f["blocks"])
    assert ops<=8192
    receipt=dict(schema="hepta.runtime.config-binary-root-author.v1",
        target_commit="d3d75c30719db966b004756f610007a7c723729e",
        baseline_sha256=BASELINE,baseline_bytes=len(original),
        source_sha256=SHA(raw),source_bytes=len(raw),functions=len(after),instructions=ops,
        aliases={**aliases,"query":"f8",**additions},constants=constants,
        retained_exact_functions=retained,relocated_exact_functions={"f8":"f52"},
        changed_functions=["f0","f8"],
        entry_change="Accept operation 9 beside operation 8 in the borrowed query-input fast path; all other entry operations and blocks are exact.",
        function_sha256={name:SHA(CANON(body)) for name,body in after.items()},
        query_operation=9,named_host_before_alias_policy=True,
        longest_original_raw_root_length=True,last_equal_length_root_wins=True,
        startup_authority="retained installed native configuration arena",
        public_route_integrated=False,native_compiled=False,native_executed=False,
        original_compared=False,whole_runtime_qualified=False)
    out.mkdir(parents=True)
    (out/"config_binary_root_span.hepta").write_bytes(raw)
    (out/"config_binary_root_span_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"config_binary_root_span.pseudo").write_text(pseudo)
    print(json.dumps({key:receipt[key] for key in ("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
