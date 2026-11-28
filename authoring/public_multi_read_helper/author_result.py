#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the original multi-file error prefix and terminal newline in HIA."""
from __future__ import annotations
import argparse,ast,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
PREFIX=b"multi-file read rejected: "
def pin(p):
 b=p.read_bytes();return dict(bytes=len(b),sha256=SHA(b))
def main():
 p=argparse.ArgumentParser()
 for name in ("source","hepta","output"):p.add_argument("--"+name,required=True,type=Path)
 a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute()
 assert not out.exists(),"fresh output required"
 q=root/"qualification/multi_read_body/v1/codec_reserved_native_build"
 target=root/"src/mcp/runtime/multi_read_host.py"
 assert SHA(target.read_bytes())=="6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5"
 node=next(n for n in ast.parse(target.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=="run_multi_read")
 assert PREFIX.decode() in [n.value for n in ast.walk(node) if isinstance(n,ast.Constant)]
 baseline=q/"baseline/binary_read_body.pseudo"
 text=baseline.read_text();old={n.name:n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 pseudo=(root/"authoring/public_multi_read_helper/result.pseudo").read_text()
 helpers={}
 for name in ("load","put","copy_in"):
  item=old[name];pseudo+="\n"+ast.get_source_segment(text,item)+"\n";helpers[name]=SHA(ast.dump(item,include_attributes=False).encode())
 pseudo+="\ndef prefix(o:mutbuf,at:u64) -> u64:\n"
 for i,b in enumerate(PREFIX):pseudo+=f"    store(o,at+{i},{b})\n"
 pseudo+=f"    return at+{len(PREFIX)}\n"
 constants=dict(REQUEST=int.from_bytes(b"HMRFQ001","little"),RESPONSE=int.from_bytes(b"HMRFR001","little"),
  INVALID=0xffffffff,CAPACITY=0xfffffffe,LIMIT=0x10000000,PREFIX_SIZE=len(PREFIX))
 pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
 nodes=ast.parse(pseudo).body;assert all(isinstance(n,ast.FunctionDef) for n in nodes) and nodes[0].name=="entry"
 for name in helpers:assert ast.dump(next(n for n in nodes if n.name==name),include_attributes=False)==ast.dump(old[name],include_attributes=False)
 sys.path.insert(0,str(a.hepta.resolve(strict=True)))
 from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
 from hepta.hia_agent_assembly import assemble_program,render_assembly
 names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
 signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
 total=total_scalar_functions(nodes);functions=[]
 for n in nodes:
  b=Builder(n,names,signatures,total);b.statements(n.body)
  functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],returns=[b.returns],
   effects=["read","write","trap"],entry="b0",blocks=b.blocks))
 doc=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="public_multi_read_result",functions=functions))
 raw=render_assembly(doc).encode();actual=assemble_program(raw).as_dict()
 assert render_assembly(actual).encode()==raw
 instructions=sum(len(b["ops"]) for f in actual["functions"] for b in f["blocks"])
 assert instructions<=8192
 paths=[Path(__file__).resolve(),root/"authoring/public_multi_read_helper/result.pseudo",target,baseline]
 receipt=dict(schema="hepta.runtime.public-multi-read-result.author.v1",sources={str(p.relative_to(root)):pin(p) for p in paths},
  original_run_ast_sha256=SHA(ast.dump(node,include_attributes=False).encode()),helper_ast_sha256=helpers,
  constants=constants,aliases=names,bytes=len(raw),sha256=SHA(raw),functions=len(functions),instructions=instructions,
  function_sha256={f["name"]:SHA(CANON(f)) for f in actual["functions"]},qualified_children_unchanged=True,
  runtime_python_required=False,native_executed=False,public_route_qualified=False,whole_runtime_replaced=False)
 out.mkdir(parents=True);(out/"public_multi_read_result.hepta").write_bytes(raw)
 (out/"public_multi_read_result_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
 (out/"expanded.pseudo").write_text(pseudo)
 print(json.dumps({k:receipt[k] for k in ("schema","bytes","sha256","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
