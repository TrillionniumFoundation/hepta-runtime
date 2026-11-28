#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the public file-info parent walk around unchanged qualified children."""
from __future__ import annotations
import argparse, ast, copy, hashlib, json, re, sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
HELPERS=("normalize","anchor","outside","sidecar","c_component","negative","equal","load","get","put","copy_in","copy_out")
LITERALS={
 "literal_absolute":b"absolute non-traversing file path required",
 "literal_outside":b"file outside configured root",
 "literal_sidecar":b"capability root and runtime sidecars are not file targets",
 "literal_nul":b"open: embedded null character in path",
}
def pin(p):
 b=p.read_bytes()
 return dict(bytes=len(b),sha256=SHA(b))
def literal(name,raw):
 text="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
 end=len(raw)//8*8
 for i in range(0,end,8):text+=f"    put(w,at+{i},{int.from_bytes(raw[i:i+8],'little')})\n"
 for i in range(end,len(raw)):text+=f"    store(w,at+{i},{raw[i]})\n"
 return text+f"    return at+{len(raw)}\n"
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--source",required=True,type=Path)
 p.add_argument("--hepta",required=True,type=Path)
 p.add_argument("--output",required=True,type=Path)
 a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute()
 assert not out.exists(),"fresh authoring output required"
 q=root/"qualification/file_info_at/v1/final/source"
 baseline=q/"baseline/binary_read_body.pseudo"
 old_text=baseline.read_text();old={n.name:n for n in ast.parse(old_text).body if isinstance(n,ast.FunctionDef)}
 info_text=(q/"authoring/file_info_at.pseudo").read_text()
 info={n.name:n for n in ast.parse(info_text).body if isinstance(n,ast.FunctionDef)}
 target=root/"src/mcp/runtime/binary_file.py"
 target_tree=ast.parse(target.read_bytes())
 parent=next(n for n in target_tree.body if isinstance(n,ast.FunctionDef) and n.name=="parent")
 # Preserve current original source authority; no test-output-derived parent behavior.
 assert SHA(target.read_bytes())=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
 assert SHA(baseline.read_bytes())=="ee9ef7c11e17eaa3bf1cb28f64e523fe405a3f06b51fd249d06b95519354b451"
 for raw in list(LITERALS.values())[:3]:assert raw.decode() in target.read_text()
 pseudo=(root/"authoring/public_file_info_walk/walk.pseudo").read_text()
 retained={}
 for name in HELPERS:
  node=old[name];segment=ast.get_source_segment(old_text,node)
  pseudo+="\n"+segment+"\n";retained[name]=SHA(ast.dump(node,include_attributes=False).encode())
 pseudo+="\n"+ast.get_source_segment(info_text,info["error_class"])+"\n"
 retained["error_class"]=SHA(ast.dump(info["error_class"],include_attributes=False).encode())
 for name,raw in LITERALS.items():pseudo+=literal(name,raw)
 before={n.name:n for n in ast.parse(pseudo).body}
 for name in HELPERS:assert ast.dump(before[name],include_attributes=False)==ast.dump(old[name],include_attributes=False)
 assert ast.dump(before["error_class"],include_attributes=False)==ast.dump(info["error_class"],include_attributes=False)
 constants={k:int.from_bytes(v,"little") for k,v in {
  "REQUEST":b"HFRDQ001","RESPONSE":b"HFRDR001","WORK_MAGIC":b"HFRDW001",
  "INFO_REQUEST":b"HINFQ001","INFO_RESPONSE":b"HINFR001",
  "ERROR_RESPONSE":b"HBRDS001","METADATA_RESPONSE":b"HMDSR001"}.items()}
 constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,NEXT=0xfffffffd,LIMIT=0xffff0000,MAXIMUM=(1<<64)-1,
  ROOT_RAW=4096,PATH_RAW="get(w,304)",ROOT_NORMAL="get(w,320)",PATH_NORMAL="get(w,328)",
  COMPONENT="get(w,336)",PACKET="get(w,376)",ERROR="get(w,424)",REPLY="get(w,392)",RESULT="get(w,360)")
 pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
 sys.path.insert(0,str(a.hepta.resolve(strict=True)))
 from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
 from hepta.hia_agent_assembly import assemble_program,render_assembly
 class NativeBuilder(Builder):
  def expr(self,node):
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="copy_within":
    values=[self.expr(v) for v in node.args]
    assert len(values)==4 and values[0][1]=="mutbuf"
    return self.op("buffer.move_within",[values[0],*(self.cast(v,"usize") for v in values[1:])])
   return super().expr(node)
 nodes=ast.parse(pseudo).body
 assert all(isinstance(n,ast.FunctionDef) for n in nodes) and nodes[0].name=="entry"
 names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
 assert len(names)==len(nodes) and "utf8" not in names
 names["utf8"]="f"+str(len(nodes))
 signatures={node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
 signatures["utf8"]=(["readbuf","u64","u64"],"u64")
 total=total_scalar_functions(nodes);functions=[]
 for node in nodes:
  b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
  functions.append(dict(name=names[node.name],params=[b.param(p) for p in b.params],returns=[b.returns],
   effects=["read","write","trap"],entry="b0",blocks=b.blocks))
 original=assemble_program((q/"baseline/binary_read_body.hepta").read_bytes()).as_dict()
 utf8=next(f for f in original["functions"] if f["name"]=="f62")
 assert not any(op["op"]=="call" for b in utf8["blocks"] for op in b["ops"])
 child=copy.deepcopy(utf8);child["name"]=names["utf8"];functions.append(child)
 doc=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="public_file_info_walk",functions=functions))
 raw=render_assembly(doc).encode();actual=assemble_program(raw).as_dict()
 assert render_assembly(actual).encode()==raw
 restored=copy.deepcopy(actual["functions"][-1]);restored["name"]="f62"
 assert CANON(restored)==CANON(utf8)
 ops=sum(len(b["ops"]) for f in actual["functions"] for b in f["blocks"])
 assert ops<=8192
 for f in actual["functions"]:
  assert len(f["blocks"])<=256 and max(len(b["params"]) for b in f["blocks"])<=16
 bindings=[Path(__file__).resolve(),root/"authoring/public_file_info_walk/walk.pseudo",baseline,
  q/"baseline/binary_read_body.hepta",q/"authoring/file_info_at.pseudo",target]
 receipt=dict(schema="hepta.runtime.public-file-info-walk.author.v1",
  sources={str(p.relative_to(root)):pin(p) for p in bindings},
  original_parent_ast_sha256=SHA(ast.dump(parent,include_attributes=False).encode()),
  helper_ast_sha256=retained,utf8_ir_sha256=SHA(CANON(utf8)),aliases=names,constants=constants,
  bytes=len(raw),sha256=SHA(raw),functions=len(functions),instructions=ops,
  function_sha256={f["name"]:SHA(CANON(f)) for f in actual["functions"]},
  qualified_children_unchanged=True,original_failed_directory_close_repeated=True,
  original_unassigned_child_orphaned_until_process_exit=True,
  runtime_python_required=False,native_executed=False,public_route_qualified=False,whole_runtime_replaced=False)
 out.mkdir(parents=True)
 (out/"public_file_info_walk.hepta").write_bytes(raw)
 (out/"public_file_info_walk_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
 (out/"expanded.pseudo").write_text(pseudo)
 print(json.dumps({k:receipt[k] for k in ("schema","bytes","sha256","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
