#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Preserve the qualified decoder except the explicit CPython 3.14 strict scan."""
from __future__ import annotations
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
def pin(p):
 b=p.read_bytes()
 return dict(bytes=len(b),sha256=SHA(b))
def main():
 p=argparse.ArgumentParser()
 for key in ("source","hepta","output"):p.add_argument("--"+key,type=Path,required=True)
 a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute()
 assert not out.exists()
 sys.path.insert(0,str(a.hepta.resolve(strict=True)))
 from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
 from hepta.hia_agent_assembly import assemble_program,render_assembly
 q=root/"qualification/binary_write_body/v1/native_build/native"
 source=q/"binary_base64_decode.hepta";meta_path=q/"binary_base64_decode_composition.json"
 raw=source.read_bytes();meta=json.loads(meta_path.read_bytes())
 assert SHA(raw)==meta["source_sha256"]=="408488daa38015a7ebdfcd1e49ff4b7276047a34776398ae0469c196fcdfbf74"
 original=assemble_program(raw).as_dict();functions={f["name"]:f for f in original["functions"]}
 assert len(functions)==19
 for f in original["functions"]:assert SHA(CANON(f))==meta["function_sha256"][f["name"]]
 pseudo_path=root/"authoring/public_binary_write/base64.pseudo"
 pseudo=pseudo_path.read_text()
 names=dict(meta["aliases"]);names["literal_excess_padding"]="f19"
 constants=dict(meta["constants"]);constants["EXCESS_PADDING_LENGTH"]=26
 literal=b"Excess padding not allowed"
 assert len(literal)==26
 pseudo+="\ndef literal_excess_padding(w:mutbuf,at:u64) -> u64:\n"
 for i,value in enumerate(literal):pseudo+=f"    store(w,at+{i},{value})\n"
 pseudo+=f"    return at+{len(literal)}\n"
 pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
 nodes=ast.parse(pseudo).body
 assert [n.name for n in nodes]==["base64_scan","emit_error","literal_excess_padding"]
 signatures={alias:([p["type"] for p in functions[name]["params"]],functions[name]["returns"][0]) for alias,name in meta["aliases"].items()}
 signatures["literal_excess_padding"]=(["mutbuf","u64"],"u64")
 total=total_scalar_functions(nodes);fresh=[]
 for node in nodes:
  b=Builder(node,names,signatures,total);b.statements(node.body)
  fresh.append(dict(name=names[node.name],params=[b.param(p) for p in b.params],returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
 replacements={f["name"]:f for f in fresh};changed={names["base64_scan"],names["emit_error"]}
 derived=copy.deepcopy(original);derived["module"]="public_binary_write_base64_profile"
 derived["functions"]=[replacements.get(f["name"],f) for f in derived["functions"]]+[replacements["f19"]]
 derived=compact_authoring_cfg(derived)
 derived["functions"]=[functions[f["name"]] if f["name"] in functions and f["name"] not in changed else f for f in derived["functions"]]
 output=render_assembly(derived).encode();actual=assemble_program(output).as_dict()
 assert render_assembly(actual).encode()==output
 inverse=copy.deepcopy(actual);inverse["module"]=original["module"];inverse["functions"]=inverse["functions"][:-1]
 for i,f in enumerate(inverse["functions"]):
  if f["name"] in changed:inverse["functions"][i]=functions[f["name"]]
 assert inverse==original
 for f in actual["functions"][:-1]:
  if f["name"] not in changed:assert f==functions[f["name"]]
 receipt=dict(schema="hepta.runtime.public-binary-write-base64-profile.v1",
  original_source=str(source.relative_to(root)),original=pin(source),original_composition=pin(meta_path),
  author=pin(Path(__file__)),pseudo=pin(pseudo_path),functions=len(actual["functions"]),unchanged_functions=17,
  changed_functions=sorted(changed),added_functions=["f19"],inverse_restores_complete_original_ir=True,
  source_bytes=len(output),source_sha256=SHA(output),
  upstream=dict(repository="python/cpython",ref="v3.14.4",path="Modules/binascii.c",
   git_blob="1030eb15f4169c691ad7254542f4992ce75ef3c7",function="binascii_a2b_base64_impl",
   url="https://github.com/python/cpython/blob/v3.14.4/Modules/binascii.c"),
  utf8_and_ascii_admission_unchanged=True,workspace_unchanged=True,runtime_python_required=False,
  native_executed=False,original_process_compared=False,public_route_qualified=False,whole_runtime_replaced=False)
 out.mkdir(parents=True)
 (out/"public_binary_write_base64_profile.hepta").write_bytes(output)
 (out/"public_binary_write_base64_profile.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
 (out/"expanded.pseudo").write_text(pseudo)
 print(json.dumps({k:receipt[k] for k in ("schema","source_bytes","source_sha256","functions","unchanged_functions")},sort_keys=True))
if __name__=="__main__":main()
