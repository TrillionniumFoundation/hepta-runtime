#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain the complete native bootstrap, explicitly preserving background stdin."""
from pathlib import Path
import argparse,ast,json,sys
sys.dont_write_bytecode=True
def main():
 p=argparse.ArgumentParser()
 for n in ("source","hepta"):p.add_argument("--"+n,type=Path,required=True)
 a=p.parse_args();root=a.source.resolve(strict=True)
 sys.path.insert(0,str(root/"authoring/public_publication_v1"))
 import source_support as s
 api=s.tools(a.hepta.resolve(strict=True))
 original=(root/"native/ssh_native_bootstrap.hepta").read_bytes()
 before=json.loads((root/"native/ssh_native_bootstrap_composition.json").read_bytes())
 if s.SHA(original)!="2721b88ceb84f4105c1972a9a84701028af14afcee6380d4a616fa2f304a2f73":raise ValueError("original bootstrap differs")
 expanded=(root/"qualification/binary_remote_helper/v1/leaf_build/native/ssh_native_bootstrap.expanded.pseudo").read_text()
 literal=next(n for n in ast.parse(expanded).body if isinstance(n,ast.FunctionDef)and n.name=="literal")
 strings={}
 for cond in literal.body:
  if not isinstance(cond,ast.If):continue
  key=cond.test.comparators[0].value
  raw=b""
  for statement in cond.body:
   if isinstance(statement,ast.Expr):
    c=statement.value
    if c.func.id not in ("emit","emit_word"):raise ValueError("literal effect differs")
    raw+=c.args[2].value.to_bytes(8 if c.func.id=="emit_word"else 1,"little")
  strings[key]=raw
 if sorted(strings)!=[1,2,3,4,5,6]:raise ValueError("literal domain differs")
 old=strings[6]
 needle=b'"$d/h" <&0 & h=$!; wait "$h"'
 if old.count(needle)!=1:raise ValueError("background command differs")
 strings[6]=old.replace(needle,b'exec 3<&0; "$d/h" <&3 3<&- & h=$!; exec 3<&-; wait "$h"')
 rows=["def literal(o:mutbuf,w:mutbuf,code:u64) -> u64:"]
 for code,value in strings.items():
  rows.append("    if code==%d:"%code)
  complete=len(value)//8*8
  for at in range(0,complete,8):rows.append("        emit_word(o,w,%d)"%int.from_bytes(value[at:at+8],"little"))
  for ch in value[complete:]:rows.append("        emit(o,w,%d)"%ch)
  rows.append("        return 0")
 rows.append("    return 0")
 pseudo="\n".join(rows)+"\n"
 out,names,proof=s.compile_delta(api,original,before["aliases"],pseudo,{},"runtime_public_read_bootstrap")
 # Regenerating the unchanged complete original literal must recover its whole body.
 original_pseudo=ast.get_source_segment(expanded,literal)+"\n"
 back,_,_=s.compile_delta(api,original,before["aliases"],original_pseudo,{},"ssh_native_bootstrap")
 if api[3](back).as_dict()!=api[3](original).as_dict():raise ValueError("whole original bootstrap inverse differs")
 proof.update(schema="hepta.runtime.public-read.bootstrap-stdin.v1",original=s.identity(original),
  original_literal=s.identity(old),current_literal=s.identity(strings[6]),
  complete_original_inverse=True,original_background=old.decode(),current_background=strings[6].decode(),
  explicit_original_stdin=True,public_routes_qualified=False,aliases=names)
 (root/"authoring/public_read/bootstrap.pseudo").write_text(pseudo)
 (root/"native/public_read_bootstrap.hepta").write_bytes(out)
 (root/"native/public_read_bootstrap_composition.json").write_bytes(s.ENCODE(proof))
 print(json.dumps(proof,sort_keys=True))
if __name__=="__main__":main()
