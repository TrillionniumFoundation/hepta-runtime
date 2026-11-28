#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Derive the current CPython open/NUL display from the fixed original HIA body."""
from pathlib import Path
import argparse,copy,json,sys
sys.dont_write_bytecode=True
OLD=b"embedded null byte"
CURRENT=b"open: embedded null character in path"
def literal(raw):
 text="def error_4(w:mutbuf,at:u64) -> u64:\n"
 end=len(raw)//8*8
 for i in range(0,end,8):text+=f"    put(w,at+{i},{int.from_bytes(raw[i:i+8],'little')})\n"
 for i in range(end,len(raw)):text+=f"    store(w,at+{i},{raw[i]})\n"
 return text+f"    return at+{len(raw)}\n"
def main():
 p=argparse.ArgumentParser()
 for key in ("source","hepta"):p.add_argument("--"+key,type=Path,required=True)
 a=p.parse_args();root=a.source.resolve(strict=True)
 sys.path.insert(0,str(root/"authoring/public_publication_v1"))
 import source_support as s
 api=s.tools(a.hepta.resolve(strict=True))
 original=(root/"native/binary_read_body.hepta").read_bytes()
 comp=json.loads((root/"native/binary_read_body_composition.json").read_bytes())
 before=api[3](original).as_dict()
 recreated,_,_=s.compile_delta(api,original,comp["aliases"],literal(OLD),{},before["module"])
 s.require(recreated==original,"complete original literal author reproduction differs")
 raw,names,proof=s.compile_delta(api,original,comp["aliases"],literal(CURRENT),{},before["module"])
 after=api[3](raw).as_dict();old_functions={f["name"]:f for f in before["functions"]}
 changed=[f["name"]for f in after["functions"]if f!=old_functions.get(f["name"])]
 s.require(changed==[comp["aliases"]["error_4"]],"nonliteral body logic changed")
 inverse=copy.deepcopy(after)
 inverse["functions"]=[old_functions[f["name"]]if f["name"]in changed else f for f in inverse["functions"]]
 s.require(api[4](inverse).encode()==original,"whole-body inverse differs")
 proof.update(schema="hepta.runtime.public-read.current-open-error.v1",
  aliases=names,source_bytes=len(raw),source_sha256=s.SHA(raw),baseline=s.identity(original),
  qualified_original_composition=s.identity((root/"native/binary_read_body_composition.json").read_bytes()),
  old_message=OLD.decode(),current_message=CURRENT.decode(),changed_functions=changed,
  retained_functions=len(before["functions"])-1,whole_original_reproduced=True,whole_body_inverse=True,
  reference_profile="CPython 3.14.4 Linux os.open path converter",
  effect_order_changed=False,public_route_qualified=False)
 (root/"authoring/public_read/binary_current_error.pseudo").write_text(literal(CURRENT))
 (root/"native/public_binary_read_body.hepta").write_bytes(raw)
 (root/"native/public_binary_read_body_composition.json").write_bytes(s.ENCODE(proof))
 print(json.dumps({"bytes":len(raw),"sha256":s.SHA(raw),"retained_functions":len(before["functions"])-1,"whole_body_inverse":True}),flush=True)
if __name__=="__main__":main()
