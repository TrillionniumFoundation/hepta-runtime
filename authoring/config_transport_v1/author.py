#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author a private installed HostConfig transport read; old operations stay exact."""
from __future__ import annotations
import argparse,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"authoring/public_publication_v1"))
import source_support as support
SHA=lambda x:hashlib.sha256(x).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
BASE="cb22aa72a33b4a429356fdb7d70dd33828492676de1a89c11837d9d8f68a55b5"
def main():
    p=argparse.ArgumentParser();p.add_argument("--hepta",required=True,type=Path);a=p.parse_args()
    inputs={name:(ROOT/name).read_bytes() for name in (
        "native/config_directory_owner_span.hepta",
        "authoring/config_transport_v1/transport.pseudo",
        "authoring/config_transport_v1/author.py",
        "authoring/public_publication_v1/source_support.py",
        "scripts/config_schema.py","src/mcp/runtime/config.rs")}
    old=inputs["native/config_directory_owner_span.hepta"]
    assert SHA(old)==BASE and len(old)==319711
    api=support.tools(a.hepta);assemble,render=api[3],api[4]
    before=assemble(old).as_dict()
    assert len(before["functions"])==60
    text=old.decode();begin=text.index("\nfn f0(")+1;end=text.index("\nfn ",begin)
    entry=text[begin:end]
    anchor=('  v641:u64 = const() {"value":9}\n'
            '  v642:bool = compare.eq(v369,v368)\n'
            '  v643:bool = compare.eq(v369,v641)\n'
            '  v370:bool = bool.or(v642,v643)\n')
    replacement=('  v641:u64 = const() {"value":9}\n'
            '  v642:bool = compare.eq(v369,v368)\n'
            '  v643:bool = compare.eq(v369,v641)\n'
            '  v644:u64 = const() {"value":10}\n'
            '  v645:bool = compare.eq(v369,v644)\n'
            '  v646:bool = bool.or(v642,v643)\n'
            '  v370:bool = bool.or(v646,v645)\n')
    assert entry.count(anchor)==1
    assert max(int(v) for v in re.findall(r"\bv([0-9]+)\b",entry))==643
    patched=assemble((text[:begin]+entry.replace(anchor,replacement)+text[end:]).encode()).as_dict()
    for oldf,newf in zip(before["functions"],patched["functions"],strict=True):
        if oldf["name"]!="f0":assert oldf==newf
    clone=copy.deepcopy(before["functions"][8]);assert clone["name"]=="f8";clone["name"]="f60"
    patched["functions"].append(clone)
    aliases={"query":"f8","retained_query":"f60","get":"f41","put":"f42","load":"f43",
             "valid_utf8":"f44","region":"f47","growth":"f51","equal":"f19","original_result":"f57"}
    constants={"REQUEST":int.from_bytes(b"HRCFGQ01","little"),
               "RESPONSE":int.from_bytes(b"HRCFGM01","little"),
               "TRANSPORT":int.from_bytes(b"HRCFTR01","little"),
               "INVALID":0xffffffff,"CAPACITY":0xfffffffe,"LIMIT":0xffff0000}
    raw,names,proof=support.compile_delta(api,render(patched).encode(),aliases,
        inputs["authoring/config_transport_v1/transport.pseudo"].decode(),constants,"config_transport_owner_span")
    after=assemble(raw).as_dict();fs={f["name"]:f for f in after["functions"]}
    retained={}
    for f in before["functions"]:
        if f["name"] not in ("f0","f8"):
            assert fs[f["name"]]==f
            retained[f["name"]]=SHA(CANON(f))
    restored=copy.deepcopy(fs["f60"]);restored["name"]="f8";assert restored==before["functions"][8]
    assert fs["f0"]==patched["functions"][0]
    proof.update(schema="hepta.runtime.config-transport-author.v1",base_sha256=BASE,
        current_physical_inputs={n:{"bytes":len(v),"sha256":SHA(v)} for n,v in inputs.items()},
        aliases=names,retained_original_functions=retained,relocated_exact_function={"f8":"f60"},
        entry_delta={"from_ops":[8,9],"to_ops":[8,9,10],"other_entry_ir_exact":True},
        query_operation=10,response_magic="HRCFTR01",response_version=1,
        authority="actual installed typed configuration arena",exact_named_host=True,
        native_jobs_in_this_wire=False,privileged_actions_in_this_wire=False,
        native_compiled=False,native_executed=False,public_route_qualified=False,whole_runtime_qualified=False)
    for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
    out=ROOT/"native/config_transport_owner_span.hepta"
    receipt=ROOT/"native/config_transport_owner_span_composition.json"
    assert not out.exists() and not receipt.exists()
    out.write_bytes(raw);receipt.write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
    print(json.dumps({"source":str(out),"bytes":len(raw),"sha256":SHA(raw),**{n:proof[n] for n in ("functions","blocks","operations")}},sort_keys=True))
if __name__=="__main__":main()
