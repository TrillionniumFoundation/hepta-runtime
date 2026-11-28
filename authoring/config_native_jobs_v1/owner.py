#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind original owner operations to the new physical HostConfig model and expose pins."""
from __future__ import annotations
import argparse,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"authoring/public_publication_v1"))
import source_support as support
SHA=lambda x:hashlib.sha256(x).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
def main():
    p=argparse.ArgumentParser();p.add_argument("--hepta",required=True,type=Path);a=p.parse_args()
    paths=("native/config_transport_owner_span.hepta","native/config_transport_owner_span_composition.json",
        "authoring/config_native_jobs_v1/owner.py","authoring/config_native_jobs_v1/owner.pseudo",
        "authoring/public_publication_v1/source_support.py","src/mcp/runtime/config.rs",
        "native/config_json_native_jobs_span.hepta","native/config_identity_native_jobs.hepta",
        "native/config_validation_native_jobs_span.hepta")
    inputs={n:(ROOT/n).read_bytes() for n in paths}
    old=inputs["native/config_transport_owner_span.hepta"]
    assert len(old)==341508 and SHA(old)=="1cf2e81412c7360ddc3c305146a81c94149ecbddcd541087bf502fc7042331bb"
    composition=json.loads(inputs["native/config_transport_owner_span_composition.json"])
    api=support.tools(a.hepta);assemble,render=api[3],api[4];before=assemble(old).as_dict()
    text=old.decode();start=text.index("\nfn f0(")+1;end=text.index("\nfn ",start);entry=text[start:end]
    anchor='  v370:bool = bool.or(v646,v645)\n'
    replacement='  v647:u64 = const() {"value":11}\n  v648:bool = compare.eq(v369,v647)\n  v649:bool = bool.or(v646,v645)\n  v370:bool = bool.or(v649,v648)\n'
    assert entry.count(anchor)==1 and max(int(x) for x in re.findall(r"v([0-9]+)",entry))==646
    patched=assemble((text[:start]+entry.replace(anchor,replacement)+text[end:]).encode()).as_dict()
    clone=copy.deepcopy(before["functions"][8]);clone["name"]=f"f{len(patched['functions'])}"
    retained=clone["name"];patched["functions"].append(clone)
    aliases={"query":"f8","retained_query":retained,"get":"f41","put":"f42","load":"f43",
        "valid_utf8":"f44","region":"f47","growth":"f51","original_result":"f57",
        "transport_named_host":composition["aliases"]["transport_named_host"],
        "transport_string":composition["aliases"]["transport_string"]}
    constants={"REQUEST":int.from_bytes(b"HRCFGQ01","little"),"RESPONSE":int.from_bytes(b"HRCFGM01","little"),
        "JOBS":int.from_bytes(b"HRCFJB01","little"),"INVALID":0xffffffff,"CAPACITY":0xfffffffe,"LIMIT":0xffff0000}
    raw,names,proof=support.compile_delta(api,render(patched).encode(),aliases,
        inputs["authoring/config_native_jobs_v1/owner.pseudo"].decode(),constants,"config_transport_jobs_owner_span")
    current=assemble(raw).as_dict();fs={f["name"]:f for f in current["functions"]}
    helper=names["legacy_host_fields"]
    target_fields={"f24":{"v262","v867"},"f52":{"v544"},"f54":{"v73"}}
    changes=[]
    for fname,values in target_fields.items():
        count=0
        for block in fs[fname]["blocks"]:
            for op in block["ops"]:
                outputs={o["name"] for o in op.get("out",[])}
                if outputs & values:
                    assert op["op"]=="call" and op["attrs"]["function"]=="f41",(fname,op)
                    op["attrs"]["function"]=helper;count+=1;changes.append([fname,sorted(outputs),helper])
        assert count==len(values),(fname,count)
    fname=aliases["transport_named_host"];count=0
    for block in fs[fname]["blocks"]:
        term=block["term"]
        if term["op"]!="ret":continue
        value=term["values"][0]
        for op in block["ops"]:
            if any(o["name"]==value for o in op.get("out",[])) and op["op"]=="call":
                assert op["attrs"]["function"]=="f41"
                op["attrs"]["function"]=helper;count+=1;changes.append([fname,[value],helper])
    assert count==1
    raw=render(current).encode()
    verified,stats=support.checked_program(api,current)
    assert verified==raw
    proof.update(stats)
    changed={"f0","f8",*target_fields,fname};retained_ids={}
    for f in before["functions"]:
        if f["name"] not in changed:
            assert fs[f["name"]]==f
            retained_ids[f["name"]]=SHA(CANON(f))
    restored=copy.deepcopy(fs[retained]);restored["name"]="f8";assert restored==before["functions"][8]
    proof.update(schema="hepta.runtime.config-native-jobs-owner-author.v1",
        actual_inputs={n:{"bytes":len(v),"sha256":SHA(v)} for n,v in inputs.items()},
        aliases=names,physical_host_field_pointer_changes=changes,retained_original_functions=retained_ids,
        original_host_field_order_retained=True,physical_native_jobs_first=True,query_operation=11,
        response_magic="HRCFJB01",response_version=1,roles=["entry","submit","observation","cancel","launcher"],
        authority="actual installed typed configuration arena",native_executed=False,public_qualified=False,whole_runtime_qualified=False)
    for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
    out=ROOT/"native/config_transport_jobs_owner_span.hepta";receipt=ROOT/"native/config_transport_jobs_owner_span_composition.json"
    assert not out.exists() and not receipt.exists()
    out.write_bytes(raw);receipt.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
    print(json.dumps({"source":str(out),"bytes":len(raw),"sha256":SHA(raw),"physical_pointer_changes":changes,**{n:proof[n] for n in ("functions","blocks","operations")}},sort_keys=True))
if __name__=="__main__":main()
