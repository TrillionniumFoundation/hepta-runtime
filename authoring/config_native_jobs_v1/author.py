#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Extend the actual native configuration schema with Rust's five pinned job roles."""
from __future__ import annotations
import argparse,copy,hashlib,json,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"authoring/public_publication_v1"))
import source_support as support
SHA=lambda x:hashlib.sha256(x).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
BASE="abc9ecb95ee9538518ec3f36c47b881974107021"
ROLES=("entry","submit","observation","cancel","launcher")
def put(at,value):return f"    put(w,{at},{value})"
def words(raw,at):
    return [put(at+i,int.from_bytes(raw[i:i+8].ljust(8,b"\0"),"little")) for i in range(0,len(raw),8)]
def schema_extension(minimal):
    out=["def schema_extension(w:mutbuf) -> u64:","    i=0","    while i<760:","        put(w,18472+i,get(w,9456+i))","        i=i+8"]
    for at,value in ((8256,18432),(8264,20),(8272,80),(9024,19232),(9032,5),(9040,31),(9048,1),(9088,19432),(9096,2),(9104,3),(9112,1)):
        out.append(put(at,value))
    # Every new field row is fully initialized, including flags and reserved words.
    out += ["    i=0","    while i<40:","        put(w,18432+i,0)","        i=i+8","    i=0","    while i<280:","        put(w,19232+i,0)","        i=i+8"]
    entries=[(18432,"native_jobs",1109,0,2)]+[(19232+i*40,n,110,0,1) for i,n in enumerate(ROLES)]+[(19432,"executable",1,0,1),(19472,"sha256",1,0,1)]
    cursor=19600
    for at,name,typ,default,flags in entries:
        if not minimal:
            out += [put(at,cursor),put(at+8,len(name)),*words(name.encode(),cursor),put(at+24,default),put(at+32,flags)]
        out.append(put(at+16,typ));cursor+=((len(name)+7)//8)*8
    assert cursor<22000
    out += ["    return 0"]
    return "\n".join(out)+"\n"
def native_literals():
    vals={i+1:("hia-job-"+("launch" if r=="launcher" else r)).encode() for i,r in enumerate(ROLES)}
    vals.update({6:b"native job transport requires Linux on host `",7:b"`",8:b"native job profile for host `",9:b"`: invalid native job role ",10:b": expected a normalized absolute installed role path and lowercase SHA256"})
    vals.update({11+i:vals[i+1] for i in range(5)})
    out=["def native_literals(w:mutbuf) -> u64:"]
    cursor=21000
    for i,raw in sorted(vals.items()):
        out += [put(24000+i*16,cursor),put(24008+i*16,len(raw)),*words(raw,cursor)]
        cursor+=(len(raw)+7)//8*8
    assert cursor<32768
    return "\n".join(out+["    return 0"])+"\n"
def main():
    p=argparse.ArgumentParser();p.add_argument("--hepta",required=True,type=Path);a=p.parse_args()
    paths=["authoring/config_native_jobs_v1/author.py","authoring/config_native_jobs_v1/validation.pseudo","authoring/public_publication_v1/source_support.py","src/mcp/runtime/config.rs"]
    specs=[
        ("config_json_span","config_json_native_jobs_span",19,[24],37,38),
        ("config_identity","config_identity_native_jobs",32,[18,37],38,39),
        ("config_validation_span","config_validation_native_jobs_span",71,[74],76,77)]
    paths += [f"native/{s[0]}.hepta" for s in specs]
    inputs={n:(ROOT/n).read_bytes() for n in paths}
    for name, *_ in specs:
        path=f"native/{name}.hepta"
        expected=subprocess.check_output(["/usr/bin/git","-C",str(ROOT),"show",BASE+":"+path])
        assert inputs[path]==expected,path
    api=support.tools(a.hepta);assemble,render=api[3],api[4]
    results=[]
    for oldname,newname,initid,mapids,getid,putid in specs:
        before=assemble(inputs[f"native/{oldname}.hepta"]).as_dict();patched=copy.deepcopy(before)
        aliases={"get":f"f{getid}","put":f"f{putid}"}
        clones={}
        def clone(index,alias):
            target=f"f{len(patched['functions'])}"
            f=copy.deepcopy(before["functions"][index]);assert f["name"]==f"f{index}"
            f["name"]=target;patched["functions"].append(f);aliases[alias]=target;clones[target]=index
        clone(initid,"retained_schema_init");aliases["schema_init"]=f"f{initid}"
        pseudo="def schema_init(w:mutbuf) -> u64:\n    retained_schema_init(w)\n    schema_extension(w)\n"
        if oldname=="config_validation_span":pseudo+="    native_literals(w)\n"
        pseudo+="    return 0\n\n"
        changed={initid,*mapids}
        for index in mapids:
            alias=f"type_{index}";old=f"retained_type_{index}";clone(index,old);aliases[alias]=f"f{index}"
            pseudo+=f"def {alias}(kind:u64) -> u64:\n    if kind==109:\n        return 9024\n    if kind==110:\n        return 9088\n    return {old}(kind)\n\n"
        pseudo+=schema_extension(oldname=="config_validation_span")
        if oldname=="config_validation_span":
            # Prove that this exact prior initializer never writes the newly reserved spans.
            reservations=((18432,22000),(24000,24464))
            prior_writes=[]
            for original in before["functions"]:
                if original["name"] not in {f"f{i}" for i in range(56,66)}|{"f71"}:continue
                constants={}
                for block in original["blocks"]:
                    for op in block["ops"]:
                        if op["op"]=="const":constants[op["out"][0]["name"]]=op["attrs"]["value"]
                        elif op["op"]=="int.cast" and op["args"][0] in constants:constants[op["out"][0]["name"]]=constants[op["args"][0]]
                        elif op["op"]=="call" and op["attrs"].get("function")=="f77":
                            start=constants[op["args"][1]];prior_writes.append((start,start+8))
                        elif op["op"]=="buffer.fill_range":
                            start=constants[op["args"][1]];size=constants[op["args"][2]];prior_writes.append((start,start+size))
            assert prior_writes
            assert all(end<=lo or start>=hi for start,end in prior_writes for lo,hi in reservations)
            clone(8,"physical_field");clone(6,"retained_host_header");clone(40,"retained_render_error")
            aliases.update(field="f8",host_header="f6",render_error="f40",read="f78",
                number="f9",present="f17",data="f13",slen="f14",key="f15",keylen="f16",valid_sha="f22",emit="f73")
            count=0
            for block in patched["functions"][7]["blocks"]:
                for op in block["ops"]:
                    if op.get("op")=="call" and op.get("attrs",{}).get("function")=="f8":
                        op["attrs"]["function"]=aliases["physical_field"];count+=1
            assert count>0
            changed.update((6,7,8,40))
            pseudo+=native_literals()+inputs["authoring/config_native_jobs_v1/validation.pseudo"].decode()
        raw,names,proof=support.compile_delta(api,render(patched).encode(),aliases,pseudo,{},newname)
        after=assemble(raw).as_dict();lookup={f["name"]:f for f in after["functions"]}
        retained={}
        for index,f in enumerate(before["functions"]):
            if index not in changed:
                assert lookup[f["name"]]==f,(oldname,index)
                retained[f["name"]]=SHA(CANON(f))
        for name,index in clones.items():
            actual=copy.deepcopy(lookup[name]);actual["name"]=f"f{index}"
            assert actual==before["functions"][index],(name,index)
        proof.update(schema="hepta.runtime.config-native-jobs-author.v1",baseline_commit=BASE,
            original_source={"path":f"native/{oldname}.hepta","bytes":len(inputs[f"native/{oldname}.hepta"]),"sha256":SHA(inputs[f"native/{oldname}.hepta"])},
            actual_inputs={n:{"bytes":len(v),"sha256":SHA(v)} for n,v in inputs.items()},
            aliases=names,relocated_exact_functions={n:f"f{i}" for n,i in clones.items()},
            retained_original_functions=retained,changed_original_function_ids=sorted(changed),
            host_field_count=20,host_native_jobs_first=True,native_job_struct=109,native_job_pin_struct=110,
            roles=list(ROLES),native_executed=False,public_qualified=False,whole_runtime_qualified=False)
        for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
        out=ROOT/f"native/{newname}.hepta";receipt=ROOT/f"native/{newname}_composition.json"
        assert not out.exists() and not receipt.exists()
        out.write_bytes(raw);receipt.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
        results.append({"source":str(out),"bytes":len(raw),"sha256":SHA(raw),**{n:proof[n] for n in ("functions","blocks","operations")}})
    for n,v in inputs.items():assert (ROOT/n).read_bytes()==v,n
    print(json.dumps(results,sort_keys=True))
if __name__=="__main__":main()
