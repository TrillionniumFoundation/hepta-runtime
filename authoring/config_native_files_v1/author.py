#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the separate administrator-pinned native file-entry configuration."""
from __future__ import annotations
import argparse,copy,hashlib,json,re,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"authoring/public_publication_v1"))
import source_support as support
SHA=lambda b:hashlib.sha256(b).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
BASE="c6dfd094e424dc783b1eda30b0e49d7643c519ec"
def put(at,value):return f"    put(w,{at},{value})"
def words(raw,at):
    return [put(at+i,int.from_bytes(raw[i:i+8].ljust(8,b"\0"),"little")) for i in range(0,len(raw),8)]
def extension(minimal):
    out=["def schema_files(w:mutbuf) -> u64:","    i=0","    while i<800:",
         "        put(w,20000+i,get(w,18432+i))","        i=i+8",
         "    i=0","    while i<40:","        put(w,20800+i,0)","        i=i+8",
         put(8256,20000),put(8264,21),put(20816,1110)]
    if not minimal:
        out += [put(20800,20840),put(20808,12),*words(b"native_files",20840),put(20824,0),put(20832,2)]
    return "\n".join(out+["    return 0"])+"\n"
def literals():
    vals={16:b"hia-file-entry",17:b"native file transport requires Linux on host "+bytes([96]),18:b"native file profile for host "+bytes([96])}
    out=["def file_literals(w:mutbuf) -> u64:"];cursor=21504
    for i,raw in sorted(vals.items()):
        out += [put(24000+i*16,cursor),put(24008+i*16,len(raw)),*words(raw,cursor)]
        cursor+=((len(raw)+7)//8)*8
    assert cursor<22000
    return "\n".join(out+["    return 0"])+"\n"
def main():
    p=argparse.ArgumentParser();p.add_argument("--hepta",required=True,type=Path);a=p.parse_args()
    paths=["authoring/config_native_files_v1/author.py","authoring/config_native_files_v1/validation.pseudo",
        "authoring/config_native_files_v1/owner.pseudo","authoring/public_publication_v1/source_support.py",
        "native/config_transport_jobs_abi.md"]
    specs=[
        ("config_json_native_jobs_span","config_json_native_files_span",19,37,38),
        ("config_identity_native_jobs","config_identity_native_files",32,38,39),
        ("config_validation_native_jobs_span","config_validation_native_files_span",71,76,77)]
    paths += [f"native/{old}.hepta" for old,*_ in specs]
    paths += ["native/config_validation_native_jobs_span_composition.json","native/config_transport_jobs_owner_span.hepta",
              "native/config_transport_jobs_owner_span_composition.json"]
    inputs={n:(ROOT/n).read_bytes() for n in paths}
    for n,b in inputs.items():
        if n.startswith("native/"):
            assert subprocess.check_output(["/usr/bin/git","-C",str(ROOT),"show",BASE+":"+n])==b,n
    api=support.tools(a.hepta);assemble,render=api[3],api[4];output=[]
    validation_meta=json.loads(inputs["native/config_validation_native_jobs_span_composition.json"])
    for old,new,init,getid,putid in specs:
        before=assemble(inputs[f"native/{old}.hepta"]).as_dict();program=copy.deepcopy(before)
        aliases={"get":f"f{getid}","put":f"f{putid}"};clones={}
        def clone(index,alias):
            target=f"f{len(program['functions'])}";f=copy.deepcopy(before["functions"][index]);assert f["name"]==f"f{index}"
            f["name"]=target;program["functions"].append(f);aliases[alias]=target;clones[target]=index
        clone(init,"retained_schema_init");aliases["schema_init"]=f"f{init}"
        pseudo="def schema_init(w:mutbuf) -> u64:\n    retained_schema_init(w)\n    schema_files(w)\n"
        if init==71:pseudo+="    file_literals(w)\n"
        pseudo+="    return 0\n\n"+extension(init==71);changed={init}
        if init==19:
            # The administrator extension is named-only. Positional HostConfig
            # remains the original twenty-field domain, including its refusal
            # of an additional null. This is the sequence arm only: the map
            # lookup and default materialization retain all twenty-one fields.
            function=program["functions"][40]
            assert function["name"]=="f40"
            assert max(int(x[1:]) for block in function["blocks"] for op in block["ops"] for x in [v["name"] for v in op.get("out",[])])==2200
            block=next(b for b in function["blocks"] if any(o.get("out")==[{"name":"v1382","type":"u64"}] for o in b["ops"]))
            index=next(i for i,o in enumerate(block["ops"]) if o.get("out")==[{"name":"v1382","type":"u64"}])
            prior=copy.deepcopy(block["ops"][index])
            assert prior["op"]=="call" and prior["args"]==["v1326","v1381"] and prior["attrs"]=={"function":"f37"}
            assert block["ops"][index+1]["op"]=="compare.gt" and block["ops"][index+1]["args"]==["v1378","v1382"]
            raw_count=copy.deepcopy(prior);raw_count["out"]=[{"name":"v2201","type":"u64"}]
            def op(name,typ,kind,args=(),attrs=None):
                return {"out":[{"name":name,"type":typ}],"op":kind,"args":list(args),"attrs":attrs or {}}
            replacement=[raw_count,
                op("v2202","u64","const",attrs={"value":101}),
                op("v2203","bool","compare.eq",["v1339","v2202"]),
                op("v2204","u64","const",attrs={"value":20}),
                op("v1382","u64","select",["v2203","v2204","v2201"])]
            block["ops"][index:index+1]=replacement
            restored=copy.deepcopy(function)
            next(b for b in restored["blocks"] if any(o.get("out")==[{"name":"v1382","type":"u64"}] for o in b["ops"]))["ops"][index:index+5]=[prior]
            assert restored==before["functions"][40]
            changed.add(40)
        if init==71:
            clone(6,"retained_file_host_header");clone(40,"retained_file_render_error")
            aliases.update(host_header="f6",render_error="f40",field="f8",number="f9",present="f17",
                valid_sha="f22",key="f15",keylen="f16")
            for name in ("physical_field","native_path","native_literal","native_host"):
                aliases[name]=validation_meta["aliases"][name]
            pseudo+=literals()+inputs["authoring/config_native_files_v1/validation.pseudo"].decode();changed.update((6,40))
        raw,names,proof=support.compile_delta(api,render(program).encode(),aliases,pseudo,{},new)
        after=assemble(raw).as_dict();fs={f["name"]:f for f in after["functions"]};kept={}
        for i,f in enumerate(before["functions"]):
            if i not in changed:
                assert fs[f["name"]]==f,(old,i);kept[f["name"]]=SHA(CANON(f))
        for name,i in clones.items():
            f=copy.deepcopy(fs[name]);f["name"]=f"f{i}";assert f==before["functions"][i]
        proof.update(schema="hepta.runtime.config-native-files-author.v1",baseline_commit=BASE,
            original_source={"path":f"native/{old}.hepta","bytes":len(inputs[f"native/{old}.hepta"]),"sha256":SHA(inputs[f"native/{old}.hepta"])},
            actual_inputs={n:{"bytes":len(b),"sha256":SHA(b)} for n,b in inputs.items()},aliases=names,
            retained_original_functions=kept,changed_original_function_ids=sorted(changed),
            host_field_count=21,prior_twenty_field_order_retained=True,native_files_last=True,
            legacy_host_sequence_max=20,native_files_named_field_only=True,
            pin_struct=110,role="hia-file-entry",native_executed=False,public_qualified=False,whole_runtime_qualified=False)
        output.append((new,raw,proof))
    old="config_transport_jobs_owner_span";new="config_transport_files_owner_span"
    before=assemble(inputs[f"native/{old}.hepta"]).as_dict()
    text=inputs[f"native/{old}.hepta"].decode();start=text.index("\nfn f0(")+1;end=text.index("\nfn ",start);entry=text[start:end]
    anchor='  v370:bool = bool.or(v649,v648)\n'
    assert entry.count(anchor)==1 and max(map(int,re.findall(r"v([0-9]+)",entry)))==649
    entry=entry.replace(anchor,'  v650:u64 = const() {"value":12}\n  v651:bool = compare.eq(v369,v650)\n  v652:bool = bool.or(v649,v648)\n  v370:bool = bool.or(v652,v651)\n')
    program=assemble((text[:start]+entry+text[end:]).encode()).as_dict()
    clone=copy.deepcopy(before["functions"][8]);clone["name"]=f"f{len(program['functions'])}";program["functions"].append(clone)
    m=json.loads(inputs["native/config_transport_jobs_owner_span_composition.json"])
    aliases={"query":"f8","retained_query":clone["name"],"get":"f41","put":"f42","load":"f43",
        "valid_utf8":"f44","region":"f47","growth":"f51","original_result":"f57",
        "transport_named_host":m["aliases"]["transport_named_host"],"transport_string":m["aliases"]["transport_string"]}
    constants={k:int.from_bytes(v,"little") for k,v in {"REQUEST":b"HRCFGQ01","RESPONSE":b"HRCFGM01","FILES":b"HRCFFL01"}.items()}
    constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,LIMIT=0xffff0000)
    raw,names,proof=support.compile_delta(api,render(program).encode(),aliases,inputs["authoring/config_native_files_v1/owner.pseudo"].decode(),constants,new)
    after=assemble(raw).as_dict();fs={f["name"]:f for f in after["functions"]};kept={}
    for i,f in enumerate(before["functions"]):
        if i not in (0,8):
            assert fs[f["name"]]==f,(old,i);kept[f["name"]]=SHA(CANON(f))
    restored=copy.deepcopy(fs[clone["name"]]);restored["name"]="f8";assert restored==before["functions"][8]
    proof.update(schema="hepta.runtime.config-native-files-owner-author.v1",baseline_commit=BASE,
        actual_inputs={n:{"bytes":len(b),"sha256":SHA(b)} for n,b in inputs.items()},aliases=names,
        retained_original_functions=kept,changed_original_function_ids=[0,8],query_operation=12,
        response_magic="HRCFFL01",response_version=1,role="hia-file-entry",
        authority="actual installed typed configuration arena; separate from native_jobs",
        native_executed=False,public_qualified=False,whole_runtime_qualified=False)
    output.append((new,raw,proof))
    for n,b in inputs.items():assert (ROOT/n).read_bytes()==b,n
    for name,raw,proof in output:
        out=ROOT/f"native/{name}.hepta";meta=ROOT/f"native/{name}_composition.json";assert not out.exists() and not meta.exists()
        out.write_bytes(raw);meta.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    for n,b in inputs.items():assert (ROOT/n).read_bytes()==b,n
    print(json.dumps([{"name":n,"bytes":len(b),"sha256":SHA(b),**{k:p[k] for k in ("functions","blocks","operations")}} for n,b,p in output]))
if __name__=="__main__":main()
