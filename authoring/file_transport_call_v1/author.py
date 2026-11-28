"""Build the HIA file transport continuation over actual private children."""
from __future__ import annotations
import argparse, ast, hashlib, importlib.util, json, stat
from pathlib import Path
SHA=lambda b:hashlib.sha256(b).hexdigest()
ENC=lambda x:(json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
WORD=lambda x:int.from_bytes(x.encode(),"little")
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--source",type=Path,default=ROOT)
    a=p.parse_args(); source=a.source.resolve(strict=True)
    own="authoring/file_transport_call_v1/"
    names=[own+"author.py",own+"call.pseudo",
           "authoring/public_publication_v1/source_support.py",
           "authoring/public_extract/adapter.pseudo",
           "native/binary_call_plan.hepta","native/binary_call_plan_composition.json",
           "native/file_transport_policy_v3.hepta","native/file_transport_policy_v3_composition.json",
           "native/file_transport_result.hepta","native/file_transport_result_composition.json",
           "native/ssh_direct_owner.hepta","native/ssh_direct_owner_composition.json"]
    def take(n):
        f=source/n
        if f.resolve(strict=True)!=f or not stat.S_ISREG(f.lstat().st_mode):
            raise ValueError("nonphysical input: "+n)
        return f.read_bytes()
    initial={n:take(n) for n in names}
    for stem in ("binary_call_plan","file_transport_policy_v3","file_transport_result","ssh_direct_owner"):
        raw=initial["native/"+stem+".hepta"]
        meta=json.loads(initial["native/"+stem+"_composition.json"])
        if meta.get("source_sha256",meta.get("source",{}).get("sha256"))!=SHA(raw):
            raise ValueError("source binding differs: "+stem)
    spec=importlib.util.spec_from_file_location("_file_transport_source_support",source/names[2])
    support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
    api=support.tools(a.hepta)
    common=initial[names[3]].decode()
    nodes={n.name:ast.get_source_segment(common,n) for n in ast.parse(common).body}
    retained=["child","region","region_capacity","reserve","request_grow","pending_grow","admit_growth","delivery_again"]
    pseudo=initial[own+"call.pseudo"].decode()+"\n\n"+"\n\n".join(nodes[n] for n in retained)+"\n"
    constants={
        "STATE_MAGIC":WORD("HFBTCS01"),"REQUEST":WORD("HFBTRQ03"),
        "ACTION_MAGIC":WORD("HFBTCA01"),"PLAN_RESULT":WORD("HFBSHP03"),
        "SSH_RESULT":WORD("HSSHRR01"),"DECODE_REQUEST":WORD("HFBRSQ01"),
        "DECODE_RESULT":WORD("HFBRRS01"),"CONFIG_RESULT":WORD("HRCFGM01"),
        "GROW_MAGIC":WORD("HGRWS002"),"PHASE":8,"SEQUENCE":16,
        "INPUT_LENGTH":24,"OUTPUT_LENGTH":32,"WORK_LENGTH":40,"ACTION":256,
        "INVALID":0xffffffff,"CAPACITY":0xfffffffe,"CANCELLED":0xfffffff7,
        "CALL":0xfffffff0,"GROW":0xffffffd0,"DELIVERY":0xffffffcd,
        "FIRST_ERROR":0xffff0000,"MAXIMUM":(1<<64)-1}
    raw,aliases,proof=support.compile_new(api,initial["native/binary_call_plan.hepta"],
        {"load":"f1","get":"f2","put":"f3"},pseudo,constants,"runtime_file_transport_call")
    if any(take(n)!=b for n,b in initial.items()):raise ValueError("source changed before publication")
    outputs={"native/file_transport_call.hepta":raw,
      "native/file_transport_call_composition.json":ENC({
        "schema":"hepta.runtime.file-transport-call.v1",**proof,"aliases":aliases,
        "constants":constants,"source_bytes":len(raw),"source_sha256":SHA(raw),
        "input_files":{n:{"bytes":len(b),"sha256":SHA(b)} for n,b in initial.items()},
        "retained_helpers":{n:SHA(nodes[n].encode()) for n in retained},
        "children":["file_transport_policy_v3","installed_foreground_ssh_owner","file_transport_result"],
        "complete_input_capture":True,"child_delivery_replay":False,
        "native_compiled":False,"public_qualified":False,"original_nineteen_methods_passed":False})}
    for n in outputs:
        if (source/n).exists():raise FileExistsError(n)
    for n,b in outputs.items():(source/n).write_bytes(b)
    if any(take(n)!=b for n,b in initial.items()):raise ValueError("source changed at terminal boundary")
    print(json.dumps({"source":"native/file_transport_call.hepta","bytes":len(raw),"sha256":SHA(raw),**proof}))
if __name__=="__main__":main()
