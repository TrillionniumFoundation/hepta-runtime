"""Add a single current text constructor edge to the qualified public9 frontend.

The original request/admission/tool continuations remain exact. Entry changes
admit phase 11 through the same completed-child validation and delivery logic.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

sys.dont_write_bytecode=True
BASELINE="05a9a2c14fd70c8b38a3266288230bf8e41a7ab4ee1a8099ab585d72561d86a6"
CONSTRUCTOR="3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode()


def generate(hepta,baseline,dsl,output):
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    class NativeBuilder(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="copy_within":
                args=[self.expr(v) for v in node.args]
                return self.op("buffer.move_within",[args[0],*(self.cast(v,"usize") for v in args[1:])])
            return super().expr(node)
    raw=(baseline/"native/runtime_mcp.hepta").read_bytes()
    if sha(raw)!=BASELINE:
        raise ValueError("qualified 79-image frontend source differs")
    composition=json.loads((baseline/"native/runtime_mcp_composition.json").read_bytes())
    old=assemble_program(raw).as_dict()
    before={f["name"]:copy.deepcopy(f) for f in old["functions"]}
    assert len(before)==46
    functions=copy.deepcopy(old["functions"])
    for old_name,new_name in [("f13","f46"),("f8","f47")]:
        copied=copy.deepcopy(before[old_name]);copied["name"]=new_name;functions.append(copied)
    aliases=dict(composition["functions"])
    aliases.update(retained_render="f46",retained_prepare="f47")
    authored=dsl.read_text()
    result_key=b',"result":'
    authored+="\ndef result_key(w:mutbuf,at:u64) -> u64:\n"
    last=len(result_key)//8*8
    for i in range(0,last,8):
        authored+=f"    put(w,at+{i},{int.from_bytes(result_key[i:i+8],'little')})\n"
    for i in range(last,len(result_key)):
        authored+=f"    store(w,at+{i},{result_key[i]})\n"
    authored+=f"    return at+{len(result_key)}\n"
    constants=dict(INVALID=0xffffffff,RESULT_KEY_SIZE=len(result_key),
        CONSTRUCTOR_REQUEST=int.from_bytes(b"HRTCRQ01","little"),
        CONSTRUCTOR_RESPONSE=int.from_bytes(b"HRTCRS01","little"))
    authored=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),authored)
    nodes=ast.parse(authored).body
    new_names=dict(render="f13",prepare="f8",prepare_constructor="f48",
                   after_constructor="f49",constructor_envelope="f50",result_key="f51")
    names={**aliases,**new_names}
    byname={f["name"]:f for f in functions}
    signatures={alias:([p["type"] for p in byname[name]["params"]],byname[name]["returns"][0])
                for alias,name in aliases.items()}
    signatures.update({n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes})
    generated=[]
    total=total_scalar_functions(nodes)
    for node in nodes:
        builder=NativeBuilder(node,names,signatures,total)
        builder.statements(node.body)
        generated.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=["read","write","trap"],entry="b0",blocks=builder.blocks))
    changes={f["name"]:f for f in generated}
    functions=[changes.get(f["name"],f) for f in functions]+[changes["f"+str(i)] for i in range(48,52)]
    compacted=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
        module="runtime_mcp_constructor_delta",functions=functions))["functions"]
    compacted={f["name"]:f for f in compacted}
    functions=[compacted[f["name"]] if f["name"] in changes else f for f in functions]
    entry=functions[0]
    blocks={b["id"]:b for b in entry["blocks"]}
    for block,name,previous,current in [("b19","v161",110,111),("b21","v177",10,11)]:
        operation=next(o for o in blocks[block]["ops"] if o["out"]==[dict(name=name,type="u64")])
        assert operation["op"]=="const" and operation["attrs"]==dict(value=previous)
        operation["attrs"]["value"]=current
    dispatch=blocks["b57"]
    assert [p["name"] for p in dispatch["params"]]==["v464","v465","v466","v467","v468","v469"]
    old_term=copy.deepcopy(dispatch["term"])
    assert old_term["cond"]=="v476"
    dispatch["ops"] += [
        dict(op="const",args=[],attrs=dict(value=11),out=[dict(name="v50000",type="u64")]),
        dict(op="compare.eq",args=["v467","v50000"],attrs={},out=[dict(name="v50001",type="bool")])]
    dispatch["term"]=dict(op="branch",cond="v50001",
        then=dict(target="b68",args=["v464","v465","v466","v468","v469"]),
        **{"else":dict(target="b69",args=["v464","v465","v466","v467","v468","v469","v476"])})
    params=[dict(name="v"+str(50020+i),type=t) for i,t in enumerate(["readbuf","mutbuf","mutbuf","u64","u64"])]
    block68=dict(id="b68",params=params,ops=[dict(op="call",args=[p["name"] for p in params],
        attrs=dict(function="f49"),out=[dict(name="v50025",type="u32")])],
        term=dict(op="ret",values=["v50025"]))
    params=[dict(name="v"+str(50030+i),type=t) for i,t in enumerate(["readbuf","mutbuf","mutbuf","u64","u64","u64","bool"])]
    remap=dict(zip(["v464","v465","v466","v467","v468","v469","v476"],[p["name"] for p in params]))
    old_term["cond"]=remap[old_term["cond"]]
    for edge in ("then","else"):
        old_term[edge]["args"]=[remap[v] for v in old_term[edge]["args"]]
    entry["blocks"] += [block68,dict(id="b69",params=params,ops=[],term=old_term)]
    document={**old,"functions":functions}
    raw=render_assembly(document).encode()
    checked=assemble_program(raw).as_dict()
    after={f["name"]:f for f in checked["functions"]}
    retained={}
    for name,function in before.items():
        if name in {"f0","f8","f13"}:
            continue
        assert after[name]==function,name
        retained[name]=sha(canonical(function))
    for old_name,new_name in [("f13","f46"),("f8","f47")]:
        expected=copy.deepcopy(before[old_name]);expected["name"]=new_name
        assert after[new_name]==expected
    for function in checked["functions"]:
        assert len(function["blocks"])<=256,function["name"]
        assert max(len(b["params"]) for b in function["blocks"])<=16,function["name"]
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(raw)
    note=dict(schema="hepta.runtime.public-text-constructor-source.v1",
        baseline_sha256=BASELINE,source_sha256=sha(raw),source_bytes=len(raw),
        retained_exact_functions=retained,relocated_exact_functions=dict(f13="f46",f8="f47"),
        changed_functions=["f0","f8","f13"],new_functions=new_names,
        entry_change="phase limits 10/110 to 11/111; phase11 branches after the original complete delivery validation",
        frontend_child=10,constructor_slot=46,phase=11,prepare_phase=111,
        constructor_source_sha256=CONSTRUCTOR,constructor_request="HRTCRQ01",constructor_response="HRTCRS01",
        frontend_raw_publisher_kind=3,full_result_extent_checked=True,
        publisher_create_format=0,publisher_generation_start_pull_write_ack_drop_preserved=True,
        author_sha256=sha(Path(__file__).read_bytes()),dsl_sha256=sha(dsl.read_bytes()),
        native_public_qualified=False,actual_target_constructor_compared=False,
        target_general_response_owner_integrated=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    (output.parent/"runtime_mcp_text_constructor_composition.json").write_text(json.dumps(note,sort_keys=True,indent=2)+"\n")
    composition.update(source_bytes=len(raw),source_sha256=sha(raw))
    composition["function_sha256"]={n:sha(canonical(f)) for n,f in after.items()}
    composition["functions"].update(new_names)
    composition["functions"]["retained_text_render"]="f46"
    composition["functions"]["retained_ninth_prepare"]="f47"
    composition["target_text_constructor_extension"]=note
    output.with_name("runtime_mcp_composition.json").write_text(json.dumps(composition,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:note[k] for k in ("source_sha256","source_bytes","constructor_slot","phase")},sort_keys=True))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("hepta","baseline","dsl","output"):
        p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    generate(*(getattr(a,n).resolve() for n in ("hepta","baseline","dsl","output")))

